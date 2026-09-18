"""Where TripEvents go.

LocalJsonlSink is real: append-only JSON Lines, one event per line, flushed
immediately so a killed process can't take the record with it.

ExternalBroadcastSink POSTs each event to an HTTP endpoint — the seed of
the cross-org containment signal: closing the days-long gap in which two
orgs independently discover the same incident. It is designed around one
rule: **a broadcast failure must never delay or prevent a kill.** The
supervisor emits before it decides, so this sink swallows every error into
`failures` rather than raising. Use it behind TeeSink with a local sink
first, so the forensic record is on disk before any network I/O happens.

HONEST STATUS: verified against a local fake endpoint. No shared registry
exists to speak to; the wire format is simply TripEvent.to_dict().
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from halt.events import TripEvent


class Sink(ABC):
    @abstractmethod
    def emit(self, event: TripEvent) -> None:
        raise NotImplementedError


class LocalJsonlSink(Sink):
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: TripEvent) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")
            f.flush()

    def read_all(self) -> list[TripEvent]:
        if not self.path.exists():
            return []
        events = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(TripEvent.from_dict(json.loads(line)))
        return events


class TeeSink(Sink):
    """Emit to several sinks in order. Order is the point: put the local,
    durable sink first so it has the record before anything slower or
    less reliable runs. A failure in one sink does not stop the others.
    """

    def __init__(self, *sinks: Sink):
        self.sinks = list(sinks)
        self.failures: list[tuple[str, BaseException]] = []

    def emit(self, event: TripEvent) -> None:
        for s in self.sinks:
            try:
                s.emit(event)
            except Exception as e:  # noqa: BLE001 - one sink must not silence the rest
                self.failures.append((type(s).__name__, e))


@dataclass
class BroadcastFailure:
    event_id: str
    reason: str


class ExternalBroadcastSink(Sink):
    def __init__(
        self,
        url: str,
        bearer: str | None = None,
        timeout: float = 3.0,
        opener: Callable = urllib.request.urlopen,
    ):
        self.url = url
        self._bearer = bearer
        self._timeout = timeout
        self._open = opener
        self.failures: list[BroadcastFailure] = []
        self.delivered: int = 0

    def emit(self, event: TripEvent) -> None:
        body = json.dumps(event.to_dict()).encode()
        headers = {"Content-Type": "application/json"}
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with self._open(req, timeout=self._timeout) as resp:
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as e:
            self.failures.append(BroadcastFailure(event.event_id, f"HTTP {e.code}"))
            return
        except Exception as e:  # noqa: BLE001 - never into the kill path
            self.failures.append(BroadcastFailure(event.event_id, f"{type(e).__name__}: {e}"))
            return
        if 200 <= status < 300:
            self.delivered += 1
        else:
            self.failures.append(BroadcastFailure(event.event_id, f"HTTP {status}"))
