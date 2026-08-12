"""Where TripEvents go.

LocalJsonlSink is real: append-only JSON Lines, one event per line, flushed
immediately so a killed process can't take the record with it.

ExternalBroadcastSink is an interface stub only — the seed for the cross-org
signal-sharing piece discussed but explicitly out of scope for this build.
It is not wired into the supervisor by default.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

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


class ExternalBroadcastSink(Sink):
    """NOT IMPLEMENTED. Placeholder for a future cross-org containment
    signal (see design discussion: closing the days-long gap between two
    orgs independently discovering the same incident). Raises rather than
    silently no-op'ing, so nobody mistakes this for working.
    """

    def emit(self, event: TripEvent) -> None:
        raise NotImplementedError(
            "ExternalBroadcastSink is a design placeholder, not a working sink"
        )
