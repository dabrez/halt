"""Portable trip-event schema.

A TripEvent is the one thing every fuse produces and the supervisor consumes.
It is deliberately serializable and self-contained: today it only ever goes to
a local sink, but the shape is chosen so a future sink could POST it to a
shared cross-org registry without any fuse code changing.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    KILL = "kill"


class FuseKind(str, Enum):
    NETWORK = "network"
    CREDENTIAL = "credential"
    WATCHDOG = "watchdog"


@dataclass(frozen=True)
class TripEvent:
    """A single fuse observation. KILL severity means the fuse is demanding
    the supervisor stop the run; WARN/INFO are logged but do not, by
    themselves, trigger a kill.
    """

    fuse: FuseKind
    severity: Severity
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    org_id: str = "local"
    run_id: str = "unknown"

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "ts": self.ts,
            "org_id": self.org_id,
            "run_id": self.run_id,
            "fuse": self.fuse.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "evidence": self.evidence,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "TripEvent":
        return TripEvent(
            fuse=FuseKind(d["fuse"]),
            severity=Severity(d["severity"]),
            reason=d["reason"],
            evidence=d.get("evidence", {}),
            org_id=d.get("org_id", "local"),
            run_id=d.get("run_id", "unknown"),
            event_id=d["event_id"],
            ts=d["ts"],
        )
