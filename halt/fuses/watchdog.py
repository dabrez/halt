from __future__ import annotations

import time

from halt.events import FuseKind, Severity, TripEvent
from halt.policy import Policy

from .base import Fuse


class WatchdogFuse(Fuse):
    """Dead-man's switch: the sandbox must call heartbeat() at least once
    per policy.heartbeat_timeout_s, or the run is considered unsupervised
    and gets killed. This is the backstop for the case where the other
    fuses simply never see the bad event — e.g. the monitored path itself
    is disabled or crashes. In the ExploitGym incident the actual attack
    took multiple days; a watchdog would not have caught the initial
    escape, but it bounds how long *anything* can run unsupervised.
    """

    name = "watchdog"

    def __init__(self, policy: Policy, clock=time.monotonic):
        self.policy = policy
        self._clock = clock
        self._last_beat = clock()

    def heartbeat(self) -> None:
        self._last_beat = self._clock()

    def observe(self, **_) -> TripEvent | None:
        elapsed = self._clock() - self._last_beat
        if elapsed <= self.policy.heartbeat_timeout_s:
            return None
        return TripEvent(
            fuse=FuseKind.WATCHDOG,
            severity=Severity.KILL,
            reason=f"no heartbeat for {elapsed:.1f}s (limit {self.policy.heartbeat_timeout_s}s)",
            evidence={"elapsed_s": elapsed, "limit_s": self.policy.heartbeat_timeout_s},
            org_id=self.policy.org_id,
            run_id=self.policy.run_id,
        )
