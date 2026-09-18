from __future__ import annotations

from typing import Callable

from halt.events import FuseKind, Severity, TripEvent
from halt.policy import Policy

from .base import Fuse


class NonTcpEgressFuse(Fuse):
    """Trips when the sandbox has emitted any non-TCP packet at all.

    The policy is a closed list of (host, port, path-prefix) — an HTTP
    allowlist. It has no vocabulary for UDP or ICMP, so there is nothing
    to match against: a non-TCP packet is off-policy by construction, and
    a fuse that sees one has nothing to decide.

    Like WatchdogFuse this is polled, not inline: the proxy can't see these
    packets (they never reach it), so the observation comes from the
    interface counter NetnsEgress.count_non_tcp() maintains. Trips on any
    count above zero; the supervisor's first-kill-wins makes repeated
    trips harmless.
    """

    name = "non_tcp_egress"

    def __init__(self, policy: Policy, read_counter: Callable[[], int]):
        self.policy = policy
        self._read = read_counter

    def observe(self, **_) -> TripEvent | None:
        n = self._read()
        if n <= 0:
            return None
        return TripEvent(
            fuse=FuseKind.NETWORK,
            severity=Severity.KILL,
            reason=f"{n} non-TCP packet(s) left the sandbox (policy is HTTP-only)",
            evidence={"non_tcp_packets": n},
            org_id=self.policy.org_id,
            run_id=self.policy.run_id,
        )
