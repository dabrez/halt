from __future__ import annotations

from halt.events import FuseKind, Severity, TripEvent
from halt.policy import Policy

from .base import Fuse


class NetworkFuse(Fuse):
    """Trips on any connection attempt not matching the policy's network
    allowlist exactly (host, port, and path-prefix). Matching only on host
    is the specific gap that let the ExploitGym escape use an allowlisted
    host's admin API instead of its intended package-fetch path — so this
    fuse refuses to allow a host-only match.
    """

    name = "network"

    def __init__(self, policy: Policy):
        self.policy = policy

    def observe(self, *, host: str, port: int, path: str = "/", **_) -> TripEvent | None:
        if self.policy.network_allowed(host, port, path):
            return None
        return TripEvent(
            fuse=FuseKind.NETWORK,
            severity=Severity.KILL,
            reason=f"egress to {host}:{port}{path} not in allowlist",
            evidence={"host": host, "port": port, "path": path},
            org_id=self.policy.org_id,
            run_id=self.policy.run_id,
        )
