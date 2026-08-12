"""Declarative allowlist policy.

Deliberately not a classifier. A policy is a closed list of exactly what an
agent run is permitted to touch: network destinations (host + port +
path-prefix, not just host — the ExploitGym incident's escape used the same
allowlisted host on a different path/port), credential scopes, and a max
silence window. Anything not explicitly listed is denied.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


@dataclass(frozen=True)
class NetworkRule:
    host: str
    port: int
    path_prefix: str = "/"

    def matches(self, host: str, port: int, path: str) -> bool:
        return (
            fnmatch.fnmatch(host, self.host)
            and port == self.port
            and path.startswith(self.path_prefix)
        )


@dataclass(frozen=True)
class CredentialRule:
    token_id: str
    allowed_scopes: frozenset[str]


@dataclass(frozen=True)
class Policy:
    """A closed allowlist for one run. Default-deny: nothing not listed here
    is permitted.
    """

    run_id: str
    org_id: str = "local"
    network_rules: tuple[NetworkRule, ...] = field(default_factory=tuple)
    credential_rules: tuple[CredentialRule, ...] = field(default_factory=tuple)
    heartbeat_timeout_s: float = 30.0

    def network_allowed(self, host: str, port: int, path: str) -> bool:
        return any(r.matches(host, port, path) for r in self.network_rules)

    def credential_scopes_for(self, token_id: str) -> frozenset[str] | None:
        for r in self.credential_rules:
            if r.token_id == token_id:
                return r.allowed_scopes
        return None
