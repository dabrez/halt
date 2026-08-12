from __future__ import annotations

from halt.events import FuseKind, Severity, TripEvent
from halt.policy import Policy

from .base import Fuse


class CredentialFuse(Fuse):
    """Trips when a token is used outside its declared scope, or a token
    not issued for this run appears at all. This is a structural check
    against the token's claimed scope, not a judgment call — a forged or
    escalated scope shows up as a fact, not an inference.
    """

    name = "credential"

    def __init__(self, policy: Policy):
        self.policy = policy

    def observe(self, *, token_id: str, requested_scope: str, **_) -> TripEvent | None:
        allowed = self.policy.credential_scopes_for(token_id)
        if allowed is None:
            return TripEvent(
                fuse=FuseKind.CREDENTIAL,
                severity=Severity.KILL,
                reason=f"unknown token {token_id!r} used (not issued for this run)",
                evidence={"token_id": token_id, "requested_scope": requested_scope},
                org_id=self.policy.org_id,
                run_id=self.policy.run_id,
            )
        if requested_scope not in allowed:
            return TripEvent(
                fuse=FuseKind.CREDENTIAL,
                severity=Severity.KILL,
                reason=f"token {token_id!r} used outside allowed scope",
                evidence={
                    "token_id": token_id,
                    "requested_scope": requested_scope,
                    "allowed_scopes": sorted(allowed),
                },
                org_id=self.policy.org_id,
                run_id=self.policy.run_id,
            )
        return None
