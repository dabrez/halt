"""The decision seam between the terminating proxy and the fuses.

The proxy knows how to see a request; it must not know what is allowed.
`PolicyGate` is the only place the two meet: it turns an
InterceptedConnection into a NetworkFuse observation, hands any trip to the
Supervisor (which owns kill authority — see supervisor.py), and answers the
proxy's one question: forward, or drop.

Two deliberate choices:

* **Every decision is logged, allow or deny.** NetworkFuse returns None for
  an allowed observation, which would leave permitted traffic invisible in
  the forensic record. The gate emits an INFO event for those, so the sink
  holds the full picture of what crossed the permitted channel — which is
  exactly the record the motivating incident lacked.
* **No path means deny.** A connection that completes TLS but never sends
  an HTTP request, or speaks something other than HTTP, has no path for
  the policy to match. Default-deny applies: the policy is a closed list of
  (host, port, path-prefix) and an observation with no path is not on it.
  Non-HTTP protocols over TCP are therefore unsupported by design at this
  layer, not merely unimplemented.
"""

from __future__ import annotations

from dataclasses import replace

from halt.events import FuseKind, Severity, TripEvent
from halt.fuses.network import NetworkFuse
from halt.intercept.proxy import InterceptedConnection
from halt.policy import Policy
from halt.supervisor import Supervisor


class PolicyGate:
    def __init__(self, policy: Policy, supervisor: Supervisor):
        self.policy = policy
        self.supervisor = supervisor
        self._fuse = NetworkFuse(policy)

    def decide(self, conn: InterceptedConnection) -> bool:
        """True to forward, False to drop. Always reports to the supervisor."""
        evidence = {
            "host": conn.host,
            "port": conn.port,
            "path": conn.path,
            "peer": list(conn.peer) if conn.peer else None,
            "redirected": conn.redirected,
            "tls": conn.tls,
        }

        if conn.path is None:
            self.supervisor.report(TripEvent(
                fuse=FuseKind.NETWORK,
                severity=Severity.KILL,
                reason=f"egress to {conn.host}:{conn.port} with no HTTP request observed",
                evidence=evidence,
                org_id=self.policy.org_id,
                run_id=self.policy.run_id,
            ))
            return False

        event = self._fuse.observe(host=conn.host, port=conn.port, path=conn.path)
        if event is not None:
            # The fuse states the violation; the gate adds how it arrived.
            # Same event, fuller record — an investigator wants both.
            self.supervisor.report(replace(event, evidence={**evidence, **event.evidence}))
            return False

        self.supervisor.report(TripEvent(
            fuse=FuseKind.NETWORK,
            severity=Severity.INFO,
            reason=f"egress to {conn.host}:{conn.port}{conn.path} allowed",
            evidence=evidence,
            org_id=self.policy.org_id,
            run_id=self.policy.run_id,
        ))
        return True
