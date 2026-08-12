"""Kill actions.

The supervisor's kill authority has to live outside whatever it's killing,
and it has to act on more than the process: the ExploitGym incident's
danger persisted past any single sandbox because credentials and network
reachability outlived it. A real kill is: revoke every credential issued to
the run, sever its network path, then terminate it — in that order, since
killing the process first gives a still-valid credential a window to be
used from somewhere else.

`KillBackend` is the seam. `LocalProcessBackend` is real and tested here —
it can revoke tokens from an in-memory registry and terminate a local
subprocess. Backends for real infra (cloud IAM token revocation, a
Firecracker host-side supervisor severing a VM's tap interface) are NOT
implemented here — this environment has no cloud credentials and no
/dev/kvm to test them against. Wiring one up is real, hardware/infra-backed
work, not a stub to paper over.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class KillResult:
    run_id: str
    credentials_revoked: list[str] = field(default_factory=list)
    network_severed: bool = False
    process_terminated: bool = False


class KillBackend(ABC):
    @abstractmethod
    def revoke_credential(self, token_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def sever_network(self, run_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def terminate(self, run_id: str) -> bool:
        raise NotImplementedError


class LocalProcessBackend(KillBackend):
    """Dev/test backend: an in-memory credential registry and a fake
    network-reachability flag per run, plus real termination of a tracked
    subprocess if one was registered. Good enough to prove the supervisor's
    ordering and idempotency logic; not a security boundary itself.
    """

    def __init__(self):
        self._revoked: set[str] = set()
        self._network_severed: set[str] = set()
        self._processes: dict[str, "subprocess.Popen"] = {}

    def register_process(self, run_id: str, proc) -> None:
        self._processes[run_id] = proc

    def revoke_credential(self, token_id: str) -> bool:
        self._revoked.add(token_id)
        return True

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked

    def sever_network(self, run_id: str) -> bool:
        self._network_severed.add(run_id)
        return True

    def is_network_severed(self, run_id: str) -> bool:
        return run_id in self._network_severed

    def terminate(self, run_id: str) -> bool:
        proc = self._processes.get(run_id)
        if proc is None:
            return False
        proc.kill()
        return True


def execute_kill(
    backend: KillBackend, run_id: str, credential_ids: list[str]
) -> KillResult:
    """Credentials first, then network, then process — a still-running
    process with a live credential can act; a dead process with a live
    credential cannot act itself but the credential remains a risk.
    Revoking first minimizes the window either way.
    """
    result = KillResult(run_id=run_id)
    for cred in credential_ids:
        if backend.revoke_credential(cred):
            result.credentials_revoked.append(cred)
    result.network_severed = backend.sever_network(run_id)
    result.process_terminated = backend.terminate(run_id)
    return result
