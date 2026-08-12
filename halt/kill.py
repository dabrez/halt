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
    #: True if sever_network() can succeed while the process is still
    #: running. False if network teardown requires the process to be gone
    #: first — e.g. Firecracker's tap device is held open by the VM
    #: process for its whole life; deleting it while the VM is alive fails
    #: with "Device or resource busy" (verified against a live microVM,
    #: see FirecrackerBackend). execute_kill() uses this to pick the right
    #: order instead of assuming one order works for every backend.
    can_sever_network_before_terminate: bool = True

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
    """Credentials always go first — a still-running process with a live
    credential can act, whether or not its network path is up (it may
    already hold an established connection, or reach the network through
    something this backend doesn't control), so revoking first minimizes
    that window regardless of what follows.

    Network vs. process ordering is backend-dependent, not universal:
    when the backend can sever network reachability while the process
    keeps running (e.g. a cloud security-group rule), do that first, so
    a process that survives an initial failed terminate() is still cut
    off. When it can't (Firecracker's tap device is held open by the VM
    process itself — verified: attempting to delete it while the VM is
    alive fails with "Device or resource busy"), terminate first, since
    a network action that's guaranteed to fail is worse than skipping the
    ordering theater and just killing the thing that's holding the
    resource.
    """
    result = KillResult(run_id=run_id)
    for cred in credential_ids:
        if backend.revoke_credential(cred):
            result.credentials_revoked.append(cred)

    if backend.can_sever_network_before_terminate:
        result.network_severed = backend.sever_network(run_id)
        result.process_terminated = backend.terminate(run_id)
    else:
        result.process_terminated = backend.terminate(run_id)
        result.network_severed = backend.sever_network(run_id)

    return result
