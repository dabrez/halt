"""KillBackend for a Firecracker microVM.

Firecracker's isolation is the hardware VM boundary (KVM) — strong against
guest-kernel-level breakout, irrelevant to the actual incident this project
is built around, since that escape never touched the VM boundary at all. It
went out through a *permitted* egress path. So this backend's job is narrow
and unglamorous: when the supervisor says kill, sever the one thing the
guest was allowed to reach, and stop the VM — it is not trying to add a
second isolation layer on top of KVM.

Two independent things happen on kill, and both are real infra actions, not
process bookkeeping:

1. Network: Firecracker VMs reach the network through a host-side tap
   device the host created. There is no "unplug the network" API call on
   Firecracker's own control socket — the tap device is a host construct,
   so severing it means removing it from the bridge / tearing it down at
   the host network stack, same as unplugging a virtual cable. This runs
   as `ip link set <tap> down` followed by `ip tuntap del`.
2. Process: Firecracker exposes a Unix-socket HTTP API. The documented way
   to stop a running microVM is `PUT /actions` with
   `{"action_type": "SendCtrlAltDel"}` for a graceful guest shutdown, but a
   circuit breaker cannot wait on a possibly-compromised guest to shut
   itself down gracefully — so this backend goes straight to killing the
   firecracker host process (SIGKILL), which tears down the guest
   unconditionally regardless of what's running inside it.

Credential revocation is deliberately NOT infra-specific here — Firecracker
has no concept of application-level credentials, so `revoke_credential`
delegates to an injected callback (e.g. a call to your cloud IAM API or an
internal token service). This backend only owns what Firecracker/the host
network stack actually control.

UNVERIFIED IN THIS ENVIRONMENT: nothing in this file has been run against a
live Firecracker VM. This machine has /dev/kvm but the invoking user is not
in the `kvm` group, and no `firecracker` binary is installed, so there was
no way to boot a real microVM here. The API socket protocol and `ip`
commands below match Firecracker's documented API as of this writing; treat
this as reviewed-but-unexecuted until it's run against a real instance.
"""

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable

from halt.kill import KillBackend


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """Firecracker's API is HTTP-over-a-Unix-socket, not TCP. http.client
    has no built-in support for that, so this overrides the connect step to
    hand it a real AF_UNIX socket instead of opening a TCP one.
    """

    def __init__(self, socket_path: str):
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)


@dataclass
class FirecrackerVM:
    run_id: str
    api_socket_path: str
    firecracker_pid: int
    tap_device: str


class FirecrackerBackend(KillBackend):
    def __init__(
        self,
        revoke_credential_fn: Callable[[str], bool] | None = None,
        run_command: Callable[[list[str]], subprocess.CompletedProcess] = subprocess.run,
    ):
        self._vms: dict[str, FirecrackerVM] = {}
        self._revoke_credential_fn = revoke_credential_fn
        self._run = run_command

    def register_vm(self, vm: FirecrackerVM) -> None:
        self._vms[vm.run_id] = vm

    def revoke_credential(self, token_id: str) -> bool:
        if self._revoke_credential_fn is None:
            raise NotImplementedError(
                "FirecrackerBackend has no application-credential concept of "
                "its own; pass revoke_credential_fn to wire this up to your "
                "IAM/token service"
            )
        return self._revoke_credential_fn(token_id)

    def sever_network(self, run_id: str) -> bool:
        vm = self._vms.get(run_id)
        if vm is None:
            return False
        # Drop the tap device out of forwarding first (fast, best-effort),
        # then delete it outright so the guest's virtio-net device has
        # nothing left to talk to on the host side.
        self._run(["ip", "link", "set", vm.tap_device, "down"])
        result = self._run(["ip", "tuntap", "del", "dev", vm.tap_device, "mode", "tap"])
        return result.returncode == 0

    def terminate(self, run_id: str) -> bool:
        vm = self._vms.get(run_id)
        if vm is None:
            return False
        try:
            os.kill(vm.firecracker_pid, signal.SIGKILL)
        except ProcessLookupError:
            return False
        return True

    def _call_api(self, vm: FirecrackerVM, method: str, path: str, body: dict) -> None:
        """Documented-but-unexercised path: PUT /actions with
        SendCtrlAltDel. Not used by terminate() above (a circuit breaker
        can't wait on a graceful guest shutdown that a compromised guest
        could simply ignore) but kept as the API-correct alternative for
        callers that want a graceful stop attempt before the hard kill.
        """
        conn = _UnixSocketHTTPConnection(vm.api_socket_path)
        conn.request(method, path, body=json.dumps(body), headers={"Content-Type": "application/json"})
        conn.getresponse().read()
        conn.close()
