"""KillBackend for a gVisor (runsc) sandbox.

Read this alongside firecracker.py's docstring, because the point of
having both is the comparison: gVisor's isolation boundary is a userspace
reimplementation of the Linux kernel (the "Sentry" process) intercepting
guest syscalls before they reach the real kernel. That's a meaningfully
weaker boundary than Firecracker's hardware-enforced KVM VM — gVisor has
shipped real host-escape CVEs where a crafted syscall sequence got past
Sentry (e.g. CVE-2023-45283-class issues in the runsc network/gofer path).
If your threat model is "can the guest break out to the host kernel," pick
Firecracker.

But that entire axis is a red herring for what this project defends
against, and it's worth being blunt about why: the ExploitGym-style escape
that motivated HALT never attacked the syscall boundary at all. It went out
through a connection the sandbox was *supposed* to be allowed to make.
gVisor's Sentry does nothing to look at what an agent does with a
connection it's permitted to open — it's a syscall filter, not a traffic
cop. Swap Firecracker in for gVisor here and the exact same escape still
works, because neither one asks "should this specific request, on this
specific allowlisted host, be going to this path." That's a different
question than "is the isolation boundary strong," and it's the one this
project actually answers. So: use gVisor or Firecracker (or both, layered)
for what they're good at, and don't mistake either one for a defense
against an agent using a channel it was actually issued.

Kill semantics here, since runsc has no tap device of its own: termination
is `runsc kill <id>` (or via the container's docker/containerd wrapper if
one is in front of it), and network severance means tearing down the
container's network namespace / veth pair at the host, same mechanism any
container runtime uses — there's no gVisor-specific network API.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable

from halt.kill import KillBackend


@dataclass
class GvisorContainer:
    run_id: str
    container_id: str
    veth_device: str


class GvisorBackend(KillBackend):
    def __init__(
        self,
        revoke_credential_fn: Callable[[str], bool] | None = None,
        run_command: Callable[[list[str]], subprocess.CompletedProcess] = subprocess.run,
    ):
        self._containers: dict[str, GvisorContainer] = {}
        self._revoke_credential_fn = revoke_credential_fn
        self._run = run_command

    def register_container(self, container: GvisorContainer) -> None:
        self._containers[container.run_id] = container

    def revoke_credential(self, token_id: str) -> bool:
        if self._revoke_credential_fn is None:
            raise NotImplementedError(
                "GvisorBackend has no application-credential concept of its "
                "own; pass revoke_credential_fn to wire this up to your "
                "IAM/token service"
            )
        return self._revoke_credential_fn(token_id)

    def sever_network(self, run_id: str) -> bool:
        c = self._containers.get(run_id)
        if c is None:
            return False
        result = self._run(["ip", "link", "delete", c.veth_device])
        return result.returncode == 0

    def terminate(self, run_id: str) -> bool:
        c = self._containers.get(run_id)
        if c is None:
            return False
        result = self._run(["runsc", "kill", c.container_id, "SIGKILL"])
        return result.returncode == 0
