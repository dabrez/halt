"""Network-namespace wiring for forced egress.

This module builds the routing that makes interception non-optional. The
proxy (proxy.py) is only an enforcement point if the sandbox genuinely has
no other way out; that property comes from here, not from the proxy.

Shape:

    sandbox netns                host netns
    +-------------+              +-------------------+
    |  agent      |   veth pair  |                   |
    |  default ---+--------------+--> HALT proxy     |
    |  route      |              |    (deny-all)     |
    +-------------+              +-------------------+

The sandbox side gets an address, a default route pointing at the host side,
and nothing else — no other interface, no second route. An agent opening a
raw socket to an arbitrary address still has exactly one path out of the
namespace, and it terminates at HALT.

WHAT THIS MODULE DOES NOT DO (milestone 1, see ROADMAP.md):

It does not DNAT/REDIRECT arbitrary destination addresses onto the proxy's
port. That means a connection to 10.0.0.2:PROXY_PORT is intercepted, but a
connection to example.com:443 is routed at the host side and dropped rather
than landing in the proxy's accept loop. Recovering the *original*
destination needs an iptables REDIRECT plus SO_ORIGINAL_DST, which is
milestone 2 work — it is also precisely what makes host/port recoverable,
and why proxy.py currently reports the local socket address instead of
pretending to know the intended destination.

The claim being tested at this milestone is narrower and prior to that:
**that a process in the namespace has no route out except through HALT.**

Everything here shells out to `ip`. Commands are executed through an
injectable `run_command` so the command *sequence* is testable without root,
in the same style as FirecrackerBackend/GvisorBackend.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class NetnsConfig:
    """Addressing for one sandbox namespace.

    Defaults are a /30 — two usable addresses, which is exactly what a
    point-to-point veth pair needs and nothing more.
    """

    name: str
    host_if: str = "halt0"
    sandbox_if: str = "halt1"
    host_addr: str = "10.201.0.1"
    sandbox_addr: str = "10.201.0.2"
    prefix_len: int = 30

    @property
    def host_cidr(self) -> str:
        return f"{self.host_addr}/{self.prefix_len}"

    @property
    def sandbox_cidr(self) -> str:
        return f"{self.sandbox_addr}/{self.prefix_len}"


class NetnsEgress:
    """Creates and tears down the forced-egress namespace.

    Not a KillBackend — this builds the observation path, whereas backends
    tear down a run. Kept separate deliberately: kill authority has one
    audit surface and this is not it.
    """

    def __init__(
        self,
        config: NetnsConfig,
        run_command: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        self.config = config
        self._run = run_command
        self._created = False

    # -- command helpers ----------------------------------------------

    def _ip(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(["ip", *args])

    def _in_ns(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(["ip", "netns", "exec", self.config.name, *args])

    # -- lifecycle ----------------------------------------------------

    def create(self) -> None:
        """Build the namespace, the veth pair, and the single default route.

        Ordering matters: the peer must be moved into the namespace before
        it can be addressed there, and the default route requires the
        sandbox-side interface to already be up.
        """
        c = self.config

        self._ip("netns", "add", c.name)
        self._ip(
            "link", "add", c.host_if, "type", "veth", "peer", "name", c.sandbox_if
        )
        self._ip("link", "set", c.sandbox_if, "netns", c.name)

        # Host side: address + up.
        self._ip("addr", "add", c.host_cidr, "dev", c.host_if)
        self._ip("link", "set", c.host_if, "up")

        # Sandbox side: loopback, address, up, and exactly one route out.
        self._in_ns("ip", "link", "set", "lo", "up")
        self._in_ns("ip", "addr", "add", c.sandbox_cidr, "dev", c.sandbox_if)
        self._in_ns("ip", "link", "set", c.sandbox_if, "up")
        self._in_ns("ip", "route", "add", "default", "via", c.host_addr)

        self._created = True

    def destroy(self) -> None:
        """Tear down. Deleting the namespace takes the veth peer with it;
        the explicit host-side link delete is belt-and-braces for the case
        where the pair was created but the move into the namespace failed.
        """
        c = self.config
        self._ip("netns", "del", c.name)
        self._ip("link", "del", c.host_if)
        self._created = False

    def __enter__(self) -> "NetnsEgress":
        self.create()
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()

    # -- verification -------------------------------------------------

    def routes(self) -> subprocess.CompletedProcess:
        """Dump the sandbox's routing table. The milestone-1 assertion is
        that this shows a default via the host side and nothing else.
        """
        return self._in_ns("ip", "route", "show")

    def exec_in_ns(self, *args: str) -> subprocess.CompletedProcess:
        """Run an arbitrary command inside the namespace — used by the live
        test to make an egress attempt from a real process.
        """
        return self._in_ns(*args)
