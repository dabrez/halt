"""Network-namespace wiring for forced egress.

This module builds the routing that makes interception non-optional. The
proxy (proxy.py) is only an enforcement point if the sandbox genuinely has
no other way out; that property comes from here, not from the proxy.

Shape:

    sandbox netns                host netns
    +-------------+              +----------------------------------+
    |  agent      |   veth pair  |  PREROUTING -i halt0 -p tcp      |
    |  default ---+--------------+--> REDIRECT --to-ports <proxy>   |
    |  route      |              |  INPUT/FORWARD -i halt0 !tcp DROP|
    +-------------+              +----------------------------------+

The sandbox side gets an address, a default route pointing at the host side,
and nothing else — no other interface, no second route. An agent opening a
raw socket to an arbitrary address still has exactly one path out of the
namespace, and it terminates at HALT.

Two layers, and it matters which does what (verified live, 2026-09-17):

* **Containment** comes from routing alone. With no route past the host
  side and ip_forward off, arbitrary destinations die at the veth. Milestone
  1 proved this — and also proved that containment by itself gives HALT no
  *visibility*: a connection to 1.1.1.1:443 was dropped without ever
  reaching the proxy's accept loop.
* **Visibility** comes from `redirect_tcp_to()`: a nat PREROUTING REDIRECT
  pulls every TCP connection arriving from the sandbox into the proxy, which
  recovers the intended destination via SO_ORIGINAL_DST (see proxy.py).
  Verified live: an agent aiming at 1.1.1.1:443, 93.184.216.34:80 and
  8.8.8.8:53 landed in the proxy with all three original destinations
  recovered exactly.

`drop_non_tcp()` is the explicit backstop for everything REDIRECT does not
cover (UDP, ICMP, raw). Live, those packets were already discarded by the
router before reaching the filter chains — the DROP counters read 0 — so
these rules are belt to routing's braces: they turn "contained by accident of
ip_forward=0" into "contained by policy". Non-TCP is contained but NOT
observed; making it visible needs NFLOG and is recorded in ROADMAP.md.

Everything here shells out to `ip` / `iptables`. Commands run through an
injectable `run_command` so the command *sequence* is testable without root,
in the same style as FirecrackerBackend/GvisorBackend. The live path needs
CAP_NET_ADMIN in the host namespace — root, or root-in-userns via
`unshare -rnm` (which is how the live tests in tests/live/ run).
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


def _run_captured(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Default runner. Output *must* be captured: non_tcp_packets() reads
    the iptables listing from stdout, and a plain subprocess.run would hand
    it None — a counter that silently reads 0 forever is exactly the kind
    of quiet failure a fuse must not have. (Found by running the README
    example for real.)
    """
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(cmd, **kw)


class NetnsEgress:
    """Creates and tears down the forced-egress namespace.

    Not a KillBackend — this builds the observation path, whereas backends
    tear down a run. Kept separate deliberately: kill authority has one
    audit surface and this is not it.
    """

    def __init__(
        self,
        config: NetnsConfig,
        run_command: Callable[..., subprocess.CompletedProcess] = _run_captured,
    ):
        self.config = config
        self._run = run_command
        self._created = False
        # Every iptables rule added, as its `-A` argument list, so destroy()
        # can `-D` each one. Rules live in the host namespace and would
        # otherwise outlive the sandbox they were written for.
        self._rules: list[list[str]] = []

    # -- command helpers ----------------------------------------------

    def _ip(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(["ip", *args])

    def _in_ns(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(["ip", "netns", "exec", self.config.name, *args])

    def _iptables_add(self, *rule: str) -> subprocess.CompletedProcess:
        self._rules.append(list(rule))
        return self._run(["iptables", *rule])

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

    def redirect_tcp_to(self, proxy_port: int) -> bool:
        """Pull every TCP connection from the sandbox into the proxy.

        This is what turns containment into visibility. Without it the
        proxy only ever sees traffic already addressed to it (the milestone
        1 finding); with it, the agent's *intended* destination is preserved
        in conntrack and readable via SO_ORIGINAL_DST on the accepted socket.
        """
        r = self._iptables_add(
            "-t", "nat", "-A", "PREROUTING",
            "-i", self.config.host_if, "-p", "tcp",
            "-j", "REDIRECT", "--to-ports", str(proxy_port),
        )
        return r.returncode == 0

    def drop_non_tcp(self) -> bool:
        """Explicitly discard what REDIRECT can't capture.

        Routing already contains non-TCP (no forward path), but a rule says
        so on purpose rather than relying on ip_forward staying off. Both
        chains: INPUT for packets aimed at the host side itself, FORWARD for
        anything that would otherwise be routed onward.
        """
        a = self._iptables_add(
            "-A", "INPUT", "-i", self.config.host_if, "!", "-p", "tcp", "-j", "DROP"
        )
        b = self._iptables_add(
            "-A", "FORWARD", "-i", self.config.host_if, "-j", "DROP"
        )
        return a.returncode == 0 and b.returncode == 0

    def count_non_tcp(self) -> bool:
        """Make non-TCP attempts *countable*, since they can't be captured.

        The DROP rules never see them: with no forward path the router
        discards a UDP or ICMP packet before any filter chain runs, which
        is why those counters read 0 live. `mangle PREROUTING` runs before
        routing and sees every packet that arrives on the interface — so a
        target-less rule there is a counter of non-TCP egress attempts.
        Verified live: two pings from the sandbox → 2 packets counted.

        This is visibility of *that something happened*, not of what. Per-
        packet detail (destination, payload) needs NFLOG; see ROADMAP.md.
        """
        r = self._iptables_add(
            "-t", "mangle", "-A", "PREROUTING", "-i", self.config.host_if, "!", "-p", "tcp"
        )
        return r.returncode == 0

    def non_tcp_packets(self) -> int:
        """Packets matched by the count_non_tcp() rule so far."""
        r = self._run(["iptables", "-t", "mangle", "-L", "PREROUTING", "-v", "-n", "-x"])
        return _parse_non_tcp_counter(r.stdout or "", self.config.host_if)

    def destroy(self) -> None:
        """Tear down, rules first (they reference the interface by name and
        would silently keep matching a future interface with the same name),
        then the namespace, which takes the veth peer with it. The explicit
        host-side link delete is belt-and-braces for the case where the pair
        was created but the move into the namespace failed.
        """
        c = self.config
        for rule in reversed(self._rules):
            delete = ["-D" if tok == "-A" else tok for tok in rule]
            self._run(["iptables", *delete])
        self._rules.clear()

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


def _parse_non_tcp_counter(listing: str, host_if: str) -> int:
    """Sum the pkts column of `iptables -L -v -n -x` rows that are our
    interface's `! -p tcp` rule. With -n the protocol column reads `!6`.
    A target-less rule has no target column, so match by content rather
    than position.
    """
    total = 0
    for line in listing.splitlines():
        tok = line.split()
        if len(tok) < 6 or not tok[0].isdigit():
            continue
        if host_if in tok and ("!6" in tok or "!tcp" in tok):
            total += int(tok[0])
    return total
