"""Command-sequence tests for the REDIRECT/backstop layer (no root needed).

The live behaviour — that REDIRECT actually pulls arbitrary destinations
into the proxy and SO_ORIGINAL_DST recovers them — is covered by
tests/live/, which runs under `unshare -rnm`.
"""

import socket
import struct
import subprocess
import time

from halt.intercept.netns import NetnsConfig, NetnsEgress
from halt.intercept.proxy import DenyAllProxy, original_destination


def recording_run():
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0)

    return calls, fake_run


def test_redirect_rule_targets_host_interface_tcp_only():
    calls, fake_run = recording_run()
    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=fake_run)

    assert egress.redirect_tcp_to(4444) is True
    assert calls == [[
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-i", "halt0", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "4444",
    ]]


def test_drop_non_tcp_covers_input_and_forward():
    calls, fake_run = recording_run()
    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=fake_run)

    assert egress.drop_non_tcp() is True
    assert calls == [
        ["iptables", "-A", "INPUT", "-i", "halt0", "!", "-p", "tcp", "-j", "DROP"],
        ["iptables", "-A", "FORWARD", "-i", "halt0", "-j", "DROP"],
    ]


def test_destroy_deletes_rules_in_reverse_before_namespace():
    """Rules match on interface *name* and would keep firing on a future
    interface that reuses it, so they must not outlive the namespace."""
    calls, fake_run = recording_run()
    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=fake_run)
    egress.redirect_tcp_to(4444)
    egress.drop_non_tcp()
    calls.clear()

    egress.destroy()

    assert calls[:3] == [
        ["iptables", "-D", "FORWARD", "-i", "halt0", "-j", "DROP"],
        ["iptables", "-D", "INPUT", "-i", "halt0", "!", "-p", "tcp", "-j", "DROP"],
        ["iptables", "-t", "nat", "-D", "PREROUTING",
         "-i", "halt0", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "4444"],
    ]
    assert calls[3] == ["ip", "netns", "del", "ns"]


def test_destroy_is_idempotent_about_rules():
    calls, fake_run = recording_run()
    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=fake_run)
    egress.redirect_tcp_to(4444)
    egress.destroy()
    calls.clear()

    egress.destroy()
    assert not any(c[0] == "iptables" for c in calls)


def test_rule_failure_reported_as_false():
    def failing_run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, returncode=2)

    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=failing_run)
    assert egress.redirect_tcp_to(1) is False
    assert egress.drop_non_tcp() is False


def test_original_destination_is_none_without_nat():
    """Plain loopback connection: no conntrack rewrite, so the option is
    absent or reflects nothing useful. The proxy must fall back honestly."""
    a, b = socket.socketpair()
    try:
        assert original_destination(a) is None
    finally:
        a.close()
        b.close()


def test_original_destination_parses_sockaddr_in():
    class FakeSock:
        def getsockopt(self, level, opt, buflen):
            assert (level, opt, buflen) == (0, 80, 16)
            return struct.pack("!2xH4s8x", 443, socket.inet_aton("1.1.1.1"))

    assert original_destination(FakeSock()) == ("1.1.1.1", 443)


def test_unredirected_connection_is_flagged_not_disguised():
    """Without REDIRECT the proxy reports its own address; `redirected`
    must be False so nobody treats that as the agent's target."""
    seen = []
    with DenyAllProxy(on_connection=seen.append) as proxy:
        port = proxy.port
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.recv(1)
        s.close()
        for _ in range(100):
            if seen:
                break
            time.sleep(0.01)

    assert seen and seen[0].redirected is False
    assert seen[0].port == port
