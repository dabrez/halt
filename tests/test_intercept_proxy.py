import socket
import time

from halt.events import FuseKind, Severity
from halt.intercept import DenyAllProxy, InterceptedConnection
from halt.kill import LocalProcessBackend
from halt.sinks import LocalJsonlSink
from halt.supervisor import Supervisor


def connect_and_read(port, timeout=2.0):
    """Connect, then read once. Deny-all means the read returns b'' (EOF)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        return s.recv(1024)
    finally:
        s.close()


def wait_for(predicate, timeout=2.0):
    """The accept loop runs on its own thread; poll rather than sleep-and-hope."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_connection_is_observed_without_being_reported():
    """The whole point: the proxy sees the attempt, and nothing inside the
    connecting code volunteered anything.
    """
    seen = []
    with DenyAllProxy(on_connection=seen.append) as proxy:
        connect_and_read(proxy.port)
        assert wait_for(lambda: len(seen) == 1)

    assert isinstance(seen[0], InterceptedConnection)
    assert seen[0].peer is not None


def test_deny_all_forwards_nothing():
    """A denied connection gets EOF immediately, not data from upstream."""
    with DenyAllProxy() as proxy:
        assert connect_and_read(proxy.port) == b""


def test_path_is_none_not_root():
    """Before TLS termination the path is genuinely unknown. Recording it as
    '/' would be a lie that NetworkRule's path_prefix matching would then
    silently act on.
    """
    seen = []
    with DenyAllProxy(on_connection=seen.append) as proxy:
        connect_and_read(proxy.port)
        assert wait_for(lambda: len(seen) == 1)

    assert seen[0].path is None


def test_multiple_connections_all_observed():
    seen = []
    with DenyAllProxy(on_connection=seen.append) as proxy:
        for _ in range(5):
            connect_and_read(proxy.port)
        assert wait_for(lambda: len(seen) == 5)

    assert len(proxy.seen) == 5


def test_callback_errors_are_surfaced_not_swallowed():
    """A broken observation path must not fail silently on a daemon thread —
    that is the exact failure mode this component exists to rule out.
    """
    def boom(_conn):
        raise RuntimeError("fuse exploded")

    with DenyAllProxy(on_connection=boom) as proxy:
        connect_and_read(proxy.port)
        assert wait_for(lambda: len(proxy.callback_errors) == 1)

    assert isinstance(proxy.callback_errors[0], RuntimeError)


def test_proxy_still_denies_when_callback_raises():
    """Enforcement must not depend on the observer behaving."""
    with DenyAllProxy(on_connection=lambda _c: 1 / 0) as proxy:
        assert connect_and_read(proxy.port) == b""


def test_intercepted_connection_drives_supervisor_kill(tmp_path):
    """End-to-end for milestone 1: an unreported egress attempt reaches the
    supervisor and kills the run. Deny-everything posture, so the trip does
    not consult a policy — that arrives with real matching in milestone 2.
    """
    sink = LocalJsonlSink(tmp_path / "events.jsonl")
    sup = Supervisor(LocalProcessBackend(), sink, run_id="run-1")

    def on_conn(conn: InterceptedConnection):
        from halt.events import TripEvent

        sup.report(
            TripEvent(
                fuse=FuseKind.NETWORK,
                severity=Severity.KILL,
                reason=f"egress attempt to {conn.host}:{conn.port} (deny-all)",
                evidence={"host": conn.host, "port": conn.port, "path": conn.path},
                run_id="run-1",
            )
        )

    with DenyAllProxy(on_connection=on_conn) as proxy:
        connect_and_read(proxy.port)
        assert wait_for(lambda: sup.killed)

    assert sup.cause is not None
    assert sup.cause.fuse is FuseKind.NETWORK
    assert len(sink.read_all()) == 1


def test_address_resolves_ephemeral_port():
    with DenyAllProxy(port=0) as proxy:
        assert proxy.port != 0
        assert proxy.address[0] == "127.0.0.1"


def test_proxy_does_not_observe_traffic_aimed_elsewhere():
    """KNOWN MILESTONE-1 LIMITATION, recorded so it cannot be forgotten.

    Verified live in a real netns (2026-09-17): an agent aiming at an
    arbitrary external address is *contained* (the veth has nowhere to
    forward it, so it times out) but is NOT *observed* — it never reaches
    the proxy's accept loop. Only traffic addressed to the proxy is seen.

    So milestone 1 proves containment, not visibility. Closing this needs
    iptables REDIRECT + SO_ORIGINAL_DST to pull arbitrary destinations into
    the proxy and recover the intended host/port (ROADMAP milestone 2).
    Until then, do not describe HALT as seeing all egress.
    """
    seen = []
    with DenyAllProxy(on_connection=seen.append) as proxy:
        # Connect to a port that is not the proxy's; nothing is listening.
        stray = socket.socket()
        stray.settimeout(0.5)
        try:
            stray.connect(("127.0.0.1", proxy.port + 1))
        except OSError:
            pass
        finally:
            stray.close()

        time.sleep(0.2)

    assert seen == [], "proxy saw traffic it cannot actually intercept yet"
