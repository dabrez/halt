"""TerminatingProxy on loopback: plain HTTP and TLS, allow and deny.

No REDIRECT here (that needs a netns; see tests/live/), so connections are
unredirected and the upstream is resolved through an injected resolver
pointing at a local server. What these tests establish is the HTTP/TLS
layer: SNI → host, request line → path, gate consulted, denied connections
closed, allowed ones relayed with the response intact.
"""

from __future__ import annotations

import http.client
import shutil
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from halt.events import Severity
from halt.intercept import CertAuthority, PolicyGate, TerminatingProxy
from halt.kill import LocalProcessBackend
from halt.policy import NetworkRule, Policy
from halt.sinks import LocalJsonlSink
from halt.supervisor import Supervisor

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI required")

UPSTREAM_NAME = "artifactory.internal"


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, so the relay outlives one exchange

    def do_GET(self):
        body = f"upstream saw {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    return CertAuthority(tmp_path_factory.mktemp("ca"))


@pytest.fixture
def upstream_plain():
    srv = HTTPServer(("127.0.0.1", 0), _Upstream)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address
    srv.shutdown()


@pytest.fixture
def upstream_tls(ca):
    """A real HTTPS upstream, using a leaf from the same CA so the proxy's
    client side can verify it against ca_cert_path."""
    srv = HTTPServer(("127.0.0.1", 0), _Upstream)
    leaf = ca.leaf_for("127.0.0.1")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(leaf.cert_path, leaf.key_path)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address
    srv.shutdown()


def make_world(tmp_path, ca, upstream_addr, tls_upstream=False):
    policy = Policy(
        run_id="run-1", org_id="acme",
        network_rules=(NetworkRule(host=UPSTREAM_NAME, port=443 if tls_upstream else 80,
                                   path_prefix="/api/npm/"),),
    )
    sink = LocalJsonlSink(tmp_path / "events.jsonl")
    sup = Supervisor(LocalProcessBackend(), sink, run_id="run-1")
    gate = PolicyGate(policy, sup)
    proxy = TerminatingProxy(
        decide=gate.decide, ca=ca,
        upstream=lambda _c: upstream_addr,
        verify_upstream=False,  # upstream leaf is for 127.0.0.1; the hostname check would fail on SNI name
    )
    return proxy, sup, sink


def wait_for(pred, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


# -- plain HTTP ------------------------------------------------------------

def test_plain_http_allowed_path_is_forwarded(tmp_path, ca, upstream_plain):
    proxy, sup, sink = make_world(tmp_path, ca, upstream_plain)
    with proxy:
        c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
        c.putrequest("GET", "/api/npm/lodash", skip_host=True)
        c.putheader("Host", f"{UPSTREAM_NAME}:80")
        c.endheaders()
        r = c.getresponse()
        assert r.status == 200
        assert r.read() == b"upstream saw /api/npm/lodash"
        c.close()

    assert not sup.killed
    seen = proxy.seen[0]
    assert (seen.host, seen.path, seen.tls, seen.method) == (UPSTREAM_NAME, "/api/npm/lodash", False, "GET")
    events = sink.read_all()
    assert [e.severity for e in events] == [Severity.INFO]


def test_plain_http_same_host_wrong_path_is_killed(tmp_path, ca, upstream_plain):
    """The motivating incident's shape: allowlisted host, different path."""
    proxy, sup, sink = make_world(tmp_path, ca, upstream_plain)
    with proxy:
        c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
        c.putrequest("GET", "/api/admin/tokens", skip_host=True)
        c.putheader("Host", UPSTREAM_NAME)
        c.endheaders()
        with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError, http.client.BadStatusLine)):
            c.getresponse()
        c.close()
        assert wait_for(lambda: sup.killed)

    assert sup.cause.severity is Severity.KILL
    assert sup.cause.evidence["path"] == "/api/admin/tokens"
    assert proxy.callback_errors == []


def test_non_http_bytes_are_denied_with_no_path(tmp_path, ca, upstream_plain):
    proxy, sup, sink = make_world(tmp_path, ca, upstream_plain)
    with proxy:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        s.sendall(b"SSH-2.0-OpenSSH_9.6\r\n\r\n")
        assert s.recv(10) == b""
        s.close()
        assert wait_for(lambda: sup.killed)

    assert sup.cause.evidence["path"] is None
    assert "no HTTP request" in sup.cause.reason


# -- TLS ---------------------------------------------------------------------

def _tls_client(proxy, ca, server_hostname):
    ctx = ssl.create_default_context(cafile=ca.ca_cert_path)
    raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
    return ctx.wrap_socket(raw, server_hostname=server_hostname)


def test_tls_sni_names_the_host_and_allowed_path_forwards(tmp_path, ca, upstream_tls):
    proxy, sup, sink = make_world(tmp_path, ca, upstream_tls, tls_upstream=True)
    with proxy:
        s = _tls_client(proxy, ca, UPSTREAM_NAME)
        # Handshake succeeded against a leaf minted for the SNI name, verified
        # by the client against the CA — i.e. the trust path the sandbox needs.
        assert s.getpeercert()["subjectAltName"] == (("DNS", UPSTREAM_NAME),)
        s.sendall(b"GET /api/npm/react HTTP/1.1\r\nHost: artifactory.internal\r\nConnection: close\r\n\r\n")
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()

    assert b"200 OK" in buf and b"upstream saw /api/npm/react" in buf
    assert not sup.killed
    seen = proxy.seen[0]
    assert (seen.host, seen.port, seen.path, seen.tls) == (UPSTREAM_NAME, proxy.seen[0].port, "/api/npm/react", True)


def test_tls_wrong_path_is_killed_after_handshake(tmp_path, ca, upstream_tls):
    proxy, sup, sink = make_world(tmp_path, ca, upstream_tls, tls_upstream=True)
    with proxy:
        s = _tls_client(proxy, ca, UPSTREAM_NAME)
        s.sendall(b"GET /api/admin/keys HTTP/1.1\r\nHost: artifactory.internal\r\n\r\n")
        try:
            got = s.recv(4096)
        except (ssl.SSLError, ConnectionResetError):
            got = b""
        s.close()
        assert got == b""
        assert wait_for(lambda: sup.killed)

    assert sup.cause.evidence["path"] == "/api/admin/keys"
    assert sup.cause.evidence["tls"] is True


def test_untrusting_client_is_contained_and_observed_without_path(tmp_path, ca, upstream_tls):
    """The deployment caveat from certs.py, as a test: a client that does not
    trust the CA fails its handshake. Nothing leaks, host/port are still seen,
    and the gate's no-path default-deny fires."""
    proxy, sup, sink = make_world(tmp_path, ca, upstream_tls, tls_upstream=True)
    with proxy:
        ctx = ssl.create_default_context()  # system trust store: no HALT CA
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        with pytest.raises(ssl.SSLCertVerificationError):
            ctx.wrap_socket(raw, server_hostname=UPSTREAM_NAME)
        raw.close()
        assert wait_for(lambda: sup.killed)

    seen = proxy.seen[0]
    assert seen.tls is True and seen.path is None


def test_second_request_on_kept_alive_connection_is_not_inspected(tmp_path, ca, upstream_plain):
    """KNOWN LIMIT (ROADMAP): only the first request head per connection is
    gated. Pinned as a test so the limitation is a fact in the suite, not a
    footnote someone has to remember."""
    proxy, sup, sink = make_world(tmp_path, ca, upstream_plain)
    with proxy:
        c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
        c.request("GET", "/api/npm/first", headers={"Host": UPSTREAM_NAME})
        assert c.getresponse().read() == b"upstream saw /api/npm/first"
        c.request("GET", "/api/admin/second", headers={"Host": UPSTREAM_NAME})
        r = c.getresponse()
        assert r.read() == b"upstream saw /api/admin/second"  # rode the relay unobserved
        c.close()

    assert not sup.killed
    assert [e.evidence["path"] for e in sink.read_all()] == ["/api/npm/first"]


def test_ca_mints_one_leaf_per_host_and_caches(ca):
    a = ca.leaf_for("example.test")
    b = ca.leaf_for("example.test")
    c = ca.leaf_for("other.test")
    assert a == b and a != c
