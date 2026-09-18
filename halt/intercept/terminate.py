"""Terminating proxy: the layer that produces a path.

DenyAllProxy (proxy.py) proves an agent's connection had nowhere else to
go and recovers where it was headed. That gives host and port. The policy
matches on host **and** port **and** path-prefix, because the motivating
incident used an allowlisted host on a different path — so a proxy that
stops at the TCP layer would allow the exact escape HALT exists to catch.

This proxy goes one layer further for HTTP traffic:

1. Peek the first byte. 0x16 is a TLS record header; anything else is
   treated as plaintext HTTP.
2. TLS: complete the handshake *as the server*, presenting a leaf cert for
   the SNI hostname minted by CertAuthority. Plain: no handshake.
3. Read the first request head (request line + headers). Host comes from
   SNI, falling back to the Host header; the path comes from the request
   line.
4. Ask the gate (gate.py). Denied: close — the sandbox side sees EOF /
   reset, and the supervisor has already been told. Allowed: open the real
   upstream (TLS with normal verification if the client used TLS), replay
   the buffered request head, and relay bytes both ways until either side
   closes.

KNOWN LIMITS, all recorded in ROADMAP.md rather than papered over:

* **First request per connection.** Only the first request head on a
  connection is inspected; later requests on a kept-alive connection ride
  the relay unobserved. Fixing this means a streaming HTTP/1.1 framer on
  the client→upstream direction. Until then a deployment that needs
  per-request enforcement should disable keep-alive at the client or
  accept per-connection granularity knowingly.
* **HTTP/1.x only.** The proxy does not offer h2 via ALPN, so compliant
  clients fall back to HTTP/1.1. A client that speaks h2 prior-knowledge
  over plaintext will produce an unparseable head and be denied.
* **Trust.** The sandbox must trust the CA (certs.py). An untrusting client
  fails its handshake: contained, observed at host/port, but no path.
* **IPv4.** SO_ORIGINAL_DST is read for AF_INET only.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Callable

from halt.intercept.certs import CertAuthority
from halt.intercept.proxy import DenyAllProxy, InterceptedConnection, original_destination

_TLS_HANDSHAKE = 0x16
_HEAD_LIMIT = 64 * 1024
_IO_TIMEOUT = 15.0

Decider = Callable[[InterceptedConnection], bool]
UpstreamResolver = Callable[[InterceptedConnection], tuple[str, int]]


def default_upstream(conn: InterceptedConnection) -> tuple[str, int]:
    """Where to open the real connection. When REDIRECT preserved the
    original destination we go exactly there — the agent already did its
    own name resolution and we should not do a second, possibly different,
    one. Only an unredirected connection (direct-to-proxy, tests) resolves
    the hostname itself.
    """
    if conn.redirected and conn.ip:
        return conn.ip, conn.port
    return conn.host, conn.port


class TerminatingProxy(DenyAllProxy):
    def __init__(
        self,
        decide: Decider,
        ca: CertAuthority | None = None,
        upstream: UpstreamResolver = default_upstream,
        on_connection: Callable[[InterceptedConnection], None] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        verify_upstream: bool = True,
        upstream_cafile: str | None = None,
    ):
        super().__init__(on_connection=on_connection, host=host, port=port)
        self._decide = decide
        self._ca = ca or CertAuthority()
        self._upstream = upstream
        self._verify_upstream = verify_upstream
        self._server_ctx = self._build_server_context()
        # Upstream verification uses the system trust store by default —
        # the proxy is a real client of the real destination. `upstream_cafile`
        # is for environments whose upstreams are signed by a private CA.
        self._client_ctx = ssl.create_default_context(cafile=upstream_cafile)
        if not verify_upstream:
            self._client_ctx.check_hostname = False
            self._client_ctx.verify_mode = ssl.CERT_NONE
        self._handlers: list[threading.Thread] = []

    @property
    def ca_cert_path(self) -> str:
        return self._ca.ca_cert_path

    # -- accept loop: one thread per connection -----------------------

    def _dispatch(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        """Relays block for as long as the agent's connection lives; the
        accept loop must not. Each connection gets its own thread, which
        also owns closing the sandbox-side socket.
        """
        t = threading.Thread(
            target=self._run_handler, args=(conn, peer),
            name="halt-terminate-conn", daemon=True,
        )
        self._handlers.append(t)
        t.start()

    def _run_handler(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        try:
            self._handle_accepted(conn, peer)
        except Exception as exc:  # noqa: BLE001 - surfaced, not swallowed
            with self._lock:
                self._callback_errors.append(exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self, timeout: float = 2.0) -> None:
        super().stop(timeout=timeout)
        for t in self._handlers:
            t.join(timeout=timeout)
        self._handlers.clear()

    # -- per-connection ------------------------------------------------

    def _handle_accepted(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        conn.settimeout(_IO_TIMEOUT)
        dst = original_destination(conn)
        if dst is not None:
            ip, port, redirected = dst[0], dst[1], True
        else:
            ip, port = conn.getsockname()[:2]
            redirected = False

        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except (OSError, socket.timeout):
            first = b""
        if not first:
            self._notify(InterceptedConnection(
                host=ip, port=port, path=None, peer=peer, redirected=redirected,
                ip=ip, tls=False,
            ))
            return

        is_tls = first[0] == _TLS_HANDSHAKE
        sni: str | None = None
        stream: socket.socket = conn
        if is_tls:
            try:
                stream, sni = self._terminate_tls(conn)
            except (ssl.SSLError, OSError):
                # Handshake failed (untrusted CA, client abort). Contained;
                # observed at host/port only. Report with no path so the
                # gate's default-deny fires and the record shows why.
                observed = InterceptedConnection(
                    host=ip, port=port, path=None,
                    peer=peer, redirected=redirected, ip=ip, tls=True,
                )
                self._notify(observed)
                self._decide(observed)
                return

        head = _read_head(stream)
        method, path, host_hdr, hdr_port = _parse_head(head)
        host = sni or host_hdr or ip
        if not redirected:
            # Unredirected means the agent addressed us directly, so the
            # listening port says nothing about its intent. The Host header
            # (or the scheme default) is what it actually asked for.
            port = hdr_port or (443 if is_tls else 80)

        observed = InterceptedConnection(
            host=host, port=port, path=path, peer=peer,
            redirected=redirected, ip=ip, tls=is_tls, method=method,
        )
        self._notify(observed)

        if not self._decide(observed):
            return  # close: the sandbox side gets EOF, the supervisor knows

        self._forward(stream, observed, head)

    # -- TLS -------------------------------------------------------------

    def _build_server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # A context needs *some* cert before wrap; the SNI callback swaps
        # in the real one per hostname. This placeholder is never what a
        # hostname-checking client will accept, which is the point.
        placeholder = self._ca.leaf_for("halt.invalid")
        ctx.load_cert_chain(placeholder.cert_path, placeholder.key_path)
        ctx.sni_callback = self._on_sni
        return ctx

    def _on_sni(self, sslobj: ssl.SSLSocket, server_name: str | None, ctx: ssl.SSLContext):
        # Python offers no server-side getter for the received SNI, so the
        # callback is the only place it is visible; stash it on the socket.
        sslobj.halt_sni = server_name  # type: ignore[attr-defined]
        if not server_name:
            return None
        leaf = self._ca.leaf_for(server_name)
        per_host = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        per_host.load_cert_chain(leaf.cert_path, leaf.key_path)
        sslobj.context = per_host
        return None

    def _terminate_tls(self, conn: socket.socket) -> tuple[ssl.SSLSocket, str | None]:
        tls = self._server_ctx.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
        tls.settimeout(_IO_TIMEOUT)
        tls.do_handshake()
        return tls, getattr(tls, "halt_sni", None)

    # -- forwarding ------------------------------------------------------

    def _forward(self, downstream: socket.socket, observed: InterceptedConnection, head: bytes) -> None:
        target = self._upstream(observed)
        upstream: socket.socket = socket.create_connection(target, timeout=_IO_TIMEOUT)
        try:
            if observed.tls:
                upstream = self._client_ctx.wrap_socket(
                    upstream, server_hostname=observed.host
                )
            upstream.sendall(head)
            _relay(downstream, upstream)
        finally:
            try:
                upstream.close()
            except OSError:
                pass


# -- HTTP head handling --------------------------------------------------

def _read_head(stream: socket.socket) -> bytes:
    """Read up to and including the blank line ending the request head.
    Bounded so a client can't hold a handler thread with an endless header.
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > _HEAD_LIMIT:
            break
        try:
            chunk = stream.recv(4096)
        except (OSError, socket.timeout):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_head(head: bytes) -> tuple[str | None, str | None, str | None, int | None]:
    """(method, path, Host name, Host port) from an HTTP/1.x head; Nones if
    it isn't one. A path is only ever returned from a well-formed request
    line — never guessed. The first Host header wins, per RFC 9112 §3.2
    (a second one is a malformed request, not a choice to honour).
    """
    try:
        text = head.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except Exception:  # noqa: BLE001
        return None, None, None, None
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        return None, None, None, None
    method, target = parts[0], parts[1]

    # absolute-form (proxy-style) targets carry the path after the authority
    if target.startswith("http://") or target.startswith("https://"):
        rest = target.split("://", 1)[1]
        target = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    if not target.startswith("/"):
        return method, None, None, None

    host, port = None, None
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            if host.count(":") == 1:  # name:port; leave bare IPv6 alone
                host, _, p = host.rpartition(":")
                port = int(p) if p.isdigit() else None
            break
    return method, target, host, port


def _relay(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes a<->b until either side closes. Two threads: simpler than
    a select loop across a TLS object and a raw socket, and the cost is a
    thread per direction per connection, fine at sandbox scale.
    """
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except (OSError, socket.timeout, ssl.SSLError):
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join(timeout=_IO_TIMEOUT)
