"""Forced-egress interception point.

This is the piece that turns HALT from a policy engine into an enforcement
point. Every other fuse entry in this codebase is *advisory*: NetworkFuse
only ever sees a connection because the calling code volunteered it, which
means an agent that just opens a socket is never observed at all.

The proxy closes that gap by construction rather than by cooperation. The
sandbox is placed in a network namespace whose only route out is the host
side of a veth pair, and a nat REDIRECT rule there pulls every TCP
connection into this listener (see netns.py). A connection attempt is
observed because it had nowhere else to go — not because anything inside
the sandbox chose to report it.

Where the destination comes from: after REDIRECT the accepted socket's own
address is the proxy's, not where the agent was going. The kernel keeps the
pre-NAT destination in conntrack and hands it back through the
SO_ORIGINAL_DST socket option; `original_destination()` reads it. Verified
live (2026-09-17): connections aimed at 1.1.1.1:443, 93.184.216.34:80 and
8.8.8.8:53 arrived here with all three recovered exactly. Without REDIRECT
(milestone 1's posture) the option is absent and we fall back to the local
socket address, flagged with `redirected=False` so nothing downstream
mistakes the proxy's own address for the agent's target.

`DenyAllProxy` is milestone 1's posture, kept as the base: accept, record,
close. It still parses nothing and forwards nothing. Path is None here
because before TLS termination it genuinely is not knowable — see
terminate.py for the layer that adds it.
"""

from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass
from typing import Callable

#: Linux-specific getsockopt level/option for the pre-NAT destination. Not
#: exposed as a constant by the socket module.
_SOL_IP = 0
_SO_ORIGINAL_DST = 80


def original_destination(sock: socket.socket) -> tuple[str, int] | None:
    """The address the peer was connecting to before REDIRECT rewrote it.

    Returns None when the option is unavailable (no NAT applied to this
    connection, non-Linux, or non-IPv4). Callers must treat None as
    "unknown" — it never means "the local address".
    """
    try:
        raw = sock.getsockopt(_SOL_IP, _SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    # struct sockaddr_in: family(2) port(2, network order) addr(4) zero(8)
    port, addr = struct.unpack("!2xH4s8x", raw)
    return socket.inet_ntoa(addr), port


@dataclass(frozen=True)
class InterceptedConnection:
    """One egress attempt seen by the proxy.

    `host`/`port` are the agent's *intended* destination when `redirected`
    is True (recovered via SO_ORIGINAL_DST). When False they are the local
    socket address the agent happened to connect to, which is only a real
    destination if the agent addressed the proxy directly. Once TLS is
    terminated (terminate.py) `host` is upgraded to the SNI / Host-header
    name — the thing policy globs match on — and `ip` keeps the literal
    address the agent connected to.

    `path` is None until something reads an HTTP request line, and None is
    not a placeholder for "/" — a TCP connection has no path. Callers must
    not invent one; a fuse that needs a path should treat None as
    "unknown", never as "root".
    """

    host: str
    port: int
    path: str | None = None
    #: Address the sandbox-side socket connected from, useful for
    #: correlating an attempt back to a process during verification.
    peer: tuple[str, int] | None = None
    #: True if host/port came from SO_ORIGINAL_DST rather than getsockname.
    redirected: bool = False
    #: The literal destination address (pre-NAT when redirected).
    ip: str | None = None
    #: Whether the agent spoke TLS to us.
    tls: bool = False
    #: HTTP method, when a request head was read.
    method: str | None = None


class DenyAllProxy:
    """A TCP listener that accepts, records, and immediately closes.

    Nothing is forwarded upstream. This is the deny-everything enforcement
    posture: the sandbox's only route out terminates here, and here refuses.
    A connection reaching this listener is proof the routing worked.

    `on_connection` is called for every accepted attempt, on the accepting
    thread, before the socket is closed. Exceptions from the callback are
    deliberately not swallowed into silence — see _serve.

    Subclasses override `_handle_accepted()` to do something with the socket
    (terminate TLS, consult policy, forward) and `_dispatch()` to change
    the threading model; the accept loop, observation bookkeeping and error
    surfacing stay here.
    """

    def __init__(
        self,
        on_connection: Callable[[InterceptedConnection], None] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ):
        self._on_connection = on_connection
        self._requested_host = host
        self._requested_port = port

        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self._lock = threading.Lock()
        self._seen: list[InterceptedConnection] = []
        self._callback_errors: list[BaseException] = []

    # -- lifecycle ----------------------------------------------------

    def start(self) -> None:
        if self._sock is not None:
            raise RuntimeError("proxy already started")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._requested_host, self._requested_port))
        sock.listen(64)
        # Bounded so stop() can't block forever on a quiet listener.
        sock.settimeout(0.2)
        self._sock = sock

        self._thread = threading.Thread(
            target=self._serve, name=f"halt-{type(self).__name__}", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "DenyAllProxy":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- introspection ------------------------------------------------

    @property
    def address(self) -> tuple[str, int]:
        """The bound (host, port). Port 0 is resolved to the real one, so
        tests and netns wiring can ask rather than guess.
        """
        if self._sock is None:
            raise RuntimeError("proxy not started")
        return self._sock.getsockname()

    @property
    def port(self) -> int:
        return self.address[1]

    @property
    def seen(self) -> list[InterceptedConnection]:
        with self._lock:
            return list(self._seen)

    @property
    def callback_errors(self) -> list[BaseException]:
        """Exceptions raised by on_connection or a handler, surfaced rather
        than hidden.

        A fuse callback that throws would otherwise fail silently on a
        daemon thread — and a silently broken observation path is the exact
        failure this whole component exists to rule out.
        """
        with self._lock:
            return list(self._callback_errors)

    # -- internals ----------------------------------------------------

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # Socket closed under us during stop(); normal shutdown.
                break
            self._dispatch(conn, peer)

    def _dispatch(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        """Inline: handle, then close. Deny-all never blocks long enough to
        need anything else. Whatever the handler did, the sandbox side of
        the connection ends here.
        """
        try:
            self._handle_accepted(conn, peer)
        except Exception as exc:  # noqa: BLE001 - a handler bug must not kill the accept loop
            with self._lock:
                self._callback_errors.append(exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _notify(self, observed: InterceptedConnection) -> None:
        """Record an observation and tell the observer. Shared by every
        posture so the bookkeeping is identical whether we deny or forward.
        """
        with self._lock:
            self._seen.append(observed)
        if self._on_connection is not None:
            try:
                self._on_connection(observed)
            except BaseException as exc:  # noqa: BLE001 - recorded, not swallowed
                with self._lock:
                    self._callback_errors.append(exc)

    def _handle_accepted(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        """Deny-all: observe at the TCP layer, then let _dispatch close it."""
        dst = original_destination(conn)
        if dst is not None:
            host, port, redirected = dst[0], dst[1], True
        else:
            try:
                host, port = conn.getsockname()[:2]
            except OSError:
                host, port = ("unknown", -1)
            redirected = False

        self._notify(InterceptedConnection(
            host=host, port=port, path=None,
            peer=peer[:2] if peer else None,
            redirected=redirected, ip=host,
        ))
