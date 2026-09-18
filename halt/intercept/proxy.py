"""Forced-egress interception point.

This is the piece that turns HALT from a policy engine into an enforcement
point. Every other fuse entry in this codebase is *advisory*: NetworkFuse
only ever sees a connection because the calling code volunteered it, which
means an agent that just opens a socket is never observed at all.

The proxy closes that gap by construction rather than by cooperation. The
sandbox is placed in a network namespace whose only route out is this
listener (see netns.py), so a connection attempt is observed because it had
nowhere else to go — not because anything inside the sandbox chose to report
it.

MILESTONE 1 SCOPE — deliberately tiny:

    Deny everything. Parse nothing. Allow no traffic through.

No TLS termination, no path extraction, no policy consultation. The risky
assumption being tested here is *not* "can we parse HTTP" — it is "can we
actually force all egress through this thing." That claim either holds or it
doesn't, and it is worth isolating from every other source of failure. A
plaintext-only-but-forwarding proxy would have taught us the easy half and
postponed the hard one.

Consequently `observe_connection()` below reports host and port and a path of
None. That is honest rather than lazy: at this layer, before any TLS
termination, the path genuinely is not knowable. Milestone 2 (see ROADMAP.md)
adds termination and with it the path, which is what NetworkRule actually
wants to match on.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class InterceptedConnection:
    """One egress attempt seen by the proxy.

    `path` is None at this milestone and is not a placeholder for "/" — a
    CONNECT-less TCP connection has no path until something terminates TLS
    and reads a request line. Callers must not invent one; a fuse that needs
    a path should treat None as "unknown", never as "root".
    """

    host: str
    port: int
    path: str | None = None
    #: Address the sandbox-side socket connected from, useful for
    #: correlating an attempt back to a process during verification.
    peer: tuple[str, int] | None = None


class DenyAllProxy:
    """A TCP listener that accepts, records, and immediately closes.

    Nothing is forwarded upstream. This is the milestone-1 enforcement
    posture: the sandbox's only route out terminates here, and here refuses.
    A connection reaching this listener is proof the routing worked; a
    connection *not* reaching it while the sandbox still gets out is the
    finding we care about most (see ROADMAP.md).

    `on_connection` is called for every accepted attempt, on the accepting
    thread, before the socket is closed. Exceptions from the callback are
    deliberately not swallowed into silence — see _serve.
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
            target=self._serve, name="halt-deny-all-proxy", daemon=True
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
        """Exceptions raised by on_connection, surfaced rather than hidden.

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

            try:
                self._handle(conn, peer)
            finally:
                # Deny-all: nothing is forwarded, the connection dies here.
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        # SO_ORIGINAL_DST would give the pre-DNAT destination under a
        # REDIRECT rule. Milestone 1 routes rather than redirects, so the
        # original destination is not recoverable here yet; record what is
        # actually known instead of fabricating it.
        try:
            local_host, local_port = conn.getsockname()[:2]
        except OSError:
            local_host, local_port = ("unknown", -1)

        observed = InterceptedConnection(
            host=local_host,
            port=local_port,
            path=None,
            peer=peer[:2] if peer else None,
        )

        with self._lock:
            self._seen.append(observed)

        if self._on_connection is None:
            return
        try:
            self._on_connection(observed)
        except BaseException as exc:  # noqa: BLE001 - recorded, not swallowed
            with self._lock:
                self._callback_errors.append(exc)
