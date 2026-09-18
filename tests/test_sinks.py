import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from halt.events import FuseKind, Severity, TripEvent
from halt.kill import LocalProcessBackend
from halt.sinks import ExternalBroadcastSink, LocalJsonlSink, Sink, TeeSink
from halt.supervisor import Supervisor


class _Registry(BaseHTTPRequestHandler):
    received: list = []
    status = 200

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        _Registry.received.append(json.loads(self.rfile.read(n)))
        self.send_response(_Registry.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def registry():
    _Registry.received = []
    _Registry.status = 200
    srv = HTTPServer(("127.0.0.1", 0), _Registry)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/events"
    srv.shutdown()


def ev(**kw):
    return TripEvent(fuse=FuseKind.NETWORK, severity=Severity.KILL, reason="x", run_id="r", **kw)


def test_broadcast_posts_serialized_event(registry):
    s = ExternalBroadcastSink(registry)
    e = ev()
    s.emit(e)
    assert _Registry.received == [e.to_dict()]
    assert s.delivered == 1 and s.failures == []


def test_broadcast_failure_is_recorded_never_raised(registry):
    _Registry.status = 500
    s = ExternalBroadcastSink(registry)
    s.emit(ev())
    assert s.failures[0].reason == "HTTP 500"

    dead = ExternalBroadcastSink("http://127.0.0.1:1/events", timeout=0.5)
    dead.emit(ev())
    assert dead.failures


def test_tee_writes_local_first_and_survives_a_broken_sink(tmp_path):
    order = []

    class Boom(Sink):
        def emit(self, event):
            order.append("boom")
            raise RuntimeError("registry down")

    local = LocalJsonlSink(tmp_path / "e.jsonl")

    class Spy(Sink):
        def emit(self, event):
            order.append("local")
            local.emit(event)

    tee = TeeSink(Spy(), Boom())
    tee.emit(ev())
    assert order == ["local", "boom"]
    assert len(local.read_all()) == 1
    assert tee.failures[0][0] == "Boom"


def test_kill_still_happens_when_broadcast_is_down(tmp_path):
    """The whole point of swallowing: the supervisor emits *before* it
    decides, so a dead registry must not stand between a trip and a kill."""
    local = LocalJsonlSink(tmp_path / "e.jsonl")
    dead = ExternalBroadcastSink("http://127.0.0.1:1/events", timeout=0.5)
    sup = Supervisor(LocalProcessBackend(), TeeSink(local, dead), run_id="r")

    sup.report(ev())
    assert sup.killed
    assert len(local.read_all()) == 1
    assert dead.failures
