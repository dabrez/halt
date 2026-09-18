"""HttpRevoker against a local fake endpoint. This is the honest extent of
verification: there is no IAM here. What is pinned is the kill-path
contract — never raise, always report."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from halt.backends.gvisor import GvisorBackend
from halt.credentials import HttpRevoker
from halt.kill import execute_kill


class _FakeIam(BaseHTTPRequestHandler):
    received: list = []
    status = 200

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        _FakeIam.received.append((self.headers.get("Authorization"), body))
        self.send_response(_FakeIam.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def iam():
    _FakeIam.received = []
    _FakeIam.status = 200
    srv = HTTPServer(("127.0.0.1", 0), _FakeIam)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/revoke"
    srv.shutdown()


def test_revoke_posts_token_with_bearer_and_returns_true(iam):
    r = HttpRevoker(iam, bearer="halt-svc")
    assert r.revoke("tok-1") is True
    assert _FakeIam.received == [("Bearer halt-svc", {"token_id": "tok-1", "action": "revoke"})]
    assert r.failures == []


def test_http_error_is_false_and_recorded_not_raised(iam):
    _FakeIam.status = 503
    r = HttpRevoker(iam)
    assert r.revoke("tok-1") is False
    assert r.failures[0].reason == "HTTP 503"


def test_unreachable_endpoint_is_false_not_raised():
    r = HttpRevoker("http://127.0.0.1:1/revoke", timeout=0.5)
    assert r.revoke("tok-1") is False
    assert r.failures and r.failures[0].token_id == "tok-1"


def test_plugs_into_backend_and_kill_continues_past_revocation_failure(iam):
    """The reason 'never raise' matters: with revocation down, execute_kill
    must still sever and terminate."""
    _FakeIam.status = 500
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        import subprocess
        return subprocess.CompletedProcess(cmd, returncode=0)

    from halt.backends.gvisor import GvisorContainer
    backend = GvisorBackend(revoke_credential_fn=HttpRevoker(iam).revoke, run_command=fake_run)
    backend.register_container(GvisorContainer(run_id="r", container_id="c", veth_device="v"))

    result = execute_kill(backend, "r", ["tok-1", "tok-2"])
    assert result.credentials_revoked == []
    assert result.network_severed and result.process_terminated
    assert len(calls) == 2
