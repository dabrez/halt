import subprocess

import pytest

from halt.backends.gvisor import GvisorBackend, GvisorContainer


def make_container(run_id="run-1"):
    return GvisorContainer(run_id=run_id, container_id="ctr-run-1", veth_device="veth-run-1")


def test_unregistered_run_returns_false_not_raise():
    backend = GvisorBackend()
    assert backend.sever_network("no-such-run") is False
    assert backend.terminate("no-such-run") is False


def test_terminate_runs_expected_runsc_command():
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0)

    backend = GvisorBackend(run_command=fake_run)
    backend.register_container(make_container())

    assert backend.terminate("run-1") is True
    assert calls == [["runsc", "kill", "ctr-run-1", "SIGKILL"]]


def test_sever_network_runs_expected_ip_command():
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0)

    backend = GvisorBackend(run_command=fake_run)
    backend.register_container(make_container())

    assert backend.sever_network("run-1") is True
    assert calls == [["ip", "link", "delete", "veth-run-1"]]


def test_command_failure_reported_as_false():
    def fake_run(cmd):
        return subprocess.CompletedProcess(cmd, returncode=1)

    backend = GvisorBackend(run_command=fake_run)
    backend.register_container(make_container())

    assert backend.terminate("run-1") is False
    assert backend.sever_network("run-1") is False


def test_revoke_credential_without_callback_raises_not_silently_noop():
    backend = GvisorBackend()
    with pytest.raises(NotImplementedError):
        backend.revoke_credential("tok-1")


def test_revoke_credential_delegates_to_injected_callback():
    seen = []
    backend = GvisorBackend(revoke_credential_fn=lambda t: seen.append(t) or True)
    assert backend.revoke_credential("tok-1") is True
    assert seen == ["tok-1"]
