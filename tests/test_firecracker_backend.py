"""Tests for the logic in FirecrackerBackend that doesn't require a real
VM: registration bookkeeping, unregistered-run handling, credential
delegation, and that the right host commands get built. The actual `ip`
commands and process kill are exercised with injected fakes here — this
does NOT prove they work against a real Firecracker instance, only that
the backend's own logic is correct. See README for what remains unverified.
"""

import subprocess

import pytest

from halt.backends.firecracker import FirecrackerBackend, FirecrackerVM


def make_vm(run_id="run-1"):
    return FirecrackerVM(
        run_id=run_id,
        api_socket_path="/tmp/fc-run-1.sock",
        firecracker_pid=999999,  # deliberately not a real pid
        tap_device="tap-run-1",
    )


def test_unregistered_run_returns_false_not_raise():
    backend = FirecrackerBackend()
    assert backend.sever_network("no-such-run") is False
    assert backend.terminate("no-such-run") is False


def test_sever_network_runs_expected_ip_commands():
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0)

    backend = FirecrackerBackend(run_command=fake_run)
    backend.register_vm(make_vm())

    assert backend.sever_network("run-1") is True
    assert calls == [
        ["ip", "link", "set", "tap-run-1", "down"],
        ["ip", "tuntap", "del", "dev", "tap-run-1", "mode", "tap"],
    ]


def test_sever_network_propagates_command_failure():
    def fake_run(cmd):
        return subprocess.CompletedProcess(cmd, returncode=1)

    backend = FirecrackerBackend(run_command=fake_run)
    backend.register_vm(make_vm())

    assert backend.sever_network("run-1") is False


def test_terminate_handles_missing_process_gracefully():
    """firecracker_pid points at a pid that doesn't exist (we picked
    999999 deliberately) — terminate() must report False, not raise.
    """
    backend = FirecrackerBackend()
    backend.register_vm(make_vm())
    assert backend.terminate("run-1") is False


def test_revoke_credential_without_callback_raises_not_silently_noop():
    backend = FirecrackerBackend()
    with pytest.raises(NotImplementedError):
        backend.revoke_credential("tok-1")


def test_revoke_credential_delegates_to_injected_callback():
    seen = []
    backend = FirecrackerBackend(revoke_credential_fn=lambda t: seen.append(t) or True)
    assert backend.revoke_credential("tok-1") is True
    assert seen == ["tok-1"]
