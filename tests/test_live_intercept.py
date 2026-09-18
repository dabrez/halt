"""Runs tests/live/*.py for real, inside unprivileged user+net+mount
namespaces. Skipped — loudly, with the reason — when the kernel or distro
forbids that, so a clean run elsewhere is not mistaken for verification.
"""

import os
import shutil
import subprocess
import sys

import pytest

LIVE_DIR = os.path.join(os.path.dirname(__file__), "live")


def _userns_available() -> str | None:
    try:
        r = subprocess.run(
            ["unshare", "-rnm", "true"], capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return f"unshare unusable: {e}"
    return None if r.returncode == 0 else f"unshare -rnm failed: {r.stderr.strip()}"


def run_live(script: str, timeout: float = 60) -> subprocess.CompletedProcess:
    reason = _userns_available()
    if reason:
        pytest.skip(reason)
    return subprocess.run(
        ["unshare", "-rnm", sys.executable, os.path.join(LIVE_DIR, script)],
        capture_output=True, text=True, timeout=timeout,
    )


def test_live_redirect_makes_contained_traffic_visible():
    r = run_live("redirect_scenario.py")
    assert r.returncode == 0, f"\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"


def test_live_tls_termination_through_redirect():
    r = run_live("terminate_scenario.py")
    assert r.returncode == 0, f"\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"


def test_live_gvisor_guest_forced_egress_then_severed():
    if shutil.which("runsc") is None:
        pytest.skip("runsc not installed")
    r = run_live("gvisor_scenario.py", timeout=120)
    assert r.returncode == 0, f"\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
