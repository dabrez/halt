"""LIVE scenario: forced egress with REDIRECT, run under `unshare -rnm`.

Executed by tests/test_live_intercept.py, which skips when user namespaces
are unavailable. Everything here is real: a real second network namespace,
a real veth pair, real nat/filter rules, and an agent subprocess that was
told nothing about HALT. Exit code 0 means every assertion held; any
failure prints the reason and exits 1.

The point of running this from pytest rather than as a one-off script is
that "verified live once, by hand" rots. This re-verifies on every run.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from halt.events import FuseKind, Severity, TripEvent  # noqa: E402
from halt.intercept.netns import NetnsConfig, NetnsEgress  # noqa: E402
from halt.intercept.proxy import DenyAllProxy  # noqa: E402
from halt.kill import LocalProcessBackend  # noqa: E402
from halt.sinks import LocalJsonlSink  # noqa: E402
from halt.supervisor import Supervisor  # noqa: E402

TARGETS = [("1.1.1.1", 443), ("93.184.216.34", 80), ("8.8.8.8", 53)]

AGENT = """
import json, socket, sys
out = []
for host, port in json.loads(sys.argv[1]):
    try:
        s = socket.create_connection((host, port), timeout=3)
        d = s.recv(64)
        s.close()
        out.append([host, port, "connected", len(d)])
    except Exception as e:
        out.append([host, port, type(e).__name__, -1])
print(json.dumps(out))
"""


def fail(msg: str) -> None:
    print("LIVE FAIL:", msg)
    sys.exit(1)


def checked_run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        fail(f"{' '.join(cmd)} -> rc={r.returncode} stderr={r.stderr.strip()}")
    return r


def main() -> None:
    # `ip netns` needs /run/netns; inside a private mount ns we own /run.
    checked_run(["mount", "-t", "tmpfs", "tmpfs", "/run"])

    cfg = NetnsConfig(name="halt-live")
    egress = NetnsEgress(cfg, run_command=checked_run)
    egress.create()

    routes = egress.routes().stdout
    if routes.count("\n") != 2 or "default via 10.201.0.1" not in routes:
        fail(f"unexpected sandbox routes:\n{routes}")

    sink = LocalJsonlSink("/run/halt-live-events.jsonl")
    sup = Supervisor(LocalProcessBackend(), sink, run_id="live")

    def on_conn(c):
        sup.report(TripEvent(
            fuse=FuseKind.NETWORK, severity=Severity.KILL,
            reason=f"egress to {c.host}:{c.port} (deny-all)",
            evidence={"host": c.host, "port": c.port, "redirected": c.redirected},
            run_id="live",
        ))

    proxy = DenyAllProxy(on_connection=on_conn, host=cfg.host_addr, port=0)
    proxy.start()

    # --- Phase 1: containment without visibility (milestone 1 finding) ---
    r = egress.exec_in_ns(sys.executable, "-c", AGENT, json.dumps(TARGETS))
    phase1 = json.loads(r.stdout)
    if any(row[2] == "connected" for row in phase1):
        fail(f"phase 1: something connected with no REDIRECT: {phase1}")
    time.sleep(0.2)
    if proxy.seen:
        fail(f"phase 1: proxy saw traffic it should not have: {proxy.seen}")

    # --- Phase 2: REDIRECT turns containment into visibility ---
    if not egress.redirect_tcp_to(proxy.port):
        fail("redirect_tcp_to failed")
    if not egress.drop_non_tcp():
        fail("drop_non_tcp failed")

    r = egress.exec_in_ns(sys.executable, "-c", AGENT, json.dumps(TARGETS))
    phase2 = json.loads(r.stdout)
    if not all(row[2] == "connected" and row[3] == 0 for row in phase2):
        fail(f"phase 2: expected connect+EOF for every target: {phase2}")

    deadline = time.time() + 3
    while time.time() < deadline and len(proxy.seen) < len(TARGETS):
        time.sleep(0.02)

    recovered = sorted((c.host, c.port) for c in proxy.seen)
    if recovered != sorted(TARGETS):
        fail(f"original destinations not recovered: {recovered}")
    if not all(c.redirected for c in proxy.seen):
        fail("some connections not flagged redirected")
    if not all(c.peer and c.peer[0] == cfg.sandbox_addr for c in proxy.seen):
        fail(f"peer not the sandbox address: {[c.peer for c in proxy.seen]}")

    # --- Phase 3: the kill path fired, once, and was persisted ---
    if not sup.killed or sup.cause is None:
        fail("supervisor did not kill")
    if len(sink.read_all()) != len(TARGETS):
        fail("not every observation reached the sink")
    if proxy.callback_errors:
        fail(f"callback errors: {proxy.callback_errors}")

    # --- Phase 4: non-TCP is contained (not observed — see ROADMAP) ---
    # Unchecked on purpose: a non-zero exit (100% loss) is the pass condition.
    r = subprocess.run(
        ["ip", "netns", "exec", cfg.name, "ping", "-c", "1", "-W", "1", "8.8.8.8"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        fail("ICMP escaped the sandbox")

    proxy.stop()
    egress.destroy()
    nat = checked_run(["iptables", "-t", "nat", "-S", "PREROUTING"]).stdout
    if "REDIRECT" in nat:
        fail("REDIRECT rule survived destroy()")

    print(json.dumps({"phase1": phase1, "phase2": phase2, "recovered": recovered}))


if __name__ == "__main__":
    main()
