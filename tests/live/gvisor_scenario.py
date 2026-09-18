"""LIVE scenario: a real gVisor guest behind forced egress, then severed.

Closes the one README claim that was still "not verified live":
GvisorBackend.sever_network(). The earlier smoke test ran --network=none
and so had no device to tear down. Here the guest is wired to a veth pair
for real, its egress is proven to reach the proxy, and then the backend's
exact `ip link delete <veth>` is shown to cut it off.

Layout (all inside `unshare -rnm`, root-in-userns):

    outer ns ("host")                 sandbox ns
    proxy on 10.201.0.1  <-- veth -->  runsc --network=host  (guest sees
    REDIRECT on halt0                   the sandbox ns as its "host" net)

runsc runs *inside* the sandbox namespace with --network=host, which is
how a gVisor guest ends up on the veth without needing runsc to create
network devices itself (which rootless runsc cannot do).

Exit code 0 means every assertion held.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from halt.backends.gvisor import GvisorBackend, GvisorContainer  # noqa: E402
from halt.intercept import DenyAllProxy, NetnsConfig, NetnsEgress  # noqa: E402

WORK = "/run/gv"
RUNSC_FLAGS = ["--rootless", "--ignore-cgroups", "--network=host", "--root", f"{WORK}/state"]
CTR = "gv-live"


def fail(msg: str) -> None:
    print("LIVE FAIL:", msg)
    sys.exit(1)


def checked_run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        fail(f"{' '.join(map(str, cmd))} -> rc={r.returncode} stderr={r.stderr.strip()[-400:]}")
    return r


def build_bundle(netns_name: str) -> str:
    """Minimal OCI bundle: static busybox, and `sleep 600` as the guest."""
    bundle = f"{WORK}/bundle"
    rootfs = f"{bundle}/rootfs"
    for d in ("bin", "proc", "dev", "tmp", "etc"):
        os.makedirs(f"{rootfs}/{d}", exist_ok=True)
    shutil.copy("/usr/bin/busybox", f"{rootfs}/bin/busybox")
    for applet in ("sh", "sleep", "nc"):
        os.symlink("busybox", f"{rootfs}/bin/{applet}")
    checked_run(["runsc", "spec", "--", "/bin/sleep", "600"], cwd=bundle)

    # `runsc spec` asks for a network namespace with no path, which means
    # "make a fresh, empty one" — the guest would be unreachable from
    # everything, veth included. Pin it to the sandbox namespace instead.
    cfg_path = f"{bundle}/config.json"
    with open(cfg_path) as f:
        spec = json.load(f)
    for ns in spec["linux"]["namespaces"]:
        if ns["type"] == "network":
            ns["path"] = f"/run/netns/{netns_name}"
    with open(cfg_path, "w") as f:
        json.dump(spec, f)
    return bundle


def main() -> None:
    if shutil.which("runsc") is None:
        fail("runsc not installed")
    checked_run(["mount", "-t", "tmpfs", "tmpfs", "/run"])
    checked_run(["ip", "link", "set", "lo", "up"])
    os.makedirs(WORK, exist_ok=True)

    cfg = NetnsConfig(name="halt-gv")
    egress = NetnsEgress(cfg, run_command=checked_run)
    egress.create()

    proxy = DenyAllProxy(host=cfg.host_addr, port=0)
    proxy.start()
    egress.redirect_tcp_to(proxy.port)

    def in_sb(*cmd: str, **kw) -> subprocess.CompletedProcess:
        kw.setdefault("capture_output", True)
        kw.setdefault("text", True)
        kw.setdefault("timeout", 30)  # a hang should be a failure, not a wait
        return subprocess.run(["ip", "netns", "exec", cfg.name, *cmd], **kw)

    def runsc(*args: str, **kw) -> subprocess.CompletedProcess:
        return in_sb("runsc", *RUNSC_FLAGS, *args, **kw)

    # --- boot a real gVisor guest on the veth ---
    bundle = build_bundle(cfg.name)
    # A detached sandbox inherits our stdio; if those are pipes, run()
    # blocks until the *sandbox* exits. Give it a file instead.
    with open(f"{WORK}/run.log", "w") as log:
        r = runsc("run", "-detach", "-bundle", bundle, CTR,
                  capture_output=False, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    if r.returncode != 0:
        fail(f"runsc run: {open(f'{WORK}/run.log').read()[-400:]}")
    for _ in range(50):
        st = runsc("state", CTR)
        if st.returncode == 0 and '"status": "running"' in st.stdout:
            break
        time.sleep(0.1)
    else:
        fail(f"guest never reached running: {st.stdout} {st.stderr}")

    def guest_egress(host: str, port: int) -> subprocess.CompletedProcess:
        # busybox nc: exit 0 on connect (then EOF from deny-all), non-zero
        # when the connection cannot be made at all.
        return runsc("exec", CTR, "/bin/nc", "-w", "2", host, str(port))

    # --- 1. the guest's egress is forced through HALT ---
    before = len(proxy.seen)
    r = guest_egress("1.1.1.1", 443)
    time.sleep(0.2)
    if len(proxy.seen) != before + 1:
        fail(f"guest egress not observed by proxy (nc rc={r.returncode}, stderr={r.stderr.strip()})")
    obs = proxy.seen[-1]
    if (obs.host, obs.port, obs.redirected) != ("1.1.1.1", 443, True):
        fail(f"unexpected observation from gVisor guest: {obs}")

    # --- 2. GvisorBackend.sever_network(), exactly as written ---
    def backend_run(cmd):
        # Same substitution the original smoke test used: the backend's
        # command lines are unchanged except that `runsc` gets the flags
        # this rootless setup needs and runs in the sandbox namespace.
        if cmd[0] == "runsc":
            return in_sb("runsc", *RUNSC_FLAGS, *cmd[1:])
        return subprocess.run(cmd, capture_output=True, text=True)

    backend = GvisorBackend(run_command=backend_run)
    backend.register_container(GvisorContainer(run_id="live", container_id=CTR, veth_device=cfg.host_if))

    if not backend.sever_network("live"):
        fail("sever_network returned False")
    link = subprocess.run(["ip", "link", "show", cfg.host_if], capture_output=True, text=True)
    if link.returncode == 0:
        fail("veth still exists after sever_network")

    before = len(proxy.seen)
    r = guest_egress("1.1.1.1", 443)
    time.sleep(0.2)
    if len(proxy.seen) != before:
        fail("guest still reached the proxy after sever_network")
    if r.returncode == 0:
        fail("guest nc succeeded after sever_network")

    # --- 3. GvisorBackend.terminate(), exactly as written ---
    if not backend.terminate("live"):
        fail("terminate returned False")
    for _ in range(50):
        st = runsc("state", CTR)
        if st.returncode != 0 or '"status": "running"' not in st.stdout:
            break
        time.sleep(0.1)
    else:
        fail("guest still running after terminate")

    runsc("delete", "-force", CTR)
    proxy.stop()
    print(json.dumps({"observed_from_guest": [obs.host, obs.port], "severed": True, "terminated": True}))


if __name__ == "__main__":
    main()
