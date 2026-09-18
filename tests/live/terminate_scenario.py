"""LIVE scenario: TLS termination through REDIRECT, run under `unshare -rnm`.

The full stack, for real: an agent in its own network namespace makes
HTTPS requests to an IP it chose, with the SNI name it chose. It is told
nothing about HALT except that its trust store contains the HALT CA (the
one deployment requirement, see certs.py). REDIRECT pulls the connection
into TerminatingProxy, which presents a leaf for the SNI name, reads the
request line, consults the policy, and either relays to the real upstream
or closes and kills.

Exit code 0 means every assertion held.
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from halt.intercept import (  # noqa: E402
    CertAuthority, NetnsConfig, NetnsEgress, PolicyGate, TerminatingProxy,
)
from halt.kill import LocalProcessBackend  # noqa: E402
from halt.policy import NetworkRule, Policy  # noqa: E402
from halt.sinks import LocalJsonlSink  # noqa: E402
from halt.supervisor import Supervisor  # noqa: E402

UPSTREAM_IP = "203.0.113.10"   # TEST-NET-3: the agent's chosen destination
UPSTREAM_NAME = "artifactory.internal"

AGENT = """
import json, socket, ssl, sys
cafile, ip, port, name, path = sys.argv[1:6]
ctx = ssl.create_default_context(cafile=cafile)
try:
    raw = socket.create_connection((ip, int(port)), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname=name)
    s.sendall(f"GET {path} HTTP/1.1\\r\\nHost: {name}\\r\\nConnection: close\\r\\n\\r\\n".encode())
    buf = b""
    while True:
        c = s.recv(4096)
        if not c: break
        buf += c
    print(json.dumps({"ok": True, "body": buf.decode("latin-1")}))
except Exception as e:
    print(json.dumps({"ok": False, "error": type(e).__name__}))
"""


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = f"upstream saw {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def fail(msg: str) -> None:
    print("LIVE FAIL:", msg)
    sys.exit(1)


def checked_run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        fail(f"{' '.join(cmd)} -> rc={r.returncode} stderr={r.stderr.strip()}")
    return r


def main() -> None:
    checked_run(["mount", "-t", "tmpfs", "tmpfs", "/run"])

    cfg = NetnsConfig(name="halt-live-tls")
    egress = NetnsEgress(cfg, run_command=checked_run)
    egress.create()

    # The "real" upstream lives in the host namespace at the IP the agent
    # will target. Root-in-userns may bind :443. A fresh netns has `lo`
    # DOWN (a real host wouldn't), so bring it up or local delivery to the
    # upstream silently times out — found by bisecting exactly that.
    checked_run(["ip", "link", "set", "lo", "up"])
    checked_run(["ip", "addr", "add", f"{UPSTREAM_IP}/32", "dev", "lo"])
    ca = CertAuthority("/run/halt-ca")
    leaf = ca.leaf_for(UPSTREAM_NAME)
    up = HTTPServer((UPSTREAM_IP, 443), _Upstream)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(leaf.cert_path, leaf.key_path)
    up.socket = sctx.wrap_socket(up.socket, server_side=True)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    policy = Policy(
        run_id="live-tls", org_id="acme",
        network_rules=(NetworkRule(host=UPSTREAM_NAME, port=443, path_prefix="/api/npm/"),),
    )
    sink = LocalJsonlSink("/run/halt-live-tls.jsonl")
    sup = Supervisor(LocalProcessBackend(), sink, run_id="live-tls")
    proxy = TerminatingProxy(
        decide=PolicyGate(policy, sup).decide, ca=ca,
        host=cfg.host_addr, port=0, upstream_cafile=ca.ca_cert_path,
    )
    proxy.start()
    if not egress.redirect_tcp_to(proxy.port):
        fail("redirect failed")

    def agent(path: str) -> dict:
        r = egress.exec_in_ns(
            sys.executable, "-c", AGENT, ca.ca_cert_path, UPSTREAM_IP, "443", UPSTREAM_NAME, path,
        )
        return json.loads(r.stdout)

    # --- allowed: relayed end to end, real TLS both sides ---
    ok = agent("/api/npm/lodash")
    if not ok["ok"] or "upstream saw /api/npm/lodash" not in ok["body"]:
        fail(f"allowed request did not relay: {ok}")
    if sup.killed:
        fail("allowed request killed the run")
    seen = proxy.seen[-1]
    if (seen.host, seen.ip, seen.port, seen.path, seen.tls, seen.redirected) != \
            (UPSTREAM_NAME, UPSTREAM_IP, 443, "/api/npm/lodash", True, True):
        fail(f"unexpected observation for allowed request: {seen}")

    # --- denied: same host, different path — the incident's shape ---
    bad = agent("/api/admin/tokens")
    if bad["ok"] and "upstream saw" in bad["body"]:
        fail(f"denied request reached upstream: {bad}")
    if not sup.killed or sup.cause is None:
        fail("wrong-path request did not kill")
    if sup.cause.evidence.get("path") != "/api/admin/tokens":
        fail(f"cause does not name the path: {sup.cause.evidence}")

    if proxy.callback_errors:
        fail(f"handler errors: {proxy.callback_errors}")

    events = sink.read_all()
    sev = [e.severity.value for e in events]
    if sev != ["info", "kill"]:
        fail(f"expected [info, kill] in sink, got {sev}")

    proxy.stop()
    up.shutdown()
    egress.destroy()
    print(json.dumps({"allowed": ok, "denied": bad, "severities": sev}))


if __name__ == "__main__":
    main()
