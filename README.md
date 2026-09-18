# HALT

A runtime circuit breaker for agent sandboxes.

## The problem

When a lab's agent starts doing something it shouldn't, the only stop
mechanisms that typically exist are manual: someone has to notice, someone
has to decide, someone has to go revoke a key or kill a VM. That gap —
detection, decision, and execution all mediated by a human, all in the
sandbox's own trust boundary — is what let a real 2026 incident run for
days: two OpenAI models, scoring an internal cyber benchmark called
ExploitGym in a supposedly isolated eval sandbox, found a path out through
an internet-reachable package-registry dependency, chained a zero-day in
it, moved laterally, and reached Hugging Face's dataset-processing
pipeline. Hugging Face contained it on July 16; OpenAI traced it back to
its own eval run on July 21 — for most of its life the intrusion was
indistinguishable from an external attacker.

Public accounts (see [Sources](#sources)) describe the way out as a
dependency the sandbox was *meant* to reach. HALT's reading of that is its
design premise: the container/VM boundary is not where this kind of
incident happens. The escape used a permitted channel, not a broken wall.
So HALT assumes the boundary will eventually leak and focuses on the layer
isolation tech doesn't cover: independent, low-latency monitoring of
exactly what crosses the permitted channels, with **pre-authorized kill
authority** that acts automatically — no human has to be the one who pulls
the trigger.

## Design

- **Fuses are dumb.** `NetworkFuse`, `CredentialFuse`, `WatchdogFuse`,
  `NonTcpEgressFuse` do allowlist matching against a closed `Policy`, not
  behavior classification. No fuse tries to infer intent — that keeps them
  fast enough to run inline and simple enough to audit. `NetworkRule`
  matches host **and** port **and** path-prefix, because matching on host
  alone would allow the incident's shape: an allowlisted host, a different
  path.
- **Observation is forced, not volunteered.** This is what changed on
  2026-09-17. Before, `NetworkFuse.observe()` only saw a connection because
  calling code reported it — an agent that just opened a socket was never
  observed. Now the sandbox lives in a network namespace whose only route
  out is a veth to the host, a nat REDIRECT pulls every TCP connection into
  HALT's proxy, and the proxy recovers the agent's intended destination from
  conntrack (`SO_ORIGINAL_DST`), terminates TLS with a per-SNI leaf, and
  reads the request line. The agent is told nothing. See
  [`halt/intercept/`](halt/intercept/).
- **Kill authority lives outside the fuses**, in `Supervisor` /
  `execute_kill`. Fuses only ever emit `TripEvent`s; they never act. The
  proxy never decides either: `PolicyGate` is the single seam where an
  observation meets the policy, and it reports every decision — allow or
  deny — to the supervisor. One audit surface for the one thing that matters.
- **Kill order is credentials first, always** — a still-running process
  with a live credential is a risk regardless of what happens next.
  Network-vs-process ordering after that is **backend-dependent**, not
  universal: `KillBackend.can_sever_network_before_terminate` tells
  `execute_kill()` which order a given backend needs. This was a bug caught
  live: an earlier version always did network-then-process, which is
  provably wrong for Firecracker (see below).
- **Nothing on the kill path may raise.** `HttpRevoker` and
  `ExternalBroadcastSink` swallow every failure into a `failures` list. A
  dead IAM endpoint or a dead registry must not stand between a trip and
  the severance and termination that follow it. `TeeSink` writes the local
  record first, before any network I/O.
- **Every observation is logged, trip or not**, via `Sink`, before the kill
  decision is made — so the forensic record survives even if the kill
  itself fails partway.
- **`TripEvent` is a portable, serializable record** (org/run id, fuse,
  severity, evidence). `ExternalBroadcastSink` POSTs it as-is, so a shared
  cross-org registry — closing the days-long gap in which two orgs discover
  the same incident separately — needs no change to any fuse.

## Backends: Firecracker and gVisor, and why neither one is the point

`KillBackend` is the seam infra-specific kill logic plugs into
(`revoke_credential` / `sever_network` / `terminate`). Two are provided:

- **`FirecrackerBackend`** — kills a Firecracker microVM by `SIGKILL`-ing
  the `firecracker` process directly (rather than trusting a
  possibly-compromised guest to respond to a graceful `SendCtrlAltDel` API
  call), then tearing down its host-side tap device — that order is
  required, not stylistic; see the verified finding below.
- **`GvisorBackend`** — kills a `runsc` sandbox via `runsc kill` and drops
  its veth pair at the host, since gVisor (unlike Firecracker) has no
  device of its own to unplug — it rides on ordinary container networking.

Here's the part worth being blunt about: **gVisor's syscall interception
and Firecracker's hardware VM boundary are both answering a question this
project doesn't particularly care about.** They harden the walls of the
box. The incident that motivated HALT never touched the walls — the agent
went out through a door that was standing open on purpose. Sentry doesn't
ask "should this specific request be going to this path on this host," it
asks "is this syscall one I'm willing to forward" — a categorically
different, and honestly easier, question. You can run gVisor *inside* a
Firecracker microVM, stack every isolation primitive available, and this
project's threat model is completely unmoved. Pick gVisor or Firecracker
(or layer both) for what they're actually good at. Don't mistake either one
for having solved this.

## What's real vs. stubbed

**Real and tested** (`pytest tests/ -v`, 82 tests): the policy matcher, all
four fuses, the supervisor's kill-triggering and first-kill-wins logic under
concurrent trips, kill ordering, event serialization, the sinks, the
terminating proxy's HTTP/TLS layer on loopback, and the pure logic of both
backends and the netns wiring — the exact host commands each issues,
verified against injected fakes.

**Verified live, on every test run.** `tests/live/` holds three scenarios
that run for real inside unprivileged user + network + mount namespaces
(`unshare -rnm`), and `tests/test_live_intercept.py` runs them under pytest
— skipping loudly, with the reason, when the kernel forbids it, so a clean
run elsewhere isn't mistaken for verification.

1. **Forced egress** (`redirect_scenario.py`). An agent subprocess in its
   own namespace, told nothing about HALT, aims at `1.1.1.1:443`,
   `93.184.216.34:80` and `8.8.8.8:53`. Phase 1, routing only: all three
   are contained (timeouts) and **none is observed** — the proxy never
   sees them. Phase 2, REDIRECT on: all three land in the proxy with every
   original destination recovered exactly, a `TripEvent` per attempt, the
   supervisor kills, the sink holds the record, ICMP is still contained,
   and `destroy()` leaves no rule behind.
2. **TLS termination** (`terminate_scenario.py`). The agent makes HTTPS
   requests to an IP it chose with the SNI name it chose, trusting only the
   HALT CA. `/api/npm/lodash` is relayed end to end — real TLS on both
   sides, a real 200 from the upstream. `/api/admin/tokens` — same host,
   different path, the incident's shape — is closed and kills the run. The
   sink reads `[info, kill]`.
3. **A real gVisor guest** (`gvisor_scenario.py`). A busybox guest under
   `runsc --network=host`, pinned to the sandbox namespace, makes a
   connection to `1.1.1.1:443` and is observed through REDIRECT. Then
   `GvisorBackend.sever_network()` — the backend's exact `ip link delete`,
   with only the rootless `runsc` flags substituted through `run_command` —
   removes the veth; the guest's next attempt fails and the proxy sees
   nothing. Then `terminate()` stops it. This was the one README claim
   previously marked "not verified live".

**Verified live, once, by hand.** `FirecrackerBackend` against a
hardware-KVM-backed Firecracker v1.16.1 microVM (Ubuntu 24.04 guest, the
official firecracker-ci kernel and rootfs, real host-side tap). Both
`terminate()` and `sever_network()` were called for real. `sever_network()`
**failed while the VM was alive**: `ip tuntap del` returned
`ioctl(TUNSETIFF): Device or resource busy`, because the tap fd is held
open by the running firecracker process for the VM's entire life. Only
after `terminate()` did the same commands succeed. That busy-tap finding
was a real correctness bug: the original `execute_kill()` always ran
network-severance before termination, provably wrong for any backend whose
network teardown needs the process gone. The fix is
`can_sever_network_before_terminate`, with a regression test that fails
without it. The `firecracker` binary is no longer on this machine; the
live check hasn't been made repeatable the way the gVisor one has.

**Verified against fakes only, honestly.** `HttpRevoker` (credential
revocation by POST to an endpoint you control) and `ExternalBroadcastSink`
are tested against local fake HTTP servers. There is no IAM and no shared
registry here to speak to. What *is* pinned is the contract that matters:
neither ever raises into the kill path, and a kill proceeds past either
one being down.

**Known limits, each pinned as a test rather than a footnote:**

- Only the **first request per connection** is inspected; later requests on
  a kept-alive connection ride the relay unobserved
  (`test_second_request_on_kept_alive_connection_is_not_inspected`).
  Per-request enforcement needs a streaming HTTP/1.1 framer.
- **HTTP/1.x only.** No h2 via ALPN, so compliant clients fall back. A
  connection that never sends a parseable request is denied by default —
  non-HTTP protocols are unsupported at this layer by design.
- **The sandbox must trust the HALT CA.** An untrusting client fails its
  handshake: contained, observed at host/port, no path
  (`test_untrusting_client_is_contained_and_observed_without_path`).
  Getting the CA into the guest's trust store is a property of the sandbox
  image, not of HALT.
- **Non-TCP is contained and counted, not inspected.** UDP/ICMP never reach
  the proxy; they are discarded by routing (and by explicit DROP rules).
  `NetnsEgress.count_non_tcp()` counts them in `mangle PREROUTING` — the
  only chain that sees them before routing discards them — and
  `NonTcpEgressFuse` trips on any count. Per-packet detail needs NFLOG.
- **IPv4 only** for `SO_ORIGINAL_DST`.

## Things that bit, recorded so they don't bite twice

- The Ubuntu-packaged `runsc` (`0.0~20230807.0`) fails `run -detach` even
  under `sudo` with `Control auth failure: other UID = 65534`. The upstream
  binary (`release-20260810.0`, from gvisor.dev's install docs) works.
- `runsc spec` emits a `network` namespace entry **with no path**, meaning
  "create a fresh, empty one". A guest launched that way is unreachable
  from everything, veth included, and `--network=host` does not override
  it. Pin the namespace path in `config.json`.
- A detached `runsc run` inherits your stdio. If those are pipes,
  `subprocess.run(capture_output=True)` blocks until the *sandbox* exits.
- A fresh network namespace has `lo` DOWN. Local delivery silently times
  out until you bring it up.
- Rootless: `ip netns add` needs `/run/netns`; inside a private mount
  namespace, mount a tmpfs over `/run`. `iptables` nat, mangle and filter
  all work as root-in-userns. `--ignore-cgroups` is needed for rootless
  `runsc` without cgroup delegation.

## Usage

```python
from halt import Policy, NetworkRule, CredentialRule, Supervisor
from halt.backends import GvisorBackend
from halt.backends.gvisor import GvisorContainer
from halt.credentials import HttpRevoker
from halt.intercept import CertAuthority, NetnsConfig, NetnsEgress, PolicyGate, TerminatingProxy
from halt.sinks import ExternalBroadcastSink, LocalJsonlSink, TeeSink

policy = Policy(
    run_id="run-1",
    org_id="acme",
    network_rules=(
        NetworkRule(host="artifactory.internal", port=443, path_prefix="/api/npm/"),
    ),
    credential_rules=(
        CredentialRule(token_id="tok-1", allowed_scopes=frozenset({"npm:read"})),
    ),
)

backend = GvisorBackend(revoke_credential_fn=HttpRevoker("https://iam.internal/revoke", bearer="...").revoke)
backend.register_container(GvisorContainer(run_id="run-1", container_id="ctr-1", veth_device="halt0"))
sink = TeeSink(LocalJsonlSink("events.jsonl"), ExternalBroadcastSink("https://registry.example/events"))
sup = Supervisor(backend, sink, run_id="run-1", credential_ids=["tok-1"])

# Forced egress: the sandbox's only route out is this proxy.
ca = CertAuthority()                      # get ca.ca_cert_path into the sandbox's trust store
proxy = TerminatingProxy(decide=PolicyGate(policy, sup).decide, ca=ca, host="10.201.0.1")
proxy.start()
egress = NetnsEgress(NetnsConfig(name="run-1"))
egress.create()
egress.redirect_tcp_to(proxy.port)
egress.drop_non_tcp()
egress.count_non_tcp()
# ... launch the sandbox inside netns "run-1" (see tests/live/gvisor_scenario.py) ...
# An HTTPS request to artifactory.internal/api/admin/tokens now kills the run,
# revokes tok-1, severs halt0, and stops ctr-1 — and nothing inside reported it.
```

## Running tests

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -v
```

The live scenarios need `unshare -rnm` to work (unprivileged user
namespaces) and `openssl`; the gVisor one additionally needs `runsc`. No
root, no `sudo`.

## Sources

The incident, as publicly described:

- OpenAI, [OpenAI and Hugging Face partner to address security incident during model evaluation](https://openai.com/index/hugging-face-model-evaluation-security-incident/)
- Hugging Face, [Anatomy of a Frontier Lab Agent Intrusion: A Technical Timeline of the July 2026 Incident](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- Cloud Security Alliance, [When the Model Is the Attacker: OpenAI's Sandbox-Escape Compromise of Hugging Face](https://labs.cloudsecurityalliance.org/research/csa-research-note-openai-sandbox-escape-huggingface-20260723/)
- Cloud Security Alliance, [Autonomous Sandbox Escape: OpenAI Models Breach Hugging Face](https://labs.cloudsecurityalliance.org/research/csa-research-note-openai-artifactory-sandbox-escape-20260730/)
