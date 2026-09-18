# HALT roadmap

Written 2026-09-17. This file exists so the *reasoning* behind the current
milestone survives a lost session, not just the code.

## Where the project actually stands

**Built and tested (35 tests):** policy matcher (host + port + path-prefix),
all three fuses, supervisor first-kill-wins under concurrent trips, kill
ordering incl. the backend-dependent branch, event serialization, local JSONL
sink, and the pure logic of both backends against injected fakes.

**Verified against real infra:** `GvisorBackend.terminate()` (live runsc
sandbox) and both `FirecrackerBackend.terminate()` / `sever_network()` (live
KVM microVM — this is where the busy-tap ordering bug was caught).

**The gap this roadmap was about (closed 2026-09-18):** HALT was a *policy
engine*, not an *enforcement point*. `NetworkFuse.observe()` only ever saw a
connection because the calling code volunteered it. An agent that opened a
raw socket was never observed at all. Default-deny was therefore only
default-deny over observations we happened to be handed. As of the work
below, observation is forced: netns + REDIRECT + terminating proxy, verified
live on every test run, including from inside a real gVisor guest.

Nothing in `halt/` isolates anything. Isolation is Firecracker's and gVisor's;
HALT observes permitted channels and kills. That division is intentional and
documented in the README — the gap is that the "observes" half is advisory.

## Why a proxy and not eBPF/netfilter

Decided 2026-09-17. This is the load-bearing design choice, so it's recorded
rather than left implicit:

- A netfilter/eBPF hook sees *every* packet regardless of agent cooperation —
  a genuinely stronger enforcement point — but at L3/L4 it yields host and
  port and **no path**.
- The motivating incident is *same allowlisted host, different path*.
  `NetworkRule` matches on host **and** port **and** path-prefix precisely
  because host-only matching would have missed it.
- So the packet-level approach, despite being the stronger primitive, is
  structurally blind to the exact case HALT exists to catch.

A terminating proxy sees host + port + path, which is what the policy already
matches on. **Longer term the two are complementary** — netfilter as the
backstop that guarantees nothing escapes the netns, proxy for path
visibility. Proxy first, because it's the one that can answer the question.

## Milestone 1 (done): prove forced egress

**Goal:** a process inside a runsc sandbox tries to reach *anything*, and the
connection is seen by HALT — not because the process reported it, but because
it had no other route.

**Deliberately excluded:** TLS termination, path extraction, real policy
consultation, allowing any traffic at all. The first version denies
everything and parses nothing.

**Why so small:** the risky assumption is not "can we parse HTTP." It is *can
we actually force all egress through this thing, such that a raw socket has
nowhere else to go*. That claim either holds or it doesn't, and everything
else is incremental work on top of it. A simplification that defers testing
it (e.g. a plaintext-only proxy) would teach us the easy part and postpone
the hard one.

Precedent: the busy-tap bug was found by running two real calls against one
real VM, not by designing a complete system. Same approach here.

**Done when:** a process in the sandbox attempts egress, the attempt reaches
a HALT fuse, a TripEvent is produced, and the supervisor kills the run — with
the routing verified to be the reason the attempt was visible.

**Expected failure modes worth recording either way:** runsc's networking may
make full egress capture awkward, or some traffic may leave the netns in a
way we don't expect. That is a finding, not a failure — same category as the
busy-tap discovery, and it belongs in the README regardless of outcome.

### STATUS: done, with a finding (2026-09-17)

Built: `halt/intercept/proxy.py` (`DenyAllProxy`) and `halt/intercept/netns.py`
(`NetnsEgress`). Suite went 35 → 51 tests, all passing.

Verified live in a real namespace, not against fakes:

- **Containment holds.** Identical code that reaches `1.1.1.1:53` from the
  host gets `ENETUNREACH` inside a namespace with no route. With the veth and
  a single default route, arbitrary external destinations (`1.1.1.1:443`,
  `93.184.216.34:80`) time out — nothing escaped.
- **Full loop works.** An agent subprocess that was told nothing about HALT
  connected, was denied (`recv` → `b''`), and the proxy observed the attempt
  *because of the route*, producing a TripEvent that killed the run and
  persisted to the sink.
- **Routing shape confirmed.** Exactly one default route, no second exit.

**The finding — visibility ≠ containment.** An agent aiming at an arbitrary
external address is contained but **not observed**: the connection dies at the
veth without reaching the proxy's accept loop. Only traffic addressed *to the
proxy* is seen. So milestone 1 proved the weaker half of its goal. Recorded as
`test_proxy_does_not_observe_traffic_aimed_elsewhere` so it cannot quietly be
forgotten, and it is why `InterceptedConnection.path` is None rather than "/".

This makes the REDIRECT work (below) load-bearing rather than a refinement:
until it lands, **do not describe HALT as seeing all egress.**

Rootless caveat: `sudo` was unavailable (password-gated), so live testing ran
under `unshare -rn`. The `ip netns`-based `NetnsEgress` command sequence is
therefore fake-verified only; the equivalent shape was exercised rootlessly.

## Backlog — all six items closed 2026-09-17/18

What each one turned out to need, for the record:

1. **iptables REDIRECT + SO_ORIGINAL_DST** — DONE. Did *not* need root:
   `iptables -t nat` works as root-in-userns, so the live test runs under
   `unshare -rnm`. `ip netns add` needed a tmpfs over `/run`. Verified live
   on every pytest run (`tests/live/redirect_scenario.py`).
2. **TLS termination + path extraction** — DONE. `TerminatingProxy` +
   `CertAuthority` (openssl CLI, no new deps) + `PolicyGate`. Verified live:
   the incident's shape (allowlisted host, wrong path) kills through real
   TLS on both sides. Known limits pinned as tests: first request per
   connection only; HTTP/1.x only; sandbox must trust the CA.
3. **netfilter backstop** — DONE as far as it can be without NFLOG.
   `drop_non_tcp()` makes non-TCP containment explicit; `count_non_tcp()`
   counts non-TCP attempts in `mangle PREROUTING` (the only chain that sees
   them before routing discards them — the DROP counters read 0 live, and
   that's why); `NonTcpEgressFuse` trips on any count. eBPF was not needed:
   REDIRECT already captures every TCP connection regardless of what the
   agent does, and non-TCP has no route. Per-packet detail for non-TCP
   remains the one open sub-item — see below.
4. **`GvisorBackend.sever_network()` live** — DONE, repeatable
   (`tests/live/gvisor_scenario.py`). Two things bit on the way and are in
   the README: `runsc spec`'s pathless network namespace, and a detached
   `runsc run` holding captured pipes open.
5. **Credential revocation** — DONE as `HttpRevoker`, verified against a
   local fake only (no IAM here). The kill-path contract — never raise,
   kill continues past a failed revoke — is what's actually pinned.
6. **`ExternalBroadcastSink`** — DONE, plus `TeeSink`. Same status as (5):
   fake endpoint, contract pinned (a dead registry doesn't block a kill).

## Still open

- **Per-request enforcement on kept-alive connections** — needs a streaming
  HTTP/1.1 framer on the client→upstream direction. Until then, granularity
  is per-connection, and the test that pins this is the reminder.
- **Non-TCP per-packet visibility** — NFLOG + a netlink reader. Counting is
  in place; detail (destination, payload) is not.
- **Firecracker live check made repeatable** — the gVisor scenario is now
  re-verified every run; Firecracker's was a one-off by hand and the binary
  is gone. Bringing it back means re-downloading firecracker + the
  firecracker-ci kernel/rootfs and needing `/dev/kvm` (user is in `kvm`).
- **HTTP/2** — not offered via ALPN; prior-knowledge h2 is denied as
  unparseable. Fine as a policy; worth a decision if a workload needs it.

## Incident citation — resolved

The two names refer to the same event. ExploitGym is the internal OpenAI
cyber-capability benchmark the models were scoring when they escaped;
OpenAI disclosed on July 21, 2026 (the commit-message date), Hugging Face
had contained it on July 16. Sources are now in the README. One nuance
kept honest there: public accounts describe the path out as an
internet-reachable package-registry dependency inside the "isolated"
sandbox, with a zero-day chained from it; "a permitted channel, not a
broken wall" is HALT's reading of that, stated as such.

## Environment notes (2026-09-17)

- `runsc release-20260810.0` at `/usr/local/bin/runsc` — the upstream build.
  The Ubuntu-packaged one (`0.0~20230807.0`) is broken for `run -detach`; see
  README for that dead end.
- `firecracker` binary is **absent** — it was installed ad hoc for the
  original verification. Re-verifying that backend means re-downloading it.
- User is in `kvm` and `docker` groups. `ip`, `iptables`, `nft`, `tcpdump`
  present. `mitmdump` absent.
- Unprivileged netns creation works (`unshare -rn` succeeds), so milestone 1
  does not require root.
- Rootless runsc needs `--ignore-cgroups` on this box (no cgroup delegation).
