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

**The gap this roadmap is about:** HALT is currently a *policy engine*, not an
*enforcement point*. `NetworkFuse.observe()` only ever sees a connection
because the calling code volunteered it. An agent that opens a raw socket is
never observed at all. Default-deny is therefore only default-deny over
observations we happen to be handed.

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

## Milestone 1 (current): prove forced egress

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

## Backlog (after milestone 1)

Ordered roughly by dependency, not priority.

1. **iptables REDIRECT + SO_ORIGINAL_DST** — promoted to first by milestone
   1's finding. Pulls arbitrary destinations into the proxy and recovers the
   *intended* host/port, which is what makes observation match containment.
   Without it the proxy only sees traffic already addressed to it. Needs root
   (the `nat` table), so it also needs a way to run privileged tests here.
2. **TLS termination + path extraction in the proxy** — turns milestone 1's
   deny-everything into real `NetworkRule` matching on host/port/path. Depends
   on (1): there is no point extracting a path from a connection the proxy
   never receives.
3. **netfilter/eBPF backstop** — guarantees nothing bypasses the proxy, incl.
   raw sockets and non-HTTP protocols. Complements rather than replaces (2).
4. **`GvisorBackend.sever_network()` live verification** — the one remaining
   "not verified live" claim in the README. Needs a sandbox actually wired to
   a veth pair; the previous smoke test ran `--network=none` and so had no
   device to tear down. `runsc release-20260810.0` is installed and
   unprivileged netns works, so this is testable on this machine.
5. **Real credential revocation** — `revoke_credential` is an injected
   callback in both backends, so "credentials first, always" currently has
   ordering logic with nothing behind it. Blocked on a real IAM/token service;
   would otherwise land as tested-against-fakes only.
6. **`ExternalBroadcastSink`** — deliberate `NotImplementedError` stub for
   cross-org signal sharing. `TripEvent` is already serializable so this isn't
   a rewrite, just unbuilt.

## Open question: the incident citation

The README attributes the project's motivation to a 2026 incident (an OpenAI
eval agent escaping its sandbox via an unmonitored egress path, then
compromising Hugging Face infrastructure). The source files instead call this
"the ExploitGym incident" — `policy.py`, `kill.py`, `network.py`,
`watchdog.py`, `gvisor.py`.

The two names don't obviously refer to the same thing, and the claim is
uncorroborated here. Since the path-matching design is justified almost
entirely by this incident's shape, the naming should be reconciled and a
citation pinned before the README goes anywhere public — a design doc leaning
this hard on one incident is weakened if a reader can't check it.

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
