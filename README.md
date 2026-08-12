# HALT

A runtime circuit breaker for agent sandboxes.

## The problem

When a lab's agent starts doing something it shouldn't, the only stop
mechanisms that typically exist are manual: someone has to notice, someone
has to decide, someone has to go revoke a key or kill a VM. That gap —
detection, decision, and execution all mediated by a human, all in the
sandbox's own trust boundary — is what let a real 2026 incident (an OpenAI
eval agent escaping its sandbox via an unmonitored egress path, then
compromising Hugging Face's infrastructure) run for days before both sides
independently discovered it.

HALT is not a sandbox hardener. Its premise is that the container/VM
boundary is not where this kind of incident actually happens — the escape
used a *permitted* channel (an allowlisted host, wrong path) rather than
breaking the isolation primitive itself. So HALT assumes the boundary will
eventually leak and focuses on the layer isolation tech doesn't cover:
independent, low-latency monitoring of exactly what crosses the permitted
channels, with **pre-authorized kill authority** that acts automatically —
no human has to be the one who pulls the trigger.

## Design

- **Fuses are dumb.** `NetworkFuse`, `CredentialFuse`, `WatchdogFuse` do
  allowlist matching against a closed `Policy`, not behavior classification.
  No fuse tries to infer intent — that keeps them fast enough to run inline
  and simple enough to audit. This is a direct response to the incident
  shape: matching on host alone would have missed the actual escape, which
  used the same allowlisted host on a different path. `NetworkRule` matches
  host **and** port **and** path-prefix.
- **Kill authority lives outside the fuses**, in `Supervisor` /
  `execute_kill`. Fuses only ever emit `TripEvent`s; they never act. One
  audit surface for the one thing that matters.
- **Kill order is credentials first, always** — a still-running process
  with a live credential is a risk regardless of what happens next.
  Network-vs-process ordering after that is **backend-dependent**, not
  universal: `KillBackend.can_sever_network_before_terminate` tells
  `execute_kill()` (kill.py) which order a given backend needs. This
  isn't a hypothetical — it's a bug that was actually caught live: an
  earlier version of this always did network-then-process, which is
  provably wrong for Firecracker (see below).
- **Every observation is logged, trip or not**, via `Sink`, before the kill
  decision is made — so the forensic record survives even if the kill
  itself fails partway.
- **`TripEvent` is a portable, serializable record** (org/run id, fuse,
  severity, evidence) — not because cross-org signal sharing is built here,
  but so it isn't a rewrite later. `ExternalBroadcastSink` is an explicit
  `NotImplementedError` stub marking where that would plug in.

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
went out through a door that was standing open on purpose (an allowlisted
host, on the wrong path). Sentry doesn't ask "should this specific request
be going to this path on this host," it asks "is this syscall one I'm
willing to forward" — a categorically different, and honestly easier,
question. You can run gVisor *inside* a Firecracker microVM, stack every
isolation primitive available, and this project's threat model is
completely unmoved, because the exploited channel was never the syscall
boundary or the VM boundary — it was the one connection everyone agreed
the sandbox was allowed to make. Pick gVisor or Firecracker (or layer both)
for what they're actually good at. Don't mistake either one for having
solved this.

## What's real vs. stubbed

**Real and tested** (35 tests, `pytest tests/ -v`): the policy matcher, all
three fuses, the supervisor's kill-triggering and first-kill-wins logic
under concurrent trips, kill ordering, event serialization, the local
JSONL sink, and the pure logic of both `FirecrackerBackend` and
`GvisorBackend` (registration bookkeeping, unregistered-run handling,
credential-callback delegation, and the exact host commands each backend
issues — verified against injected fakes, not real infra).

**`GvisorBackend.terminate()` has also been verified against a real, live
`runsc` sandbox**, not just fakes: a `sleep 600` process was booted under
`runsc run -detach` in a minimal busybox rootfs, confirmed `running` via
`runsc list` (real PID, real OS process), then killed by calling
`GvisorBackend.terminate()` exactly as written, with only the `runsc`
binary path substituted in `run_command`. Afterward `runsc list` showed
`status: stopped, PID: -1` and the original PID was gone from `ps`. This is
the honest state of that verification, including two dead ends worth
recording because they'll bite the next person too:

1. The Ubuntu-packaged `runsc` (apt install runsc, version
   `0.0~20230807.0`) fails on `run -detach` even under `sudo`, with
   `Control auth failure: other UID = 65534, current UID = 0` followed by
   `broken pipe` while setting up the sandbox's loopback interface. Neither
   missing `uidmap`/`newuidmap` (it was present, setuid, with a valid
   `/etc/subuid` range) nor plain root access fixed it — this looks like a
   genuine bug/rough edge in that specific distro build, not a config
   problem on this machine. Installing the current upstream binary
   directly from `storage.googleapis.com/gvisor/releases/release/latest/`
   (per gvisor.dev's install docs) fixed it outright — that build reports
   itself as `release-20260810.0`.
2. Running fully rootless (no `sudo`) with the upstream binary still needs
   `--ignore-cgroups`, since real cgroup delegation for an unprivileged
   user requires host-side setup (`cgroup.subtree_control` writable by the
   user) this environment doesn't have configured. That's a reasonable
   thing to skip for a kill-logic smoke test; a production deployment
   running its own sandboxes would set up proper cgroup delegation rather
   than routinely disable it.

**`FirecrackerBackend` has been verified against a real, hardware-KVM-backed
microVM** — the invoking user was added to the `kvm` group
(`sudo usermod -aG kvm`), Firecracker v1.16.1 was downloaded directly from
its GitHub release (checksum-verified), and a genuine Ubuntu 24.04 guest
was booted using the official firecracker-ci kernel (`vmlinux-6.1.102`) and
squashfs rootfs (converted to a writable ext4 image), with a real host-side
tap device. The boot log shows a real KVM-detected kernel boot through to
an actual login prompt inside the guest. Both `terminate()` and
`sever_network()` were then called for real, not against fakes:

- `terminate()` — confirmed the `firecracker` host process was actually
  gone (`ps -p <pid>` before/after) after calling it.
- `sever_network()` — first call, **while the VM was still alive, failed**:
  `ip link set <tap> down` returned `Operation not permitted` when run
  unprivileged, and even with root, `ip tuntap del` failed with
  `ioctl(TUNSETIFF): Device or resource busy`, because the tap fd is held
  open by the running firecracker process for the VM's entire life. Only
  after `terminate()` killed the process did the same `ip` commands succeed
  and the tap device actually disappear (`ip link show` → "does not
  exist").

That busy-tap finding was a real correctness bug, not a footnote: the
original `execute_kill()` always ran network-severance before termination,
which is provably wrong for any backend whose network teardown requires the
process to already be dead. The fix — `can_sever_network_before_terminate`
on `KillBackend`, `False` on `FirecrackerBackend`, and `execute_kill()`
branching on it — is in `kill.py`, with a regression test
(`test_execute_kill_terminates_before_severing_network_when_backend_requires_it`
in `tests/test_kill.py`) that fails without the fix.

**Still not verified live**: `GvisorBackend.sever_network()` (the
veth-teardown path) — the runsc smoke test only exercised `terminate()`,
since that test container ran with `--network=none` and had no veth device
to tear down; testing that path for real needs a sandbox actually wired to
one. `ExternalBroadcastSink` and real cloud-IAM credential revocation are
also not implemented — both backends' `revoke_credential` deliberately
delegates to an injected callback rather than assume any particular
credential system.

## Usage

```python
from halt import Policy, NetworkRule, CredentialRule, Supervisor
from halt.fuses import NetworkFuse, CredentialFuse
from halt.kill import LocalProcessBackend
from halt.sinks import LocalJsonlSink

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

sup = Supervisor(LocalProcessBackend(), LocalJsonlSink("events.jsonl"), run_id="run-1")

net_fuse = NetworkFuse(policy)
if event := net_fuse.observe(host="artifactory.internal", port=443, path="/api/admin/tokens"):
    sup.report(event)  # kills the run, revokes credentials, logs the cause
```

## Running tests

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -v
```
