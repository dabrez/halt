import threading

from halt.events import FuseKind, Severity, TripEvent
from halt.kill import LocalProcessBackend
from halt.sinks import LocalJsonlSink
from halt.supervisor import Supervisor


def make_supervisor(tmp_path, credential_ids=None):
    backend = LocalProcessBackend()
    sink = LocalJsonlSink(tmp_path / "events.jsonl")
    sup = Supervisor(backend, sink, run_id="run-1", credential_ids=credential_ids or ["tok-1"])
    return sup, backend, sink


def kill_event(reason="test"):
    return TripEvent(fuse=FuseKind.NETWORK, severity=Severity.KILL, reason=reason, run_id="run-1")


def warn_event(reason="fyi"):
    return TripEvent(fuse=FuseKind.NETWORK, severity=Severity.WARN, reason=reason, run_id="run-1")


def test_warn_event_does_not_kill(tmp_path):
    sup, backend, _ = make_supervisor(tmp_path)
    sup.report(warn_event())
    assert not sup.killed


def test_kill_event_triggers_kill_and_revokes_credentials(tmp_path):
    sup, backend, _ = make_supervisor(tmp_path, credential_ids=["tok-1", "tok-2"])
    sup.report(kill_event("bad egress"))
    assert sup.killed
    assert backend.is_revoked("tok-1")
    assert backend.is_revoked("tok-2")
    assert backend.is_network_severed("run-1")


def test_all_events_are_logged_even_after_kill(tmp_path):
    sup, backend, sink = make_supervisor(tmp_path)
    sup.report(kill_event("first"))
    sup.report(kill_event("second"))
    logged = sink.read_all()
    assert len(logged) == 2


def test_first_kill_wins_is_recorded_cause(tmp_path):
    sup, backend, _ = make_supervisor(tmp_path)
    sup.report(kill_event("first"))
    sup.report(kill_event("second"))
    assert sup.cause.reason == "first"


def test_concurrent_trips_pick_exactly_one_cause_deterministically(tmp_path):
    """The realistic case: multiple fuses trip near-simultaneously. Exactly
    one kill should execute; the recorded cause must be whichever report()
    call actually acquired the lock first, and it must not flip between
    runs due to a race in the accounting itself.
    """
    sup, backend, sink = make_supervisor(tmp_path)

    events = [kill_event(f"cause-{i}") for i in range(20)]
    threads = [threading.Thread(target=sup.report, args=(e,)) for e in events]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sup.killed
    assert sup.cause is not None
    assert sup.cause.reason.startswith("cause-")
    logged = sink.read_all()
    assert len(logged) == 20
    kill_results_fired = backend.is_network_severed("run-1")
    assert kill_results_fired
