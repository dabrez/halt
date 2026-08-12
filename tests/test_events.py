from halt.events import FuseKind, Severity, TripEvent


def test_roundtrip_serialization():
    e = TripEvent(
        fuse=FuseKind.CREDENTIAL,
        severity=Severity.KILL,
        reason="scope violation",
        evidence={"token_id": "tok-1"},
        org_id="acme",
        run_id="run-1",
    )
    d = e.to_dict()
    e2 = TripEvent.from_dict(d)
    assert e2 == e


def test_event_id_and_ts_are_populated_by_default():
    e = TripEvent(fuse=FuseKind.NETWORK, severity=Severity.WARN, reason="x")
    assert e.event_id
    assert e.ts > 0
