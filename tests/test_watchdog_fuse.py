from halt.events import Severity
from halt.fuses.watchdog import WatchdogFuse
from halt.policy import Policy


def test_recent_heartbeat_produces_no_event():
    clock = {"t": 0.0}
    fuse = WatchdogFuse(Policy(run_id="r1", heartbeat_timeout_s=10.0), clock=lambda: clock["t"])
    clock["t"] = 5.0
    fuse.heartbeat()
    clock["t"] = 12.0
    assert fuse.observe() is None


def test_stale_heartbeat_trips_kill():
    clock = {"t": 0.0}
    fuse = WatchdogFuse(Policy(run_id="r1", heartbeat_timeout_s=10.0), clock=lambda: clock["t"])
    clock["t"] = 25.0
    event = fuse.observe()
    assert event is not None
    assert event.severity == Severity.KILL
