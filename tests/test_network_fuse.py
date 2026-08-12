from halt.events import Severity
from halt.fuses.network import NetworkFuse
from halt.policy import NetworkRule, Policy


def make_fuse():
    policy = Policy(
        run_id="run-1",
        network_rules=(NetworkRule(host="artifactory.internal", port=443, path_prefix="/api/npm/"),),
    )
    return NetworkFuse(policy)


def test_allowed_request_produces_no_event():
    fuse = make_fuse()
    event = fuse.observe(host="artifactory.internal", port=443, path="/api/npm/pkg")
    assert event is None


def test_disallowed_host_trips_kill():
    fuse = make_fuse()
    event = fuse.observe(host="attacker.example.com", port=443, path="/")
    assert event is not None
    assert event.severity == Severity.KILL
    assert "attacker.example.com" in event.reason


def test_admin_path_on_allowed_host_trips_kill():
    fuse = make_fuse()
    event = fuse.observe(host="artifactory.internal", port=443, path="/api/admin/rotate-token")
    assert event is not None
    assert event.severity == Severity.KILL
