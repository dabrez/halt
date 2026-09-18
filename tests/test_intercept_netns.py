import subprocess

from halt.intercept.netns import NetnsConfig, NetnsEgress


def recording_run():
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0)

    return calls, fake_run


def test_config_builds_point_to_point_cidrs():
    c = NetnsConfig(name="halt-run-1")
    assert c.host_cidr == "10.201.0.1/30"
    assert c.sandbox_cidr == "10.201.0.2/30"


def test_create_issues_expected_command_sequence():
    calls, fake_run = recording_run()
    NetnsEgress(NetnsConfig(name="halt-run-1"), run_command=fake_run).create()

    assert calls == [
        ["ip", "netns", "add", "halt-run-1"],
        ["ip", "link", "add", "halt0", "type", "veth", "peer", "name", "halt1"],
        ["ip", "link", "set", "halt1", "netns", "halt-run-1"],
        ["ip", "addr", "add", "10.201.0.1/30", "dev", "halt0"],
        ["ip", "link", "set", "halt0", "up"],
        ["ip", "netns", "exec", "halt-run-1", "ip", "link", "set", "lo", "up"],
        ["ip", "netns", "exec", "halt-run-1", "ip", "addr", "add", "10.201.0.2/30", "dev", "halt1"],
        ["ip", "netns", "exec", "halt-run-1", "ip", "link", "set", "halt1", "up"],
        ["ip", "netns", "exec", "halt-run-1", "ip", "route", "add", "default", "via", "10.201.0.1"],
    ]


def test_peer_moved_into_namespace_before_being_addressed():
    """Addressing the sandbox interface before moving it would configure it
    in the wrong namespace — ordering here is correctness, not style.
    """
    calls, fake_run = recording_run()
    NetnsEgress(NetnsConfig(name="halt-run-1"), run_command=fake_run).create()

    move = calls.index(["ip", "link", "set", "halt1", "netns", "halt-run-1"])
    addr = calls.index(
        ["ip", "netns", "exec", "halt-run-1", "ip", "addr", "add", "10.201.0.2/30", "dev", "halt1"]
    )
    assert move < addr


def test_exactly_one_default_route_is_added():
    """The forced-egress claim rests on there being no second way out."""
    calls, fake_run = recording_run()
    NetnsEgress(NetnsConfig(name="halt-run-1"), run_command=fake_run).create()

    routes = [c for c in calls if "route" in c]
    assert len(routes) == 1
    assert routes[0][-3:] == ["default", "via", "10.201.0.1"]


def test_destroy_removes_namespace_and_host_link():
    calls, fake_run = recording_run()
    NetnsEgress(NetnsConfig(name="halt-run-1"), run_command=fake_run).destroy()

    assert calls == [
        ["ip", "netns", "del", "halt-run-1"],
        ["ip", "link", "del", "halt0"],
    ]


def test_context_manager_creates_then_destroys():
    calls, fake_run = recording_run()
    with NetnsEgress(NetnsConfig(name="halt-run-1"), run_command=fake_run):
        pass

    assert calls[0] == ["ip", "netns", "add", "halt-run-1"]
    assert calls[-1] == ["ip", "link", "del", "halt0"]


def test_custom_config_is_respected():
    calls, fake_run = recording_run()
    cfg = NetnsConfig(
        name="ns2", host_if="a0", sandbox_if="b0",
        host_addr="192.168.9.1", sandbox_addr="192.168.9.2",
    )
    NetnsEgress(cfg, run_command=fake_run).create()

    assert ["ip", "link", "add", "a0", "type", "veth", "peer", "name", "b0"] in calls
    assert ["ip", "netns", "exec", "ns2", "ip", "route", "add", "default", "via", "192.168.9.1"] in calls
