import subprocess

from halt.events import Severity
from halt.fuses import NonTcpEgressFuse
from halt.intercept.netns import NetnsConfig, NetnsEgress, _parse_non_tcp_counter
from halt.policy import Policy

# Real `iptables -t mangle -L PREROUTING -v -n -x` output from the live run:
# a target-less `! -p tcp` rule shows prot as `!6` and no target column.
LISTING = """\
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
       0        0            17   --  halt0  *       0.0.0.0/0            0.0.0.0/0
       2      168            1    --  halt0  *       0.0.0.0/0            0.0.0.0/0
       2      168           !6    --  halt0  *       0.0.0.0/0            0.0.0.0/0
       9      900           !6    --  other0 *       0.0.0.0/0            0.0.0.0/0
"""


def test_counter_parser_picks_only_our_interfaces_not_tcp_rule():
    assert _parse_non_tcp_counter(LISTING, "halt0") == 2
    assert _parse_non_tcp_counter(LISTING, "other0") == 9
    assert _parse_non_tcp_counter(LISTING, "nope0") == 0
    assert _parse_non_tcp_counter("", "halt0") == 0


def test_count_non_tcp_adds_mangle_prerouting_rule_and_reads_it():
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        out = LISTING if "-L" in cmd else ""
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=out)

    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=fake_run)
    assert egress.count_non_tcp() is True
    assert calls[-1] == ["iptables", "-t", "mangle", "-A", "PREROUTING", "-i", "halt0", "!", "-p", "tcp"]
    assert egress.non_tcp_packets() == 2
    assert calls[-1] == ["iptables", "-t", "mangle", "-L", "PREROUTING", "-v", "-n", "-x"]


def test_counter_rule_is_removed_on_destroy():
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="")

    egress = NetnsEgress(NetnsConfig(name="ns"), run_command=fake_run)
    egress.count_non_tcp()
    egress.destroy()
    assert ["iptables", "-t", "mangle", "-D", "PREROUTING", "-i", "halt0", "!", "-p", "tcp"] in calls


def test_fuse_is_quiet_at_zero_and_trips_on_any_packet():
    policy = Policy(run_id="r", org_id="o")
    count = {"n": 0}
    fuse = NonTcpEgressFuse(policy, lambda: count["n"])

    assert fuse.observe() is None
    count["n"] = 1
    ev = fuse.observe()
    assert ev is not None and ev.severity is Severity.KILL
    assert ev.evidence == {"non_tcp_packets": 1}
    assert (ev.run_id, ev.org_id) == ("r", "o")
