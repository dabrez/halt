from halt.events import Severity
from halt.fuses.credential import CredentialFuse
from halt.policy import CredentialRule, Policy


def make_fuse():
    policy = Policy(
        run_id="run-1",
        credential_rules=(CredentialRule(token_id="tok-1", allowed_scopes=frozenset({"npm:read"})),),
    )
    return CredentialFuse(policy)


def test_in_scope_use_produces_no_event():
    fuse = make_fuse()
    assert fuse.observe(token_id="tok-1", requested_scope="npm:read") is None


def test_out_of_scope_use_trips_kill():
    """Regression test for JWT-scope-escalation shape: a token that exists
    and is issued for this run, but used for an operation it wasn't scoped
    for.
    """
    fuse = make_fuse()
    event = fuse.observe(token_id="tok-1", requested_scope="admin:write")
    assert event is not None
    assert event.severity == Severity.KILL
    assert "tok-1" in event.reason


def test_unknown_token_trips_kill():
    fuse = make_fuse()
    event = fuse.observe(token_id="tok-forged", requested_scope="npm:read")
    assert event is not None
    assert event.severity == Severity.KILL
    assert "unknown token" in event.reason
