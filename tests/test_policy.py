from halt.policy import CredentialRule, NetworkRule, Policy


def make_policy():
    return Policy(
        run_id="run-1",
        org_id="acme",
        network_rules=(
            NetworkRule(host="artifactory.internal", port=443, path_prefix="/api/npm/"),
        ),
        credential_rules=(
            CredentialRule(token_id="tok-1", allowed_scopes=frozenset({"npm:read"})),
        ),
    )


def test_network_allows_exact_match():
    p = make_policy()
    assert p.network_allowed("artifactory.internal", 443, "/api/npm/foo")


def test_network_denies_wrong_path_same_host():
    """Regression test for the actual incident shape: same allowlisted
    host, different (admin) path — must be denied, not treated as
    'the host is fine so anything on it is fine'.
    """
    p = make_policy()
    assert not p.network_allowed("artifactory.internal", 443, "/api/admin/tokens")


def test_network_denies_wrong_port_same_host():
    p = make_policy()
    assert not p.network_allowed("artifactory.internal", 9999, "/api/npm/foo")


def test_network_denies_unlisted_host():
    p = make_policy()
    assert not p.network_allowed("evil.example.com", 443, "/")


def test_credential_scope_lookup():
    p = make_policy()
    assert p.credential_scopes_for("tok-1") == frozenset({"npm:read"})
    assert p.credential_scopes_for("tok-unknown") is None
