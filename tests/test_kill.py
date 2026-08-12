from halt.kill import LocalProcessBackend, execute_kill


def test_execute_kill_orders_credentials_before_network_before_process():
    backend = LocalProcessBackend()
    result = execute_kill(backend, "run-1", ["tok-1", "tok-2"])
    assert result.credentials_revoked == ["tok-1", "tok-2"]
    assert result.network_severed
    assert backend.is_revoked("tok-1")
    assert backend.is_revoked("tok-2")
    assert backend.is_network_severed("run-1")


def test_execute_kill_with_no_registered_process_reports_not_terminated():
    backend = LocalProcessBackend()
    result = execute_kill(backend, "run-1", [])
    assert result.process_terminated is False
