from halt.kill import KillBackend, LocalProcessBackend, execute_kill


def test_execute_kill_orders_credentials_before_network_before_process():
    """LocalProcessBackend can sever network before terminating (the
    default), so credentials -> network -> process."""
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


class _NetworkOnlyWorksAfterTerminate(KillBackend):
    """Regression test double modeling the verified Firecracker finding:
    sever_network() fails while the process is alive (tap fd held open)
    and only succeeds once terminate() has already run.
    """

    can_sever_network_before_terminate = False

    def __init__(self):
        self.terminated = False
        self.network_severed = False
        self.revoked = []
        self.sever_network_call_order = []

    def revoke_credential(self, token_id):
        self.revoked.append(token_id)
        return True

    def sever_network(self, run_id):
        self.sever_network_call_order.append(self.terminated)
        if not self.terminated:
            return False
        self.network_severed = True
        return True

    def terminate(self, run_id):
        self.terminated = True
        return True


def test_execute_kill_terminates_before_severing_network_when_backend_requires_it():
    """Regression test for the live Firecracker finding: a backend that
    can't tear down its network path until the process is dead must have
    execute_kill() call terminate() first, or network severance always
    fails.
    """
    backend = _NetworkOnlyWorksAfterTerminate()
    result = execute_kill(backend, "run-1", ["tok-1"])

    assert result.credentials_revoked == ["tok-1"]
    assert result.process_terminated is True
    assert result.network_severed is True
    # sever_network was called exactly once, and terminated was already
    # True at that point -- proving the order, not just the outcome.
    assert backend.sever_network_call_order == [True]
