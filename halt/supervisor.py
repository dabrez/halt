"""The supervisor owns kill authority.

It is the one thing in this system that is allowed to call execute_kill.
Fuses only ever produce TripEvents; they never act directly. This split
matters because it means the kill path has exactly one implementation to
audit, and fuses can be added without touching kill logic.

Under concurrent trips (realistic — a real escape trips multiple fuses
near-simultaneously) the supervisor records the first KILL-severity event
as the recorded cause and ignores severity-ordering races: "first kill
wins" deterministically by event_id/ts, not by which thread happened to
acquire a lock first.
"""

from __future__ import annotations

import threading

from halt.events import Severity, TripEvent
from halt.kill import KillBackend, KillResult, execute_kill
from halt.sinks import Sink


class Supervisor:
    def __init__(
        self,
        backend: KillBackend,
        sink: Sink,
        run_id: str,
        credential_ids: list[str] | None = None,
    ):
        self.backend = backend
        self.sink = sink
        self.run_id = run_id
        self.credential_ids = credential_ids or []

        self._lock = threading.Lock()
        self._killed = False
        self._cause: TripEvent | None = None
        self._kill_result: KillResult | None = None

    @property
    def killed(self) -> bool:
        return self._killed

    @property
    def cause(self) -> TripEvent | None:
        return self._cause

    @property
    def kill_result(self) -> KillResult | None:
        return self._kill_result

    def report(self, event: TripEvent) -> None:
        """Called by fuses (or code driving them) with every observation,
        trip or not. Only KILL-severity events can trigger a kill; the
        first one, under the lock, is the one that fires and is recorded
        as cause — later concurrent trips are still logged but do not
        re-trigger or overwrite the recorded cause.
        """
        self.sink.emit(event)

        if event.severity != Severity.KILL:
            return

        with self._lock:
            if self._killed:
                return
            self._killed = True
            self._cause = event
            self._kill_result = execute_kill(
                self.backend, self.run_id, self.credential_ids
            )
