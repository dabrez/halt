"""Fuse interface.

A fuse is intentionally not an analyzer: it takes one concrete observation
(a connection attempt, a token use, a heartbeat) and returns either nothing
or a TripEvent. No fuse should need to reason about intent — that keeps them
fast enough to run inline and simple enough to audit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from halt.events import TripEvent


class Fuse(ABC):
    name: str

    @abstractmethod
    def observe(self, **kwargs) -> TripEvent | None:
        """Check one observation against policy. Return a TripEvent if it
        violates policy, else None. Must not raise on a normal violation —
        raising is reserved for the fuse itself being broken.
        """
        raise NotImplementedError
