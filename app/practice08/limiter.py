"""Student task: atomic constant-state admission window, before authentication."""
from dataclasses import dataclass
from threading import RLock
from time import monotonic
from typing import Callable
from .settings import LimitSettings


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: int = 0

    def __post_init__(self):
        if type(self.allowed) is not bool or type(self.retry_after) is not int:
            raise TypeError("invalid admission decision")
        if (self.allowed and self.retry_after != 0) or (
                not self.allowed and self.retry_after < 1):
            raise ValueError("invalid retry interval")


class FixedWindowLimiter:
    def __init__(self, settings: LimitSettings,
                 clock: Callable[[], float] = monotonic):
        if not isinstance(settings, LimitSettings) or not callable(clock):
            raise TypeError("settings and clock required")
        self.settings, self.clock = settings, clock
        self._lock = RLock()
        self._started = None
        self._last = None
        self._used = 0

    def admit(self) -> Decision:
        """TODO under one lock: read/check clock, renew expired window, decide.

        Clock is finite nonnegative int/float, never bool; backward time raises
        ValueError without resetting the policy. The first allowed call starts
        [start,start+T). First N calls allowed; others denied with ceil(remaining)
        at least1. Rejected calls neither increase _used nor move _started.
        No sleep, body/login/IP storage, database, callbacks, or public reset.
        State belongs to this object, shared by all matched requests in ONE app.
        """
        raise NotImplementedError("TODO: atomic fixed admission window")
