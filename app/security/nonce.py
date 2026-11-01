
from threading import Lock


class NonceSequence:
    def __init__(self, limit=1_000_000):
        self._value = 0
        self._limit = limit
        self._lock = Lock()

    def next(self) -> bytes:
        with self._lock:
            if self._value >= self._limit:
                raise RuntimeError("Key usage limit reached")

            result = self._value.to_bytes(12, "big")
            self._value += 1
            return result
