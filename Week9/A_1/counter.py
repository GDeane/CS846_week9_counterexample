import threading


class ThreadSafeCounter:
    """A counter intended for use across multiple threads."""

    def __init__(self):
        self._lock = threading.Lock()
        self._value = 0

    def increment(self):
        current = self._value
        self._value = current + 1

    def decrement(self):
        with self._lock:
            self._value -= 1

    def get(self):
        return self._value
