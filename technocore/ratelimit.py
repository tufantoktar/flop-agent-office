"""Client-side token buckets.

Technocore rate-limits per IP with two buckets (reads and writes) whose limits
vary by deployment. We keep our own buckets set *below* whatever the server
advertises, so we throttle ourselves before the server has to. Being throttled
by a shared public service is both rude and a availability risk for everyone
else using it.

Deliberately absent: aggressive retry. On refusal the caller waits or gives up.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = ["TokenBucket", "RateLimitExceeded", "Budget", "SAFETY_FACTOR"]

#: Fraction of the server's advertised limit we allow ourselves to use.
SAFETY_FACTOR = 0.5


class RateLimitExceeded(Exception):
    """A call was refused locally to stay inside our own budget."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(f"local rate limit reached; retry in {retry_after:.1f}s")
        self.retry_after = retry_after


@dataclass
class TokenBucket:
    """Continuously refilling token bucket, thread-safe."""

    capacity: float
    refill_per_second: float
    _tokens: float = 0.0
    _updated: float = 0.0
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.refill_per_second <= 0:
            raise ValueError("capacity and refill_per_second must be positive")
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)
        self._updated = now

    def try_acquire(self, tokens: float = 1.0) -> bool:
        with self._lock:
            self._refill(time.monotonic())
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: float = 1.0, *, block: bool = True,
                max_wait: float = 30.0) -> None:
        """Take ``tokens``, waiting if allowed. Raises RateLimitExceeded otherwise."""
        deadline = time.monotonic() + max_wait
        while True:
            if self.try_acquire(tokens):
                return
            with self._lock:
                self._refill(time.monotonic())
                deficit = tokens - self._tokens
                wait = max(0.01, deficit / self.refill_per_second)
            if not block or time.monotonic() + wait > deadline:
                raise RateLimitExceeded(wait)
            time.sleep(min(wait, 0.5))

    @property
    def available(self) -> float:
        with self._lock:
            self._refill(time.monotonic())
            return self._tokens


@dataclass(frozen=True, slots=True)
class Budget:
    """Read/write buckets derived from a server's advertised limits."""

    reads: TokenBucket
    writes: TokenBucket

    @classmethod
    def from_advertised(
        cls,
        reads_per_minute: int,
        writes_per_minute: int,
        *,
        safety: float = SAFETY_FACTOR,
    ) -> "Budget":
        """Build buckets at ``safety`` x the server's stated limits."""
        reads = max(1.0, reads_per_minute * safety)
        writes = max(1.0, writes_per_minute * safety)
        return cls(
            reads=TokenBucket(capacity=reads, refill_per_second=reads / 60.0),
            writes=TokenBucket(capacity=writes, refill_per_second=writes / 60.0),
        )

    @classmethod
    def conservative(cls) -> "Budget":
        """Fallback when limits could not be discovered: assume little."""
        return cls.from_advertised(reads_per_minute=30, writes_per_minute=2)
