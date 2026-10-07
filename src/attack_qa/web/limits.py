"""Rate limits for the public demo API (grill-decisions Q43).

Counters live in memory, so they reset when the container scales to zero. That is acceptable:
Groq's own daily quota and Azure's one-replica cap are the hard limits; these counters only let
the demo stop gracefully before Groq does.
"""

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

HOUR_S = 3600.0


@dataclass(frozen=True)
class Limits:
    per_ip_per_hour: int = 10
    per_day: int = 50  # all visitors together; leaves ~30% of Groq's free tokens for development
    max_question_chars: int = 300


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""  # "ip" or "daily" when refused
    retry_after_s: int = 0
    remaining_today: int = 0


class RateLimiter:
    def __init__(self, limits: Limits = Limits(), clock: Callable[[], float] = time.time) -> None:
        self.limits = limits
        self._clock = clock
        self._recent: dict[str, deque[float]] = {}  # per IP: times of allowed questions, oldest first
        self._day = ""
        self._today = 0
        self._lock = threading.Lock()  # FastAPI runs sync endpoints in a thread pool

    def check(self, ip: str) -> Decision:
        """Decide whether this visitor may ask now; an allowed question is counted immediately."""
        with self._lock:
            now = self._clock()
            day = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
            if day != self._day:  # the daily cap resets at 00:00 UTC (08:00 in Taiwan)
                self._day, self._today = day, 0
            left = self.limits.per_day - self._today
            if left <= 0:
                return Decision(False, "daily")
            wait = self._seconds_until_allowed(ip, now)
            if wait > 0:
                return Decision(False, "ip", retry_after_s=wait, remaining_today=left)
            self._recent.setdefault(ip, deque()).append(now)
            self._today += 1
            return Decision(True, remaining_today=left - 1)

    def _seconds_until_allowed(self, ip: str, now: float) -> int:
        """0 if this IP has asked fewer than per_ip_per_hour questions in the past hour.

        Otherwise the whole seconds until its oldest question in that hour drops out of the window.
        """
        recent = self._recent.get(ip)
        if recent is None:
            return 0
        while recent and now - recent[0] >= HOUR_S:  # oldest first, so stop at the first recent one
            recent.popleft()
        if not recent:
            del self._recent[ip]  # forget visitors who have gone quiet, or memory grows forever
            return 0
        if len(recent) < self.limits.per_ip_per_hour:
            return 0
        return max(1, math.ceil(recent[0] + HOUR_S - now))
