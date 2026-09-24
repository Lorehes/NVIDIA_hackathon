"""요청 제한(검토 2.7): 세션·클라이언트별 속도 제한과 재생 모드 동시 실행 상한. 모두 메모리 안에서만 센다."""
from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """키별로 최근 window초 안의 요청 수를 센다. 허용하면 True(그리고 기록), 초과하면 False.

    키 수에는 하드 상한(max_keys)이 있다. 가득 차면 만료된 키를 정리해 보고(간격은 evict_interval_s, 기본 1초에 한 번만), 그래도 자리가 없으면
    새 키는 거부한다(키를 돌려 가며 메모리를 채우거나 정리 작업으로 잠금을 붙잡는 공격을 막는다).
    """

    def __init__(self, limit: int, window_s: float = 60.0, max_keys: int = 10_000, evict_interval_s: float = 1.0):
        self.limit, self.window, self.max_keys, self.evict_interval = limit, window_s, max_keys, evict_interval_s
        self._hits: dict[str, deque[float]] = {}
        self._last_evict = float("-inf")
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        self._last_evict = now
        for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window]:
            del self._hits[k]

    def allow(self, key: str, limit: int | None = None) -> bool:
        now = time.monotonic()
        cap = self.limit if limit is None else limit
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self.max_keys:
                    if now - self._last_evict >= self.evict_interval:
                        self._evict(now)
                    if len(self._hits) >= self.max_keys:
                        return False
                q = self._hits[key] = deque()
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= cap:
                return False
            q.append(now)
            return True


class Slots:
    """동시에 실행할 수 있는 작업 수를 제한한다(재생 모드 스레드용)."""

    def __init__(self, n: int):
        self._n, self._used, self._lock = n, 0, threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self._used >= self._n:
                return False
            self._used += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._used = max(0, self._used - 1)
