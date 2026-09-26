"""One monotonic job budget, including a reserved window for permission cleanup.

Queue wait is excluded. OS scheduling and local result persistence are not a
hard real-time guarantee. Expired cleanup fails closed and is retried before
the sandbox can be used again.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import math
import threading
import time


class BudgetExpired(TimeoutError):
    pass


@dataclass
class Budget:
    work_until: float
    finish_until: float


_current = ContextVar('investigation_budget', default=None)
_cleaning = ContextVar('investigation_cleanup', default=False)
_read_slots = threading.BoundedSemaphore(4)


@contextmanager
def investigation(seconds=90.0, cleanup_seconds=15.0):
    if not math.isfinite(seconds) or not 0 < cleanup_seconds < seconds:
        raise ValueError('invalid investigation budget')
    now = time.monotonic()
    token = _current.set(Budget(now + seconds - cleanup_seconds, now + seconds))
    try:
        yield
    finally:
        _current.reset(token)


@contextmanager
def cleanup():
    token = _cleaning.set(True)
    try:
        yield
    finally:
        _cleaning.reset(token)


def timeout(limit=None, *, finishing=False):
    current = _current.get()
    if current is None:
        return limit
    end = current.finish_until if finishing or _cleaning.get() else current.work_until
    remaining = end - time.monotonic()
    if remaining <= 0:
        raise BudgetExpired('investigation time budget exhausted')
    return remaining if limit is None else min(limit, remaining)


def command(args, limit):
    """Cap both the local process and the remote command; never start after expiry."""
    allowed = timeout(limit)
    if _current.get() is None:
        return args, allowed
    result = list(args)
    # Only structured timeout arguments are inspected; never shell/message text.
    indexes = [i for i, arg in enumerate(result) if arg == '--timeout' or arg.startswith('--timeout=')]
    if indexes:
        seconds = math.floor(allowed - 0.25)
        if seconds < 1:
            raise BudgetExpired('insufficient time for remote command')
        for i in indexes:
            if result[i] == '--timeout':
                result[i + 1] = str(min(int(result[i + 1]), seconds))
            else:
                result[i] = '--timeout=' + str(min(int(result[i].split('=', 1)[1]), seconds))
    return result, allowed


def read_only(fn, *args, **kwargs):
    """Bound DNS/HTTP reads that may outlive a per-socket timeout.

Never use for policy mutations. At most four abandoned reads can exist; a
late answer is discarded and cannot open a network grant or update the KB.
"""
    allowed = timeout()
    if allowed is None:
        return fn(*args, **kwargs)
    slots = _read_slots
    if not slots.acquire(blocking=False):
        raise BudgetExpired('read workers unavailable')
    done = threading.Event()
    answer = []

    def run():
        try:
            answer.append((True, fn(*args, **kwargs)))
        except BaseException as exc:
            answer.append((False, exc))
        finally:
            slots.release()
            done.set()

    try:
        threading.Thread(target=run, name='bounded-investigation-read', daemon=True).start()
    except BaseException:
        slots.release()
        raise
    if not done.wait(allowed):
        raise BudgetExpired('read exceeded investigation budget')
    timeout()
    ok, value = answer[0]
    if not ok:
        raise value
    return value
