"""Cross-platform time-bounded execution for standard-library regex searches."""

from __future__ import annotations

import math
import pickle
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Callable
from re import Pattern
from types import FrameType
from typing import Any, cast

from logprivacy.exceptions import InputLimitExceededError

DEFAULT_REGEX_TIMEOUT_SECONDS = 0.25
_WORKER_STARTUP_SECONDS = 10.0
_LIMIT_REGEX_EXECUTION_MS = "regex_execution_ms"
_LIMIT_REGEX_WORKER_STARTUP_MS = "regex_worker_startup_ms"

_GetSignal = Callable[[int], Any]
_SetSignal = Callable[[int, Any], Any]
_GetITimer = Callable[[int], tuple[float, float]]
_SetITimer = Callable[[int, float, float], tuple[float, float]]

_GETSIGNAL = cast(_GetSignal, signal.getsignal)
_SET_SIGNAL = cast(_SetSignal, signal.signal)
_SIGALRM = cast(int | None, getattr(signal, "SIGALRM", None))
_ITIMER_REAL = cast(int | None, getattr(signal, "ITIMER_REAL", None))
_GETITIMER = cast(_GetITimer | None, getattr(signal, "getitimer", None))
_SETITIMER = cast(_SetITimer | None, getattr(signal, "setitimer", None))

_WORKER_CODE = r"""
import pickle
import re
import sys

sys.stdout.buffer.write(b"READY\n")
sys.stdout.buffer.flush()
pattern, flags, text = pickle.loads(sys.stdin.buffer.read())
compiled = re.compile(pattern, flags)
pickle.dump(compiled.search(text) is not None, sys.stdout.buffer)
"""


class _RegexExecutionTimeout(Exception):
    """Internal signal used to interrupt the stdlib regex engine."""


def regex_search_with_timeout(
    pattern: Pattern[str],
    text: str,
    *,
    timeout_seconds: float = DEFAULT_REGEX_TIMEOUT_SECONDS,
) -> bool:
    """Return whether ``pattern`` matches while enforcing an execution deadline."""
    if _signal_timeout_available():
        return _search_with_signal(pattern, text, timeout_seconds=timeout_seconds)
    return _search_in_worker(pattern, text, timeout_seconds=timeout_seconds)


def _search_with_signal(
    pattern: Pattern[str],
    text: str,
    *,
    timeout_seconds: float,
) -> bool:
    sigalrm = _SIGALRM
    itimer_real = _ITIMER_REAL
    setitimer = _SETITIMER
    if sigalrm is None or itimer_real is None or setitimer is None:
        return _search_in_worker(pattern, text, timeout_seconds=timeout_seconds)

    def raise_timeout(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        raise _RegexExecutionTimeout

    previous_handler = _GETSIGNAL(sigalrm)
    _SET_SIGNAL(sigalrm, raise_timeout)
    setitimer(itimer_real, timeout_seconds, 0.0)
    try:
        return pattern.search(text) is not None
    except _RegexExecutionTimeout:
        raise _execution_limit_error(timeout_seconds) from None
    finally:
        setitimer(itimer_real, 0.0, 0.0)
        _SET_SIGNAL(sigalrm, previous_handler)


def _search_in_worker(
    pattern: Pattern[str],
    text: str,
    *,
    timeout_seconds: float,
) -> bool:
    payload = pickle.dumps(
        (pattern.pattern, pattern.flags & ~re.DEBUG, text),
        protocol=pickle.HIGHEST_PROTOCOL,
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", _WORKER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    stdout_pipe = process.stdout
    assert stdout_pipe is not None

    ready: list[bytes] = []
    reader = threading.Thread(
        target=lambda: ready.append(stdout_pipe.readline()),
        daemon=True,
    )
    reader.start()
    reader.join(_WORKER_STARTUP_SECONDS)
    if reader.is_alive():
        process.kill()
        process.wait()
        raise InputLimitExceededError(
            limit=_LIMIT_REGEX_WORKER_STARTUP_MS,
            maximum=math.ceil(_WORKER_STARTUP_SECONDS * 1_000),
        )
    if ready != [b"READY\n"]:
        process.kill()
        process.wait()
        raise RuntimeError("regex worker failed to start")

    try:
        stdout, _ = process.communicate(input=payload, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise _execution_limit_error(timeout_seconds) from None

    if process.returncode != 0:
        raise RuntimeError("regex worker failed")
    result = pickle.loads(stdout)
    if type(result) is not bool:
        raise RuntimeError("regex worker returned an invalid result")
    return result


def _signal_timeout_available() -> bool:
    """Return whether a private real-time alarm can safely bound this call."""
    sigalrm = _SIGALRM
    itimer_real = _ITIMER_REAL
    getitimer = _GETITIMER
    setitimer = _SETITIMER
    if sigalrm is None or itimer_real is None or getitimer is None or setitimer is None:
        return False
    if threading.current_thread() is not threading.main_thread():
        return False
    if _GETSIGNAL(sigalrm) is not signal.SIG_DFL:
        return False
    remaining, interval = getitimer(itimer_real)
    return remaining == 0 and interval == 0


def _execution_limit_error(timeout_seconds: float) -> InputLimitExceededError:
    return InputLimitExceededError(
        limit=_LIMIT_REGEX_EXECUTION_MS,
        maximum=max(1, math.ceil(timeout_seconds * 1_000)),
    )
