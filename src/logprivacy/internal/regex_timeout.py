"""Cross-platform time-bounded execution for standard-library regex searches."""

from __future__ import annotations

import atexit
import contextlib
import math
import pickle
import queue
import re
import signal
import struct
import subprocess
import sys
import threading
from collections.abc import Callable
from re import Pattern
from types import FrameType
from typing import IO, Any, cast

from logprivacy.exceptions import InputLimitExceededError

DEFAULT_REGEX_TIMEOUT_SECONDS = 0.25
_WORKER_STARTUP_SECONDS = 10.0
_LIMIT_REGEX_EXECUTION_MS = "regex_execution_ms"
_LIMIT_REGEX_WORKER_STARTUP_MS = "regex_worker_startup_ms"
_FRAME_HEADER_SIZE = 4

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
import struct
import sys


def read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


stdin = sys.stdin.buffer
stdout = sys.stdout.buffer
stdout.write(b"READY\n")
stdout.flush()

while True:
    header = stdin.read(4)
    if not header:
        break
    if len(header) != 4:
        break
    try:
        size = struct.unpack("!I", header)[0]
        payload = read_exact(stdin, size)
        pattern, flags, text = pickle.loads(payload)
        response = ("ok", re.compile(pattern, flags).search(text) is not None)
    except Exception:
        response = ("error", None)
    encoded = pickle.dumps(response, protocol=pickle.HIGHEST_PROTOCOL)
    stdout.write(struct.pack("!I", len(encoded)))
    stdout.write(encoded)
    stdout.flush()
"""


class _RegexExecutionTimeout(Exception):
    """Internal signal used to interrupt the stdlib regex engine."""


class _RegexWorkerUnavailable(Exception):
    """Internal marker for a worker that exited before returning a result."""


class _PersistentRegexWorker:
    """Reuse one isolated Python worker for sequential regex searches."""

    def __init__(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", _WORKER_CODE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        stdin_pipe = process.stdin
        stdout_pipe = process.stdout
        assert stdin_pipe is not None
        assert stdout_pipe is not None

        self._process: subprocess.Popen[bytes] = process
        self._stdin: IO[bytes] = stdin_pipe
        self._stdout: IO[bytes] = stdout_pipe
        self._responses: queue.Queue[bytes | None] = queue.Queue()
        self._request_lock = threading.Lock()
        self._ready = threading.Event()
        self._startup_ok = False
        self._closed = False
        self._reader = threading.Thread(target=self._read_responses, daemon=True)
        self._reader.start()

        if not self._ready.wait(_WORKER_STARTUP_SECONDS):
            self.close()
            raise InputLimitExceededError(
                limit=_LIMIT_REGEX_WORKER_STARTUP_MS,
                maximum=math.ceil(_WORKER_STARTUP_SECONDS * 1_000),
            )
        if not self._startup_ok:
            self.close()
            raise RuntimeError("regex worker failed to start")

    @property
    def is_alive(self) -> bool:
        """Return whether the worker can accept another request."""
        return not self._closed and self._process.poll() is None

    def search(self, pattern: Pattern[str], text: str, *, timeout_seconds: float) -> bool:
        """Run one search while serializing access to the shared worker."""
        payload = pickle.dumps(
            (pattern.pattern, pattern.flags & ~re.DEBUG, text),
            protocol=pickle.HIGHEST_PROTOCOL,
        )
        frame = struct.pack("!I", len(payload)) + payload

        with self._request_lock:
            if not self.is_alive:
                raise _RegexWorkerUnavailable
            try:
                self._stdin.write(frame)
                self._stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise _RegexWorkerUnavailable from exc

            try:
                encoded = self._responses.get(timeout=timeout_seconds)
            except queue.Empty:
                self.close()
                raise _execution_limit_error(timeout_seconds) from None

            if encoded is None:
                raise _RegexWorkerUnavailable
            try:
                status, result = pickle.loads(encoded)
            except Exception as exc:
                raise RuntimeError("regex worker returned an invalid result") from exc
            if status != "ok" or type(result) is not bool:
                raise RuntimeError("regex worker failed")
            return result

    def close(self) -> None:
        """Stop the worker and release its pipes without waiting indefinitely."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError, ValueError):
            self._stdin.close()
        if self._process.poll() is None:
            with contextlib.suppress(OSError):
                self._process.terminate()
            try:
                self._process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(OSError):
                    self._process.kill()
                with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                    self._process.wait(timeout=0.2)
        with contextlib.suppress(OSError, ValueError):
            self._stdout.close()

    def _read_responses(self) -> None:
        try:
            if self._stdout.readline() != b"READY\n":
                return
            self._startup_ok = True
            self._ready.set()

            while True:
                header = _read_exact(self._stdout, _FRAME_HEADER_SIZE)
                if header is None:
                    return
                size = struct.unpack("!I", header)[0]
                payload = _read_exact(self._stdout, size)
                if payload is None:
                    return
                self._responses.put(payload)
        except (EOFError, OSError, ValueError, struct.error):
            return
        finally:
            self._ready.set()
            self._responses.put(None)


_ACTIVE_WORKER: _PersistentRegexWorker | None = None
_ACTIVE_WORKER_LOCK = threading.Lock()


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
    for attempt in range(2):
        worker = _get_worker()
        try:
            return worker.search(pattern, text, timeout_seconds=timeout_seconds)
        except _RegexWorkerUnavailable:
            _discard_worker(worker)
            if attempt == 1:
                raise RuntimeError("regex worker failed") from None
    raise AssertionError("unreachable")


def _get_worker() -> _PersistentRegexWorker:
    global _ACTIVE_WORKER
    with _ACTIVE_WORKER_LOCK:
        worker = _ACTIVE_WORKER
        if worker is None or not worker.is_alive:
            if worker is not None:
                worker.close()
            worker = _PersistentRegexWorker()
            _ACTIVE_WORKER = worker
        return worker


def _discard_worker(worker: _PersistentRegexWorker) -> None:
    global _ACTIVE_WORKER
    with _ACTIVE_WORKER_LOCK:
        if _ACTIVE_WORKER is worker:
            _ACTIVE_WORKER = None
    worker.close()


def _shutdown_worker() -> None:
    """Close the shared worker during interpreter shutdown and test cleanup."""
    global _ACTIVE_WORKER
    with _ACTIVE_WORKER_LOCK:
        worker = _ACTIVE_WORKER
        _ACTIVE_WORKER = None
    if worker is not None:
        worker.close()


def _read_exact(stream: IO[bytes], size: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if not chunks:
                return None
            raise EOFError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


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


atexit.register(_shutdown_worker)
