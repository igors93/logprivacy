"""Custom user-defined redaction rules."""

from __future__ import annotations

import math
import pickle
import re
import signal
import subprocess
import sys
import threading
from types import FrameType

from logprivacy.exceptions import InputLimitExceededError
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.rules.base import RegexRedactionRule

_DEFAULT_TIMEOUT_SECONDS = 0.25
_WORKER_STARTUP_SECONDS = 10.0
_LIMIT_REGEX_EXECUTION_MS = "regex_execution_ms"
_LIMIT_REGEX_WORKER_STARTUP_MS = "regex_worker_startup_ms"

_WORKER_CODE = r"""
import pickle
import re
import sys

sys.stdout.buffer.write(b"READY\n")
sys.stdout.buffer.flush()
pattern, flags, text, max_matches = pickle.loads(sys.stdin.buffer.read())
compiled = re.compile(pattern, flags)
matches = []
for match in compiled.finditer(text):
    if max_matches is not None and len(matches) >= max_matches:
        pickle.dump(("max_matches", ()), sys.stdout.buffer)
        raise SystemExit(0)
    matches.append((match.start(), match.end(), match.group(0)))
pickle.dump(("ok", matches), sys.stdout.buffer)
"""


class _RegexExecutionTimeout(Exception):
    """Internal signal used to interrupt the stdlib regex engine."""


class CustomRegexRule(RegexRedactionRule):
    """Create a custom regex rule with isolated, time-bounded execution."""

    __slots__ = ("timeout_seconds",)

    timeout_seconds: float | None

    def __init__(
        self,
        *,
        name: str,
        category: str,
        pattern: str,
        flags: int = 0,
        reason: str = "text matched a custom redaction rule",
        timeout_seconds: float | None = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if timeout_seconds is not None:
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
                raise TypeError("timeout_seconds must be a positive number or None")
            if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
                raise ValueError("timeout_seconds must be greater than zero")
            timeout_seconds = float(timeout_seconds)

        super().__init__(
            name=name,
            category=category,
            pattern=re.compile(pattern, flags),
            reason=reason,
        )
        object.__setattr__(self, "timeout_seconds", timeout_seconds)

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        """Return matches while enforcing the configured execution timeout."""
        return self._find_matches_with_timeout(text, max_matches=None)

    def find_limited(self, text: str, max_matches: int) -> tuple[_DetectedMatch, ...]:
        """Return a bounded number of matches within the execution timeout."""
        return self._find_matches_with_timeout(text, max_matches=max_matches)

    def _find_matches_with_timeout(
        self,
        text: str,
        *,
        max_matches: int | None,
    ) -> tuple[_DetectedMatch, ...]:
        timeout_seconds = self.timeout_seconds
        if timeout_seconds is None:
            return super()._find_matches(text, max_matches=max_matches)
        if _signal_timeout_available():
            return self._find_matches_with_signal(
                text,
                max_matches=max_matches,
                timeout_seconds=timeout_seconds,
            )
        return self._find_matches_in_worker(
            text,
            max_matches=max_matches,
            timeout_seconds=timeout_seconds,
        )

    def _find_matches_with_signal(
        self,
        text: str,
        *,
        max_matches: int | None,
        timeout_seconds: float,
    ) -> tuple[_DetectedMatch, ...]:
        def raise_timeout(signum: int, frame: FrameType | None) -> None:
            del signum, frame
            raise _RegexExecutionTimeout

        _sv = vars(signal)
        _sigalrm = _sv["SIGALRM"]
        _itimer_real = _sv["ITIMER_REAL"]
        _setitimer = _sv["setitimer"]
        previous_handler = signal.getsignal(_sigalrm)
        signal.signal(_sigalrm, raise_timeout)
        _setitimer(_itimer_real, timeout_seconds)
        try:
            return super()._find_matches(text, max_matches=max_matches)
        except _RegexExecutionTimeout:
            raise _execution_limit_error(timeout_seconds) from None
        finally:
            _setitimer(_itimer_real, 0)
            signal.signal(_sigalrm, previous_handler)

    def _find_matches_in_worker(
        self,
        text: str,
        *,
        max_matches: int | None,
        timeout_seconds: float,
    ) -> tuple[_DetectedMatch, ...]:
        payload = pickle.dumps(
            (self.pattern.pattern, self.pattern.flags & ~re.DEBUG, text, max_matches),
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
            raise RuntimeError("custom regex worker failed to start")

        try:
            stdout, _ = process.communicate(input=payload, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise _execution_limit_error(timeout_seconds) from None

        if process.returncode != 0:
            raise RuntimeError("custom regex worker failed")
        return self._decode_worker_result(stdout, max_matches=max_matches)

    def _decode_worker_result(
        self,
        payload: bytes,
        *,
        max_matches: int | None,
    ) -> tuple[_DetectedMatch, ...]:
        status, raw_matches = pickle.loads(payload)
        if status == "max_matches":
            assert max_matches is not None
            raise InputLimitExceededError(limit="max_matches", maximum=max_matches)
        if status != "ok":
            raise RuntimeError("custom regex worker returned an invalid result")

        return tuple(
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=start,
                end=end,
                matched=matched,
                reason=self.reason,
            )
            for start, end, matched in raw_matches
        )


def _signal_timeout_available() -> bool:
    """Return whether a private real-time alarm can safely bound this call."""
    if threading.current_thread() is not threading.main_thread():
        return False
    required = ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")
    if not all(hasattr(signal, name) for name in required):
        return False
    _sv = vars(signal)
    if signal.getsignal(_sv["SIGALRM"]) is not signal.SIG_DFL:
        return False
    remaining, interval = _sv["getitimer"](_sv["ITIMER_REAL"])
    return bool(remaining == 0 and interval == 0)


def _execution_limit_error(timeout_seconds: float) -> InputLimitExceededError:
    return InputLimitExceededError(
        limit=_LIMIT_REGEX_EXECUTION_MS,
        maximum=max(1, math.ceil(timeout_seconds * 1_000)),
    )
