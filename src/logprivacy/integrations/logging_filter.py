"""Python logging filter that redacts sensitive data before emission."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import LogBlockedError
from logprivacy.masking.value import mask_sensitive_value


def _build_standard_record_attributes() -> frozenset[str]:
    """Return the stdlib attributes that are not user supplied through ``extra``."""
    sample = logging.LogRecord(
        name="logprivacy",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    )
    return frozenset((*sample.__dict__, "message", "asctime"))


_STANDARD_RECORD_ATTRIBUTES = _build_standard_record_attributes()
_PRIMITIVE_TYPES = (int, float, complex, bool, type(None))


def _sanitize_value(value: Any, cleaner: Cleaner) -> Any:
    """Return a logging-safe copy, including values unsupported by ``Cleaner.clean``."""
    if isinstance(value, str):
        return cleaner.clean_text(value)

    if isinstance(value, bytes | bytearray):
        decoded = bytes(value).decode("utf-8", errors="replace")
        return cleaner.clean_text(decoded)

    if isinstance(value, Mapping):
        cleaned_mapping: dict[Any, Any] = {}
        for key, item in value.items():
            if cleaner.policy.is_sensitive_key(key):
                cleaned_mapping[key] = mask_sensitive_value(
                    item,
                    category="credential",
                    rule_name="logging_extra",
                    reason="value belongs to a sensitive logging mapping key",
                    policy=cleaner.policy,
                )
            else:
                cleaned_mapping[key] = _sanitize_value(item, cleaner)
        return cleaned_mapping

    if isinstance(value, tuple):
        return tuple(_sanitize_value(item, cleaner) for item in value)

    if isinstance(value, Sequence):
        return [_sanitize_value(item, cleaner) for item in value]

    if isinstance(value, _PRIMITIVE_TYPES):
        return value

    # Logging will eventually call str() or repr() for arbitrary objects. Convert
    # them here and clean the result before a formatter can expose the raw value.
    return cleaner.clean_text(str(value))


def _sanitize_exception(record: logging.LogRecord, cleaner: Cleaner) -> None:
    """Render, clean, and cache exception text before any formatter sees it."""
    if record.exc_info:
        rendered = "".join(traceback.format_exception(*record.exc_info)).rstrip()
        record.exc_text = cleaner.clean_text(rendered)
        # Prevent a formatter from rebuilding the traceback from the original
        # exception object after we have already produced a safe version.
        record.exc_info = None
    elif record.exc_text:
        record.exc_text = cleaner.clean_text(str(record.exc_text))


def _sanitize_extra_attributes(record: logging.LogRecord, cleaner: Cleaner) -> None:
    """Clean user-provided ``extra`` fields in place."""
    for key in tuple(record.__dict__):
        if key in _STANDARD_RECORD_ATTRIBUTES:
            continue

        if cleaner.policy.is_sensitive_key(key):
            record.__dict__[key] = mask_sensitive_value(
                record.__dict__[key],
                category="credential",
                rule_name="logging_extra",
                reason="value belongs to a sensitive LogRecord attribute",
                policy=cleaner.policy,
            )
        else:
            record.__dict__[key] = _sanitize_value(record.__dict__[key], cleaner)


def _matches_logger_namespace(record_name: str, logger_prefix: str | None) -> bool:
    """Return whether a record belongs to a configured logger namespace."""
    if logger_prefix is None:
        return True
    return record_name == logger_prefix or record_name.startswith(f"{logger_prefix}.")


@dataclass(slots=True)
class LogPrivacyFilter(logging.Filter):
    """
    Clean every sensitive component of a ``LogRecord`` before formatting.

    Besides the rendered message, the filter sanitizes format arguments,
    exception tracebacks, stack information, and custom ``extra`` attributes.
    ``logger_prefix`` is used internally by ``get_safe_logger()`` when attaching
    a scoped filter to shared handlers so child loggers are protected without
    modifying unrelated namespaces.
    """

    cleaner: Cleaner = field(default_factory=Cleaner)
    drop_blocked: bool = True
    logger_prefix: str | None = None

    def filter(self, record: logging.LogRecord) -> bool:
        """Clean the complete record and allow it to be emitted."""
        if not _matches_logger_namespace(record.name, self.logger_prefix):
            return True

        try:
            record.args = _sanitize_value(record.args, self.cleaner)
            record.msg = self.cleaner.clean_text(record.getMessage())
            # Clear args so formatters cannot interpolate an original value a
            # second time. The rendered and cleaned message is now authoritative.
            record.args = ()

            _sanitize_exception(record, self.cleaner)

            if record.stack_info:
                record.stack_info = self.cleaner.clean_text(str(record.stack_info))

            _sanitize_extra_attributes(record, self.cleaner)
        except LogBlockedError:
            if self.drop_blocked:
                return False
            raise

        return True


def _iter_effective_handlers(logger: logging.Logger) -> Iterator[logging.Handler]:
    """Yield each handler that can receive records from ``logger`` exactly once."""
    seen: set[int] = set()
    current: logging.Logger | None = logger

    while current is not None:
        for handler in current.handlers:
            handler_id = id(handler)
            if handler_id not in seen:
                seen.add(handler_id)
                yield handler

        if not current.propagate:
            break
        current = current.parent


def install_handler_filters(
    logger: logging.Logger,
    *,
    cleaner: Cleaner,
    drop_blocked: bool,
) -> None:
    """Protect configured handlers for ``logger`` and all of its child loggers."""
    root_logger = logging.getLogger()
    logger_prefix = None if logger is root_logger else logger.name

    for handler in _iter_effective_handlers(logger):
        existing = next(
            (
                candidate
                for candidate in handler.filters
                if isinstance(candidate, LogPrivacyFilter)
                and candidate.logger_prefix == logger_prefix
            ),
            None,
        )
        if existing is None:
            handler.addFilter(
                LogPrivacyFilter(
                    cleaner=cleaner,
                    drop_blocked=drop_blocked,
                    logger_prefix=logger_prefix,
                )
            )
        else:
            existing.cleaner = cleaner
            existing.drop_blocked = drop_blocked
