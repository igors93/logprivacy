from __future__ import annotations

import io
import logging
import sys

import pytest

from logprivacy import Cleaner, CleanerPolicy, LogBlockedError, LogPrivacyFilter, get_safe_logger


def _record(
    message: object,
    *,
    args: tuple[object, ...] | dict[str, object] = (),
    exc_info: tuple[type[BaseException], BaseException, object] | None = None,
) -> logging.LogRecord:
    return logging.LogRecord(
        name="secure",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=args,
        exc_info=exc_info,  # type: ignore[arg-type]
    )


def test_filter_cleans_exception_traceback_and_discards_original_exc_info() -> None:
    secret = "password=super-secret"
    try:
        raise RuntimeError(secret)
    except RuntimeError:
        record = _record("request failed", exc_info=sys.exc_info())  # type: ignore[arg-type]

    assert LogPrivacyFilter().filter(record) is True

    assert record.exc_info is None
    assert record.exc_text is not None
    assert secret not in record.exc_text
    assert "password=[SECRET]" in record.exc_text


def test_filter_cleans_stack_info() -> None:
    record = _record("request failed")
    record.stack_info = "Stack trace: user=john@example.com password=secret123"

    assert LogPrivacyFilter().filter(record) is True

    assert record.stack_info == "Stack trace: user=[EMAIL] password=[SECRET]"


def test_filter_cleans_sensitive_extra_fields_and_nested_payloads() -> None:
    record = _record("request failed")
    record.password = "plain-value"
    record.payload = {
        "email": "john@example.com",
        "nested": {"api_key": "abc123"},
    }

    assert LogPrivacyFilter().filter(record) is True

    assert record.password == "[SECRET]"
    assert record.payload == {
        "email": "[EMAIL]",
        "nested": {"api_key": "[SECRET]"},
    }


def test_filter_cleans_unknown_objects_before_formatting() -> None:
    class UnsafeObject:
        def __str__(self) -> str:
            return "owner=john@example.com password=secret123"

    record = _record("value=%s", args=(UnsafeObject(),))

    assert LogPrivacyFilter().filter(record) is True
    assert record.getMessage() == "value=owner=[EMAIL] password=[SECRET]"


def test_get_safe_logger_protects_child_records_on_shared_root_handler() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(name)s %(message)s"))
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level

    try:
        root.handlers[:] = [handler]
        root.setLevel(logging.DEBUG)

        parent = get_safe_logger("secure-app", level=logging.DEBUG)
        parent.propagate = True
        child = logging.getLogger("secure-app.http")
        child.setLevel(logging.DEBUG)
        child.propagate = True

        child.error("email=%s password=%s", "john@example.com", "secret123")
    finally:
        root.handlers[:] = original_handlers
        root.setLevel(original_level)

    rendered = stream.getvalue()
    assert "john@example.com" not in rendered
    assert "secret123" not in rendered
    assert "secure-app.http email=[EMAIL] password=[SECRET]" in rendered


def test_handler_filter_does_not_modify_unrelated_namespaces() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level

    try:
        root.handlers[:] = [handler]
        root.setLevel(logging.DEBUG)
        get_safe_logger("secure-scope")

        unrelated = logging.getLogger("unrelated")
        unrelated.setLevel(logging.DEBUG)
        unrelated.propagate = True
        unrelated.warning("password=visible-by-design")
    finally:
        root.handlers[:] = original_handlers
        root.setLevel(original_level)

    assert "password=visible-by-design" in stream.getvalue()


def test_get_safe_logger_deduplicates_scoped_handler_filters() -> None:
    handler = logging.StreamHandler(io.StringIO())
    logger = logging.getLogger("deduplicated")
    original_handlers = list(logger.handlers)
    original_propagate = logger.propagate

    try:
        logger.handlers[:] = [handler]
        logger.propagate = False
        get_safe_logger("deduplicated")
        get_safe_logger("deduplicated")

        scoped = [
            candidate
            for candidate in handler.filters
            if isinstance(candidate, LogPrivacyFilter) and candidate.logger_prefix == "deduplicated"
        ]
        assert len(scoped) == 1
    finally:
        logger.handlers[:] = original_handlers
        logger.propagate = original_propagate
        for candidate in list(logger.filters):
            if isinstance(candidate, LogPrivacyFilter):
                logger.removeFilter(candidate)


def test_drop_blocked_false_raises_instead_of_silently_dropping() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.production())
    record = _record("password=secret123")

    with pytest.raises(LogBlockedError):
        LogPrivacyFilter(cleaner=cleaner, drop_blocked=False).filter(record)


def test_drop_blocked_true_drops_the_record() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.production())
    record = _record("password=secret123")

    assert LogPrivacyFilter(cleaner=cleaner, drop_blocked=True).filter(record) is False


def test_final_formatter_output_contains_only_clean_exception_and_extra_data() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s owner=%(owner)s"))
    handler.addFilter(LogPrivacyFilter())
    logger = logging.getLogger("formatted-security")
    original_handlers = list(logger.handlers)
    original_propagate = logger.propagate
    original_level = logger.level

    try:
        logger.handlers[:] = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

        try:
            raise RuntimeError("password=traceback-secret")
        except RuntimeError:
            logger.exception(
                "request from %s failed",
                "john@example.com",
                extra={"owner": "admin@example.com"},
            )
    finally:
        logger.handlers[:] = original_handlers
        logger.propagate = original_propagate
        logger.setLevel(original_level)

    rendered = stream.getvalue()
    assert "john@example.com" not in rendered
    assert "admin@example.com" not in rendered
    assert "traceback-secret" not in rendered
    assert "request from [EMAIL] failed owner=[EMAIL]" in rendered
    assert "password=[SECRET]" in rendered
