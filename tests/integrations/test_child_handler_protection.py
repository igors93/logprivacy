from __future__ import annotations

import io
import logging

from logprivacy import LogPrivacyFilter, get_safe_logger


def _restore_logger(
    logger: logging.Logger,
    *,
    handlers: list[logging.Handler],
    filters: list[logging.Filter],
    level: int,
    propagate: bool,
) -> None:
    logger.handlers[:] = handlers
    logger.filters[:] = filters
    logger.setLevel(level)
    logger.propagate = propagate


def test_get_safe_logger_protects_existing_child_handler_without_propagation() -> None:
    parent = logging.getLogger("child-handler-secure")
    child = logging.getLogger("child-handler-secure.worker")
    parent_state = {
        "handlers": list(parent.handlers),
        "filters": list(parent.filters),
        "level": parent.level,
        "propagate": parent.propagate,
    }
    child_state = {
        "handlers": list(child.handlers),
        "filters": list(child.filters),
        "level": child.level,
        "propagate": child.propagate,
    }
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)

    try:
        parent.handlers[:] = []
        parent.propagate = False
        child.handlers[:] = [handler]
        child.filters[:] = []
        child.setLevel(logging.DEBUG)
        child.propagate = False

        get_safe_logger("child-handler-secure", level=logging.DEBUG)
        child.error("email=%s password=%s", "john@example.com", "secret123")
    finally:
        _restore_logger(parent, **parent_state)
        _restore_logger(child, **child_state)

    rendered = stream.getvalue()
    assert "john@example.com" not in rendered
    assert "secret123" not in rendered
    assert "email=[EMAIL] password=[SECRET]" in rendered


def test_get_safe_logger_deduplicates_filters_on_existing_child_handler() -> None:
    parent = logging.getLogger("child-handler-deduplicated")
    child = logging.getLogger("child-handler-deduplicated.worker")
    parent_state = {
        "handlers": list(parent.handlers),
        "filters": list(parent.filters),
        "level": parent.level,
        "propagate": parent.propagate,
    }
    child_state = {
        "handlers": list(child.handlers),
        "filters": list(child.filters),
        "level": child.level,
        "propagate": child.propagate,
    }
    handler = logging.StreamHandler(io.StringIO())

    try:
        parent.handlers[:] = []
        parent.propagate = False
        child.handlers[:] = [handler]
        child.propagate = False

        get_safe_logger("child-handler-deduplicated")
        get_safe_logger("child-handler-deduplicated")

        scoped = [
            candidate
            for candidate in handler.filters
            if isinstance(candidate, LogPrivacyFilter)
            and candidate.logger_prefix == "child-handler-deduplicated"
        ]
        assert len(scoped) == 1
    finally:
        _restore_logger(parent, **parent_state)
        _restore_logger(child, **child_state)


def test_get_safe_logger_does_not_install_filters_on_unrelated_child_handlers() -> None:
    parent = logging.getLogger("child-handler-scope")
    unrelated = logging.getLogger("other-child-handler.worker")
    parent_state = {
        "handlers": list(parent.handlers),
        "filters": list(parent.filters),
        "level": parent.level,
        "propagate": parent.propagate,
    }
    unrelated_state = {
        "handlers": list(unrelated.handlers),
        "filters": list(unrelated.filters),
        "level": unrelated.level,
        "propagate": unrelated.propagate,
    }
    handler = logging.StreamHandler(io.StringIO())

    try:
        parent.handlers[:] = []
        parent.propagate = False
        unrelated.handlers[:] = [handler]
        unrelated.propagate = False

        get_safe_logger("child-handler-scope")

        scoped = [
            candidate for candidate in handler.filters if isinstance(candidate, LogPrivacyFilter)
        ]
        assert scoped == []
    finally:
        _restore_logger(parent, **parent_state)
        _restore_logger(unrelated, **unrelated_state)


def test_get_safe_logger_does_not_match_similar_namespace_prefix() -> None:
    parent = logging.getLogger("app")
    unrelated = logging.getLogger("application.worker")
    parent_state = {
        "handlers": list(parent.handlers),
        "filters": list(parent.filters),
        "level": parent.level,
        "propagate": parent.propagate,
    }
    unrelated_state = {
        "handlers": list(unrelated.handlers),
        "filters": list(unrelated.filters),
        "level": unrelated.level,
        "propagate": unrelated.propagate,
    }
    handler = logging.StreamHandler(io.StringIO())

    try:
        parent.handlers[:] = []
        parent.propagate = False
        unrelated.handlers[:] = [handler]
        unrelated.propagate = False

        get_safe_logger("app")

        assert not any(isinstance(candidate, LogPrivacyFilter) for candidate in handler.filters)
    finally:
        _restore_logger(parent, **parent_state)
        _restore_logger(unrelated, **unrelated_state)


def test_shared_handler_receives_one_scoped_filter() -> None:
    parent = logging.getLogger("shared-handler")
    child = logging.getLogger("shared-handler.worker")
    parent_state = {
        "handlers": list(parent.handlers),
        "filters": list(parent.filters),
        "level": parent.level,
        "propagate": parent.propagate,
    }
    child_state = {
        "handlers": list(child.handlers),
        "filters": list(child.filters),
        "level": child.level,
        "propagate": child.propagate,
    }
    handler = logging.StreamHandler(io.StringIO())

    try:
        parent.handlers[:] = [handler]
        parent.propagate = False
        child.handlers[:] = [handler]
        child.propagate = False

        get_safe_logger("shared-handler")

        scoped = [
            candidate
            for candidate in handler.filters
            if isinstance(candidate, LogPrivacyFilter)
            and candidate.logger_prefix == "shared-handler"
        ]
        assert len(scoped) == 1
    finally:
        _restore_logger(parent, **parent_state)
        _restore_logger(child, **child_state)
