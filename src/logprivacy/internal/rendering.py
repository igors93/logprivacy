"""Safe rendering helpers for terminal and diagnostic output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from typing import Any

from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import LogBlockedError

_PRIMITIVE_TYPES = (int, float, complex, bool, type(None))
_MAX_DEPTH_PLACEHOLDER = "[MAX_DEPTH]"


def safe_render(value: Any, cleaner: Cleaner) -> str:
    """Return a recursively rendered string that cannot expose raw object representations."""
    return _render(value, cleaner, nested=False, depth=0, active=set())


def _render(
    value: Any,
    cleaner: Cleaner,
    *,
    nested: bool,
    depth: int,
    active: set[int],
) -> str:
    """Render one value without delegating container formatting to unsafe ``repr()`` calls."""
    max_depth = int(getattr(cleaner.policy, "max_depth", 20))
    if depth > max_depth:
        return _render_text(_MAX_DEPTH_PLACEHOLDER, nested=nested)

    if isinstance(value, str):
        return _render_text(cleaner.clean_text(value), nested=nested)

    if isinstance(value, bytes | bytearray | memoryview):
        decoded = bytes(value).decode("utf-8", errors="replace")
        return _render_text(cleaner.clean_text(decoded), nested=nested)

    if isinstance(value, Mapping):
        return _render_mapping(value, cleaner, depth=depth, active=active)

    if isinstance(value, tuple):
        return _render_tuple(value, cleaner, depth=depth, active=active)

    if isinstance(value, list):
        return _render_list(value, cleaner, depth=depth, active=active)

    if isinstance(value, Set):
        return _render_set(value, cleaner, depth=depth, active=active)

    if isinstance(value, Sequence):
        return _render_sequence(value, cleaner, depth=depth, active=active)

    if isinstance(value, _PRIMITIVE_TYPES):
        return repr(value)

    rendered = _stringify_unknown(value)
    return _render_text(cleaner.clean_text(rendered), nested=nested)


def _render_text(value: str, *, nested: bool) -> str:
    """Render text directly at the top level and quoted inside containers."""
    return repr(value) if nested else value


def _render_mapping(
    value: Mapping[Any, Any],
    cleaner: Cleaner,
    *,
    depth: int,
    active: set[int],
) -> str:
    """Render a mapping while fully masking sensitive-key values."""
    value_id = id(value)
    if value_id in active:
        return "{...}"

    active.add(value_id)
    try:
        parts: list[str] = []
        for key, item in value.items():
            rendered_key = _render(key, cleaner, nested=True, depth=depth + 1, active=active)
            if _is_sensitive_key(cleaner, key):
                _raise_if_credential_is_blocked(cleaner)
                replacement = cleaner.policy.masking.mask_category("secret")
                rendered_item = repr(replacement)
            else:
                rendered_item = _render(
                    item,
                    cleaner,
                    nested=True,
                    depth=depth + 1,
                    active=active,
                )
            parts.append(f"{rendered_key}: {rendered_item}")
        return "{" + ", ".join(parts) + "}"
    finally:
        active.remove(value_id)


def _render_tuple(
    value: tuple[Any, ...],
    cleaner: Cleaner,
    *,
    depth: int,
    active: set[int],
) -> str:
    """Render a tuple with Python-compatible single-item syntax."""
    value_id = id(value)
    if value_id in active:
        return "(...)"

    active.add(value_id)
    try:
        parts = [
            _render(item, cleaner, nested=True, depth=depth + 1, active=active)
            for item in value
        ]
        suffix = "," if len(parts) == 1 else ""
        return "(" + ", ".join(parts) + suffix + ")"
    finally:
        active.remove(value_id)


def _render_list(
    value: list[Any],
    cleaner: Cleaner,
    *,
    depth: int,
    active: set[int],
) -> str:
    """Render a list without invoking element ``repr()`` methods."""
    value_id = id(value)
    if value_id in active:
        return "[...]"

    active.add(value_id)
    try:
        parts = [
            _render(item, cleaner, nested=True, depth=depth + 1, active=active)
            for item in value
        ]
        return "[" + ", ".join(parts) + "]"
    finally:
        active.remove(value_id)


def _render_set(
    value: Set[Any],
    cleaner: Cleaner,
    *,
    depth: int,
    active: set[int],
) -> str:
    """Render sets safely while preserving empty-set and frozenset notation."""
    value_id = id(value)
    if value_id in active:
        return "{...}"

    active.add(value_id)
    try:
        parts = sorted(
            _render(item, cleaner, nested=True, depth=depth + 1, active=active)
            for item in value
        )
        if isinstance(value, frozenset):
            if not parts:
                return "frozenset()"
            return "frozenset({" + ", ".join(parts) + "})"
        if not parts:
            return "set()"
        return "{" + ", ".join(parts) + "}"
    finally:
        active.remove(value_id)


def _render_sequence(
    value: Sequence[Any],
    cleaner: Cleaner,
    *,
    depth: int,
    active: set[int],
) -> str:
    """Render non-standard sequences as a safe list representation."""
    value_id = id(value)
    if value_id in active:
        return "[...]"

    active.add(value_id)
    try:
        parts = [
            _render(item, cleaner, nested=True, depth=depth + 1, active=active)
            for item in value
        ]
        return "[" + ", ".join(parts) + "]"
    finally:
        active.remove(value_id)


def _stringify_unknown(value: Any) -> str:
    """Convert an arbitrary object to text without allowing conversion failures to leak data."""
    try:
        return str(value)
    except Exception:
        return f"<unprintable {type(value).__name__}>"


def _is_sensitive_key(cleaner: Cleaner, key: object) -> bool:
    """Check a mapping key defensively because user-defined keys may raise in ``__str__``."""
    try:
        return cleaner.policy.is_sensitive_key(key)
    except Exception:
        return False


def _raise_if_credential_is_blocked(cleaner: Cleaner) -> None:
    """Honor production block mode for sensitive structured keys."""
    if "credential" in cleaner.policy.block_categories:
        raise LogBlockedError(
            "LogPrivacy blocked sensitive categories: credential",
            categories=("credential",),
        )
