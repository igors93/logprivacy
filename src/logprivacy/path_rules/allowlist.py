"""Internal allowlist matching for structured traversal."""

from __future__ import annotations

from logprivacy.field_rules.rules import normalize_field_name

_TraversalPath = tuple[str | int, ...]


class _AllowlistMatcher:
    """Pre-compiled allowlist for fast field-path checking.

    Allowlist paths are dot-separated patterns that may use ``*`` as a
    single-segment wildcard: ``"orders.*.status"``.

    A field at path ``P`` is retained when:
    - ``P`` exactly matches an allowlist pattern, OR
    - ``P`` is a proper prefix of an allowlist pattern (meaning there is
      allowed content nested under ``P``).

    This ensures parent objects are preserved when any of their descendants
    are allowed.
    """

    __slots__ = ("_patterns",)

    def __init__(self, patterns: tuple[str, ...]) -> None:
        parsed: list[tuple[str, ...]] = []
        for pat in patterns:
            parsed.append(_parse_allowlist_path(pat))
        self._patterns: tuple[tuple[str, ...], ...] = tuple(parsed)

    def is_path_allowed(self, path: _TraversalPath) -> bool:
        """Return True if ``path`` is allowed or leads to allowed content.

        Returns False when no patterns are configured (empty allowlist rejects everything).
        The caller is responsible for checking whether an allowlist is active at all.
        """
        if not self._patterns:
            return False
        norm = _normalize_traversal_path(path)
        return any(_path_matches_or_prefixes_pattern(norm, pattern) for pattern in self._patterns)


def _normalize_traversal_path(path: _TraversalPath) -> tuple[str, ...]:
    result: list[str] = []
    for seg in path:
        if isinstance(seg, int):
            result.append(str(seg))
        else:
            result.append(normalize_field_name(seg))
    return tuple(result)


def _path_matches_or_prefixes_pattern(norm_path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    """Return True if norm_path matches pattern exactly or is a proper prefix of it."""
    plen = len(pattern)
    nlen = len(norm_path)
    if nlen > plen:
        return False
    for p_seg, n_seg in zip(pattern[:nlen], norm_path, strict=False):
        if p_seg == "*":
            continue
        if p_seg != n_seg:
            return False
    return True


def _parse_allowlist_path(path_str: str) -> tuple[str, ...]:
    """Parse 'error.type' -> ('error', 'type'), 'orders.*.status' -> ('orders', '*', 'status')."""
    if not path_str:
        raise ValueError("allowlist path must not be empty")
    if path_str.startswith(".") or path_str.endswith("."):
        raise ValueError(f"allowlist path {path_str!r} must not start or end with '.'")
    if ".." in path_str:
        raise ValueError(f"allowlist path {path_str!r} must not contain '..'")
    segments: list[str] = []
    for seg in path_str.split("."):
        if not seg:
            raise ValueError(f"empty segment in allowlist path {path_str!r}")
        if seg == "**":
            raise ValueError("'**' is not supported in allowlist paths; use '*'")
        if "*" in seg and seg != "*":
            raise ValueError(f"partial wildcard {seg!r} in allowlist path {path_str!r}")
        if seg == "*":
            segments.append("*")
        else:
            norm = normalize_field_name(seg)
            if not norm:
                raise ValueError(f"allowlist segment {seg!r} normalizes to empty string")
            segments.append(norm)
    return tuple(segments)
