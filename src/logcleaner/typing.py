"""Shared type aliases used by LogCleaner."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypeAlias

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | Mapping[str, Any] | Sequence[Any]
SensitiveCategory: TypeAlias = str
