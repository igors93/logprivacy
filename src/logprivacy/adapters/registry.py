"""Public adapter registry for custom structured-data conversion."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeAlias

AdapterConverter: TypeAlias = Callable[[object], object]

_SAFE_TYPE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")

# Types handled directly by the core pipeline; adapters must not override them.
_RESERVED_TYPES: frozenset[type[object]] = frozenset(
    {
        object,
        str,
        int,
        float,
        bool,
        bytes,
        bytearray,
        memoryview,
        dict,
        list,
        tuple,
        set,
        frozenset,
    }
)


def _safe_adapter_type_name(value: object) -> str:
    name = type(value).__name__ or "object"
    safe = _SAFE_TYPE_NAME_PATTERN.sub("_", name)[:80]
    return safe or "object"


@dataclass(slots=True)
class AdapterRegistry:
    """Registry mapping Python types to converters used by ``to_safe_data()``.

    Adapters are intended for application classes, external library types, and
    custom subclasses.  Built-in types handled directly by the core pipeline
    (``str``, ``int``, ``dict``, ``list``, etc.) are reserved and cannot be
    registered.  A custom subclass such as ``class ExternalList(list)`` *can*
    be registered; ``list`` itself cannot.

    ``default()`` returns a fresh registry so applications and tests can add
    converters without mutating shared global state.
    """

    _converters: dict[type[object], AdapterConverter] = field(default_factory=dict)

    @classmethod
    def default(cls) -> AdapterRegistry:
        """Return a new registry with the built-in core behavior."""
        return cls()

    def copy(self) -> AdapterRegistry:
        """Return an independent copy of this registry."""
        return AdapterRegistry(dict(self._converters))

    def register(self, value_type: type[object], converter: AdapterConverter) -> AdapterRegistry:
        """Register ``converter`` for ``value_type`` and return this registry.

        Raises ``TypeError`` when ``value_type`` is not a type or ``converter``
        is not callable.  Raises ``ValueError`` when ``value_type`` is one of
        the built-in types reserved for the core pipeline.

        The converter result is never trusted directly; it is fed back through
        the normal sanitization pipeline.
        """
        if not isinstance(value_type, type):
            raise TypeError("adapter type must be a type")
        if not callable(converter):
            raise TypeError("adapter converter must be callable")
        if value_type in _RESERVED_TYPES:
            raise ValueError(
                f"adapter type cannot be a reserved built-in type: {value_type.__name__!r}. "
                "Register a custom subclass instead."
            )
        self._converters[value_type] = converter
        return self

    def resolve(self, value: object) -> AdapterConverter | None:
        """Return the best converter for ``value`` or ``None``.

        Resolution order:
        1. Concrete type registered directly.
        2. Base classes in MRO order, most specific first.
        3. Abstract / virtual base classes in registration order.

        ``__instancecheck__`` calls are protected; a metaclass that raises
        during ``isinstance`` is treated as non-matching.
        """
        value_type = type(value)
        for candidate in value_type.__mro__:
            converter = self._converters.get(candidate)
            if converter is not None:
                return converter

        for registered_type, converter in self._converters.items():
            try:
                matches = isinstance(value, registered_type)
            except Exception:
                matches = False
            if matches:
                return converter
        return None
