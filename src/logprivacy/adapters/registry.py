"""Public adapter registry for custom structured-data conversion."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeAlias

AdapterConverter: TypeAlias = Callable[[object], object]


@dataclass(slots=True)
class AdapterRegistry:
    """Registry mapping Python types to converters used by ``to_safe_data()``.

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

        The converter result is never trusted directly; it is fed back through
        the normal sanitization pipeline.
        """
        if not isinstance(value_type, type):
            raise TypeError("adapter type must be a type")
        if value_type is object:
            raise ValueError("adapter type cannot be object")
        if not callable(converter):
            raise TypeError("adapter converter must be callable")
        self._converters[value_type] = converter
        return self

    def resolve(self, value: object) -> AdapterConverter | None:
        """Return the best converter for ``value`` or ``None``.

        Resolution prefers the concrete class, then base classes in MRO order,
        then registered abstract or virtual base classes in registration order.
        """
        value_type = type(value)
        for candidate in value_type.__mro__:
            converter = self._converters.get(candidate)
            if converter is not None:
                return converter

        for registered_type, converter in self._converters.items():
            if isinstance(value, registered_type):
                return converter
        return None
