"""Convenience masking helpers."""
from __future__ import annotations

def keep_edges(value: str, *, left: int = 2, right: int = 2, fill: str = "*") -> str:
    """Mask the middle of a value while keeping its edges."""
    if len(value) <= left + right:
        return fill * len(value)
    return f"{value[:left]}{fill * (len(value) - left - right)}{value[-right:]}"
