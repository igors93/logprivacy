"""Email redaction rule."""

from __future__ import annotations

import re

from logcleaner.rules.base import RegexRedactionRule

_EMAIL_PATTERN = (
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])"
)


class EmailRule(RegexRedactionRule):
    """Detect email addresses."""

    def __init__(self) -> None:
        super().__init__(name="email", category="email", pattern=re.compile(_EMAIL_PATTERN))
