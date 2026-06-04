"""IP address redaction rule."""

from __future__ import annotations

import re

from logcleaner.rules.base import RegexRedactionRule

_IPV4_PATTERN = r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)"


class IPAddressRule(RegexRedactionRule):
    """Detect IPv4 addresses."""

    def __init__(self) -> None:
        super().__init__(
            name="ip_address", category="ip_address", pattern=re.compile(_IPV4_PATTERN)
        )
