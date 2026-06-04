"""Python logging formatter that redacts the final formatted message."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from logprivacy.cleaner import Cleaner


@dataclass(slots=True)
class LogPrivacyFormatter(logging.Formatter):
    """Formatter that cleans the final formatted output."""

    cleaner: Cleaner = field(default_factory=Cleaner)

    def format(self, record: logging.LogRecord) -> str:
        """Format and then clean the log output."""
        return self.cleaner.clean_text(super().format(record))
