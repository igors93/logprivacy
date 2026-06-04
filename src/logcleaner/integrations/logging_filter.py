"""Python logging filter that redacts sensitive data before emission."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from logcleaner.cleaner import Cleaner


@dataclass(slots=True)
class LogCleanerFilter(logging.Filter):
    """Logging filter that cleans the rendered log message."""

    cleaner: Cleaner = field(default_factory=Cleaner)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.cleaner.clean_text(record.getMessage())
        record.args = ()
        return True
