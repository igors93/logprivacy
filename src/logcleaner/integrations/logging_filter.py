"""Python logging filter that redacts sensitive data before emission."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from logcleaner.cleaner import Cleaner
from logcleaner.exceptions import LogBlockedError


@dataclass(slots=True)
class LogCleanerFilter(logging.Filter):
    """
    Logging filter that cleans the rendered log message.

    It sets record.msg to the cleaned message and clears record.args so the
    standard logging formatter does not re-apply unsafe interpolation.
    """

    cleaner: Cleaner = field(default_factory=Cleaner)
    drop_blocked: bool = True

    def filter(self, record: logging.LogRecord) -> bool:
        """Clean the log record and allow it to be emitted."""
        try:
            record.msg = self.cleaner.clean_text(record.getMessage())
        except LogBlockedError:
            if self.drop_blocked:
                return False
            raise
        record.args = ()
        return True
