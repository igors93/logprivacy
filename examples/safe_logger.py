"""Python logging integration with automatic sensitive-data cleaning."""

import logging

from logprivacy import get_safe_logger

logging.basicConfig(level=logging.INFO)
logger = get_safe_logger(__name__)

logger.info("User %s logged in", "john@example.com")
# INFO User [EMAIL] logged in

logger.warning("Auth failed: password=%s", "hunter2")
# WARNING Auth failed: password=[SECRET]
