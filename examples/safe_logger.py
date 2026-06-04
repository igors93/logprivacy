import logging

from logcleaner import get_safe_logger

logging.basicConfig(level=logging.INFO)
logger = get_safe_logger(__name__)

logger.info("User john@example.com used password=123456")
