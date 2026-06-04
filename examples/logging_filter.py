import logging
from logcleaner import LogCleanerFilter

logger = logging.getLogger("demo")
logger.setLevel(logging.INFO)
logger.addFilter(LogCleanerFilter())
logger.addHandler(logging.StreamHandler())
logger.info("User %s used password=%s", "john@example.com", "123456")
