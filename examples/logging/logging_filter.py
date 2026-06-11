import logging

from logprivacy import LogPrivacyFilter

logger = logging.getLogger("demo")
logger.setLevel(logging.INFO)
logger.addFilter(LogPrivacyFilter())
logger.addHandler(logging.StreamHandler())

logger.info("User %s used password=%s", "john@example.com", "123456")
