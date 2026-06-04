import logging

from logcleaner import LogCleanerFilter, get_safe_logger


def test_logging_filter_cleans_rendered_message():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="email=%s password=%s",
        args=("john@example.com", "123"),
        exc_info=None,
    )

    LogCleanerFilter().filter(record)

    assert record.getMessage() == "email=[EMAIL] password=[SECRET]"
    assert record.args == ()


def test_get_safe_logger_adds_filter_once():
    logger = get_safe_logger("logcleaner-test")
    logger = get_safe_logger("logcleaner-test")
    filters = [item for item in logger.filters if isinstance(item, LogCleanerFilter)]
    assert len(filters) == 1
