import logging
from logcleaner import LogCleanerFilter

def test_logging_filter_cleans_rendered_message():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "email=%s password=%s", ("john@example.com", "123"), None)
    LogCleanerFilter().filter(record)
    assert record.getMessage() == "email=[EMAIL] password=[SECRET]"
    assert record.args == ()
