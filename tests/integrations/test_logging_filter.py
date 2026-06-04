import logging

from logprivacy import Cleaner, CleanerPolicy, LogPrivacyFilter, get_safe_logger


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

    LogPrivacyFilter().filter(record)

    assert record.getMessage() == "email=[EMAIL] password=[SECRET]"
    assert record.args == ()


def test_logging_filter_clears_args_after_cleaning():
    """Args must be cleared so the formatter cannot re-apply unclean values."""
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="user=%s",
        args=("john@example.com",),
        exc_info=None,
    )
    LogPrivacyFilter().filter(record)
    assert record.args == ()


def test_get_safe_logger_adds_filter_once():
    logger = get_safe_logger("logprivacy-test-once")
    get_safe_logger("logprivacy-test-once")
    filters = [f for f in logger.filters if isinstance(f, LogPrivacyFilter)]
    assert len(filters) == 1


def test_get_safe_logger_replaces_filter_when_policy_given():
    logger = get_safe_logger("logprivacy-test-policy")
    original_filters = [f for f in logger.filters if isinstance(f, LogPrivacyFilter)]
    assert len(original_filters) == 1
    original_cleaner = original_filters[0].cleaner  # type: ignore[union-attr]

    strict_policy = CleanerPolicy.strict()
    get_safe_logger("logprivacy-test-policy", policy=strict_policy)

    updated_filters = [f for f in logger.filters if isinstance(f, LogPrivacyFilter)]
    assert len(updated_filters) == 1
    assert updated_filters[0].cleaner is not original_cleaner  # type: ignore[union-attr]


def test_get_safe_logger_without_policy_keeps_existing_filter():
    first_cleaner = Cleaner(policy=CleanerPolicy.strict())
    logger = logging.getLogger("logprivacy-test-keep")
    for f in list(logger.filters):
        logger.removeFilter(f)
    logger.addFilter(LogPrivacyFilter(cleaner=first_cleaner))

    get_safe_logger("logprivacy-test-keep")

    filters = [f for f in logger.filters if isinstance(f, LogPrivacyFilter)]
    assert len(filters) == 1
    assert filters[0].cleaner is first_cleaner  # type: ignore[union-attr]
