import pytest

from logcleaner import Cleaner, CleanerPolicy, LogBlockedError


def test_cleaner_cleans_text():
    cleaner = Cleaner()
    assert cleaner.clean_text("token=abc123456789") == "token=[SECRET]"


def test_cleaner_keeps_unknown_values_by_default():
    cleaner = Cleaner()
    assert cleaner.clean(123) == 123


def test_cleaner_can_clean_unknown_objects():
    cleaner = Cleaner(policy=CleanerPolicy(clean_unknown_objects=True))
    assert cleaner.clean("john@example.com") == "[EMAIL]"


def test_url_wins_over_email_inside_url():
    cleaner = Cleaner()
    text = "GET https://example.com/users?email=john@example.com"
    assert cleaner.clean_text(text) == "GET [URL]"


def test_block_mode_raises_for_blocked_category():
    cleaner = Cleaner(policy=CleanerPolicy.default().block("credential"))
    with pytest.raises(LogBlockedError):
        cleaner.clean_text("password=123")


def test_explain_describes_redaction():
    cleaner = Cleaner()
    explanation = cleaner.explain("password=123")
    assert "credential" in explanation
    assert "password" in explanation
