from logcleaner import Cleaner, CleanerPolicy


def test_cleaner_cleans_text():
    assert Cleaner().clean_text("token=abc123456789") == "token=[SECRET]"


def test_cleaner_keeps_unknown_values_by_default():
    assert Cleaner().clean(123) == 123


def test_cleaner_can_clean_unknown_objects():
    cleaner = Cleaner(policy=CleanerPolicy(clean_unknown_objects=True))
    assert cleaner.clean("john@example.com") == "[EMAIL]"


def test_url_wins_over_email_inside_url():
    assert (
        Cleaner().clean_text("GET https://example.com/users?email=john@example.com") == "GET [URL]"
    )
