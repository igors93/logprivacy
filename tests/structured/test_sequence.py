from logcleaner import clean


def test_list_is_cleaned():
    assert clean(["john@example.com", "ok"]) == ["[EMAIL]", "ok"]


def test_tuple_is_preserved():
    assert clean(("john@example.com", "ok")) == ("[EMAIL]", "ok")
