from logcleaner.masking.masks import keep_edges


def test_keep_edges_masks_middle():
    assert keep_edges("abcdef") == "ab**ef"


def test_keep_edges_masks_short_values():
    assert keep_edges("abc") == "***"
