from logcleaner.masking.masks import keep_edges, mask_email


def test_keep_edges_masks_middle():
    assert keep_edges("abcdef") == "ab**ef"


def test_keep_edges_masks_short_values():
    assert keep_edges("abc") == "***"


def test_mask_email_keeps_domain():
    assert mask_email("john@example.com") == "j***@example.com"
