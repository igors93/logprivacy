from logprivacy import clean_with_result


def test_result_summary_is_safe():
    result = clean_with_result("john@example.com password=123")
    summary = result.summary()
    assert summary["changed"] is True
    assert summary["finding_count"] == 2
    assert summary["counts"]["email"] == 1
    assert summary["counts"]["credential"] == 1


def test_result_explain_no_findings():
    result = clean_with_result("hello world")
    assert result.explain() == "LogPrivacy found no sensitive values."
