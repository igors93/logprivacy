from logcleaner.rules import UrlRule

def test_url_rule_finds_url():
    findings = UrlRule().find("GET https://example.com/path?token=abc")
    assert len(findings) == 1
    assert findings[0].category == "url"
