from logprivacy.audit import AuditReport
from logprivacy.result import Finding, RedactionResult


def _sensitive_finding() -> Finding:
    secret = "super-secret-token-12345"
    return Finding(
        rule_name="credential",
        category="token",
        start=0,
        end=len(secret),
        matched=secret,
        replacement="[TOKEN]",
        reason="authorization header contains a sensitive credential",
        metadata={"scheme": "Bearer", "value": secret},
    )


def test_finding_repr_never_exposes_match_metadata_or_replacement() -> None:
    finding = _sensitive_finding()

    rendered = repr(finding)

    assert "super-secret-token-12345" not in rendered
    assert "[TOKEN]" not in rendered
    assert "metadata" not in rendered
    assert "category='token'" in rendered
    assert "has_replacement=True" in rendered


def test_finding_to_dict_is_safe_by_default() -> None:
    finding = _sensitive_finding()

    serialized = finding.to_dict()

    assert "matched" not in serialized
    assert "metadata" not in serialized
    assert serialized["category"] == "token"
    assert serialized["replacement"] == "[TOKEN]"


def test_finding_to_dict_requires_explicit_opt_in_for_sensitive_details() -> None:
    finding = _sensitive_finding()

    serialized = finding.to_dict(include_match=True, include_metadata=True)

    assert serialized["matched"] == "super-secret-token-12345"
    assert serialized["metadata"]["value"] == "super-secret-token-12345"


def test_audit_report_repr_is_safe() -> None:
    report = AuditReport((_sensitive_finding(),))

    rendered = repr(report)

    assert "super-secret-token-12345" not in rendered
    assert "value" not in rendered
    assert "safe=False" in rendered
    assert "risk_level='high'" in rendered
    assert "finding_count=1" in rendered
    assert "categories=('token',)" in rendered


def test_redaction_result_repr_is_safe() -> None:
    secret = "super-secret-token-12345"
    result = RedactionResult(
        original=f"Authorization: Bearer {secret}",
        cleaned="Authorization: Bearer [TOKEN]",
        findings=(_sensitive_finding(),),
    )

    rendered = repr(result)

    assert secret not in rendered
    assert "Authorization" not in rendered
    assert "[TOKEN]" not in rendered
    assert "changed=True" in rendered
    assert "finding_count=1" in rendered
    assert "categories=('token',)" in rendered


def test_safe_objects_are_also_safe_when_converted_to_string() -> None:
    finding = _sensitive_finding()
    report = AuditReport((finding,))
    result = RedactionResult(
        original=finding.matched,
        cleaned="[TOKEN]",
        findings=(finding,),
    )

    assert finding.matched not in str(finding)
    assert finding.matched not in str(report)
    assert finding.matched not in str(result)
