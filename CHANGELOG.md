# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 - Unreleased

### Changed

- Finalized the public package name as `logprivacy` (previously `logcleaner`, which was unavailable on PyPI).

### Added

- `safe_print()` for safe terminal and debug output.
- `get_safe_logger()` for easy stdlib logging integration.
- `audit()` and `AuditReport` for inspecting sensitive findings without modifying the input.
- `assert_clean()` for CI and test safety gates.
- `clean_url()` for sanitizing sensitive URL query parameters while keeping safe context readable.
- `scan_file()` and `clean_file()` for scanning and cleaning log files.
- CLI commands: `scan`, `clean`, and `text`.
- Partial masking strategy (preserves value shape, e.g. `j***@example.com`).
- Hash masking strategy (stable short SHA-256 prefix, e.g. `[EMAIL:855f96e9]`).
- Block mode: `CleanerPolicy.production()` raises `LogBlockedError` for high-risk categories.
- `CreditCardRule` with Luhn validation to reduce false positives.
- `PhoneRule` for phone-number-like value detection (strict mode).
- `IPAddressRule` for IPv4 address detection (strict mode).
- `CleanerPolicy.web()` focused on HTTP access log patterns.
- `explain()` for a human-readable breakdown of what would be redacted and why.
- `RedactionResult` and `Finding` as rich result types with metadata.
- `LogPrivacyFormatter` as an alternative logging integration.

### Changed

- `audit()` now traverses dicts, lists, and tuples recursively instead of
  falling back to `repr()`. Sensitive dictionary keys are reported as
  `credential` findings even when the value does not match a text pattern.
- `clean_url()` now returns human-readable placeholders (`[SECRET]`, `[EMAIL]`)
  instead of percent-encoded values (`%5BSECRET%5D`). Output is intended for
  display and logging, not round-trip URL parsing.
- `get_safe_logger()` now accepts an explicit `policy` argument to replace an
  existing filter. Calling it again without a policy reuses the existing filter
  without adding a duplicate.
- `CleanerPolicy` factory docstrings expanded to describe what each policy
  detects and when to use it.

### Fixed

- `clean_url()` was URL-encoding placeholder tokens in query parameter values,
  making the output unreadable in logs.

### Documentation

- README rewritten with a quick-start table, badges, policy comparison table,
  and a security disclaimer.
- New `docs/which-api.md`: decision guide for picking the right function.
- New `docs/policies.md`: explanation of all four built-in policies.
- New `docs/release-checklist.md`: step-by-step release process.
- `docs/security-model.md` rewritten: what LogPrivacy protects against, what
  it does not, and the right mental model for using it.

### Tests

- Fixed `test_clean_url_preserves_safe_query_params` to match the corrected
  human-readable output.
- Added tests for `clean_url()` edge cases (no params, safe-only params, non-URL input).
- Added tests for `audit()` with dicts, lists, tuples, and nested structures.
- Added tests for `assert_clean()` with structured data.
- Added tests for `get_safe_logger()` policy replacement and filter deduplication.
- Added `tests/test_realworld.py` covering end-to-end realistic scenarios:
  %-style logger args, mixed URL params, file cleaning, production policy blocking,
  partial and hash masking, and structured audit.

## 0.1.0 - Initial project

### Added

- Initial project structure.
- Text cleaning API (`clean()`, `clean_text()`, `clean_with_result()`).
- Modular redaction rules: email, credential, token, secret, URL.
- Placeholder masking strategy.
- Structured data cleaning for dicts, lists, and tuples.
- Python logging integration via `LogPrivacyFilter`.
- Documentation and examples.
