# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## 0.6.0 - 2026-06-11

### Added

- CI matrix now covers **Linux, macOS, and Windows** across Python 3.10–3.14,
  ensuring the library works on all supported platforms and interpreter versions.
- Python 3.13 and 3.14 added to the test matrix and to the
  `Programming Language :: Python` PyPI classifiers across all platforms.
- Post-build wheel smoke-test in CI and publish workflows: the built wheel is
  installed into a clean virtual environment and `logprivacy.__version__` is
  verified before publishing.

### Changed

- `pyproject.toml` classifier updated from `Development Status :: 3 - Alpha`
  to `Development Status :: 4 - Beta`.
- Added `Operating System :: OS Independent`, `Topic :: Security`, and
  `Topic :: System :: Logging` classifiers.
- CI test job renamed from `Tests on Python ${{ matrix.python-version }}` to
  `Tests — Python ${{ matrix.python-version }} on ${{ matrix.os }}` to make
  the matrix dimension visible in the GitHub Actions UI.
- `pytest` invocation in CI now uses `-v --tb=short` for clearer failure output.

---

## 0.5.3 - Unreleased

### Added

- `PathRule` — path-based privacy rules matching full traversal paths such as
  `"account.balance"` or `"orders.*.order_id"` (exact and glob modes). Takes
  precedence over `FieldRule`, `sensitive_keys`, and the allowlist.
- `HMACMaskingStrategy` — deterministic pseudonymization via HMAC-SHA256.
  Key must be `bytes`; it is never stored in `repr`, exceptions, or
  serialization. Token format: `[CATEGORY:hmac:hexdigest]`.
- `pseudonymize` action for `FieldRule` and `PathRule`; requires
  `policy.with_pseudonymizer(HMACMaskingStrategy(key=...))`.
- `CleanerPolicy.allow_paths(*paths)` — opt-in allowlist: any field whose path
  is not covered (directly or as a parent) is removed. Parent nodes leading to
  allowed fields are preserved. Values of allowed fields are still sanitized.
- `CleanerPolicy.add_path_rules()`, `with_path_rules()`, `with_pseudonymizer()`.
- `CleanerPolicy.from_dict()`, `to_dict()`, `from_json()`, `to_json()` for
  schema-version-1 declarative policies. Keys for HMAC are never serialized.
- JSONL streaming: `safe_jsonl_write()`, `iter_safe_jsonl()`, `clean_jsonl()`,
  `scan_jsonl()`. `clean_jsonl` writes atomically via a temp file and
  `os.replace`; the original file is never partially overwritten on failure.
- `JSONLRecord`, `JSONLResult`, `JSONLStats`, `JSONLScanRecord` result types.
- `PolicyConfigurationError`, `JSONLProcessingError`,
  `PseudonymizationConfigurationError` error types.
- `SafeDataStats` fields: `path_rule_matches`, `not_allowed`, `pseudonymized`.

### Changed

- Allowlist removal (`not_allowed`) does NOT set `complete=False`; it is an
  intentional policy decision, not a traversal failure.
- Structured traversal precedence is now explicit:
  `block` → `PathRule` → `FieldRule` → `sensitive_keys` → `allowlist` →
  `text sanitization`.

### Security

- HMAC key is excluded from `repr`, `str`, `to_dict`, and `to_json`.
- `clean_jsonl` uses atomic rename; a failed write leaves the original intact.
- Allowlist defaults to inactive — adding one is an explicit opt-in.

## 0.5.2 - Unreleased

### Fixed

- `truncate` field rule now sanitizes the full text before cutting to `max_chars`,
  preventing secrets from surviving as partial fragments after truncation.
- `FieldRule.exact` and `FieldRule.contains` now reject match strings that normalize
  to an empty string (e.g. `"---"`, `"___"`), preventing accidental wildcard matching.
- `FieldRule.regex` now rejects an empty regex string at construction time.
- Field rules now apply to `type` and `message` fields produced when an exception
  is sanitized, providing the same protection as mappings and dataclasses.
- Adapter resolution now guards against `__instancecheck__` raising; such types are
  treated as non-matching instead of propagating the error.
- Converters that raise or return the original object now fail closed, recording an
  `adapter_error` limitation and returning an `[UNSUPPORTED:TypeName]` placeholder
  without exposing the original value.

### Changed

- Built-in types handled by the core pipeline (`str`, `int`, `dict`, `list`, etc.)
  are now reserved and cannot be registered as adapter targets. Registering them
  raises `ValueError`. Custom subclasses (e.g. `class ExternalList(list)`) remain
  fully supported.
- `Cleaner` now builds the text pipeline (`TextScanner`, `FindingResolver`,
  `TextRedactor`) once in `__post_init__` rather than on every call, improving
  throughput for repeated use of the same instance.
- `to_safe_data()` now delegates to `to_safe_data_with_result()` and returns
  `result.cleaned`; its observable behavior is unchanged.

### Added

- `to_safe_data_with_result()` — returns a `SafeDataResult` with the sanitized
  value plus completeness, limitations, and per-call stats.
- `SafeDataResult` — immutable dataclass: `cleaned`, `complete`, `limitations`,
  `stats`.
- `SafeDataStats` — immutable dataclass of aggregate counters: `masked`, `removed`,
  `truncated`, `unsupported`, `adapter_errors`, `field_rule_matches`.
- `LIMIT_ADAPTER_ERROR`, `LIMIT_UNSUPPORTED_TYPE`, `LIMIT_RECURSIVE` constants
  exported from `logprivacy.internal.traversal` for stable limitation identifiers.

## 0.5.1 - 2026-06-04

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
- Public `JSONScalar` and `JSONValue` aliases for JSON-safe data.
- `to_safe_data()` for recursive, fail-closed structured sanitization that
  returns only JSON-safe values.
- `AdapterRegistry` for custom type conversion before sanitization.
- `FieldRule` / `FieldAction` support for structured field masking, removal,
  truncation, and blocking.
- `safe_json_dumps()` and `safe_json_dump()` for JSON serialization that always
  sanitizes before encoding.

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
- Documentation and examples are organized into topical folders instead of
  flat root-level file lists.
- Implementation was moved out of large package `__init__.py` files into
  named modules such as `cleaner/engine.py`, `files/operations.py`, and
  `safe_data/normalization.py`.
- Local `.env` files are ignored to reduce the risk of committing secrets.

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
