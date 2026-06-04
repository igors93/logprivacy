# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 - Unreleased

### Added

- `safe_print()` for safe terminal/debug output.
- `get_safe_logger()` for easy stdlib logging integration.
- `audit()` and `AuditReport` for inspecting sensitive findings.
- `assert_clean()` for CI/test safety.
- `clean_url()` for sanitizing sensitive URL query parameters.
- `scan_file()` and `clean_file()` for log files.
- CLI commands: `scan`, `clean`, and `text`.
- Partial and hash masking strategies.
- Block mode for selected sensitive categories.
- New rules for phone-like values and credit-card-like values.
- More tests, examples, docs, and quality scripts.

## 0.1.0 - Initial project

### Added

- Initial project structure.
- Text cleaning API.
- Modular redaction rules.
- Placeholder masking.
- Structured data cleaning.
- Python logging integration.
- Documentation and examples.
