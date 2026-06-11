# LogPrivacy Documentation

LogPrivacy is a zero-dependency Python library that prevents accidental leaks of
sensitive data in logs, debug output, strings, dictionaries, files, and standard
Python logging records. It runs on Linux, macOS, and Windows and supports
Python 3.10–3.14.

---

## Guides

- [Getting started](guides/getting-started.md) — installation and first steps
- [Which API should I use?](guides/which-api.md) — decision guide for picking the right function

## Core concepts

- [Policies](core/policies.md) — built-in policies and how to compose them
- [Rules](core/rules.md) — built-in detection rules and how they work
- [Custom rules](core/custom-rules.md) — adding your own `CustomRegexRule`
- [Masking](core/masking.md) — placeholder, partial, hash, and HMAC masking styles

## Data and structured values

- [Audit](data/audit.md) — inspecting findings without modifying the input
- [Structured data](data/structured-data.md) — `to_safe_data()`, field rules, path rules, adapters, JSONL
- [Traversal limits](data/traversal-limits.md) — depth limits, fail-closed behavior, limitation codes

## Integrations

- [Logging](integrations/logging.md) — `get_safe_logger()` and `LogPrivacyFilter`
- [Logging integration](integrations/logging-integration.md) — `LogPrivacyFormatter` and advanced patterns

## Security

- [Security model](security/security-model.md) — what LogPrivacy protects against and what it does not

## Project

- [Project structure](project/project-structure.md) — source layout, module responsibilities
- [Quality](project/quality.md) — local setup, CI matrix (Linux / macOS / Windows, Python 3.10–3.14)
- [Release checklist](project/release-checklist.md) — step-by-step release process
- [Roadmap](project/roadmap.md) — planned areas
