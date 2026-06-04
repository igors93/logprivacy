# Security model

LogCleaner is a safety net that reduces the risk of accidental sensitive-data
exposure in logs. Understanding what it protects against — and what it does not
— is important before relying on it in a production system.

---

## What LogCleaner protects against

LogCleaner is designed to catch **accidental leaks** — the kind that happen when
a developer prints a payload, logs an exception that contains a user object, or
passes a dictionary to a logger without reviewing its contents.

It detects and masks:

- Email addresses
- Credential patterns (`password=…`, `api_key=…`, etc.)
- Bearer tokens and JWTs
- API secrets and access keys
- HTTP URLs (configurable)
- Credit-card-like values (validated with the Luhn algorithm)
- IPv4 addresses *(strict mode)*
- Phone-number-like values *(strict mode)*

It works with raw strings, dictionaries, lists, and tuples, and integrates with
Python's standard `logging` module without replacing it.

---

## What LogCleaner does not protect against

LogCleaner is **not** a data-loss prevention (DLP) system. It does not:

- **Guarantee complete anonymization.** Regex-based detection has false
  negatives — novel secret formats, obfuscated values, or custom encodings may
  not be detected.
- **Prevent intentional exfiltration.** It is not designed to stop a malicious
  actor who controls the code.
- **Replace secret management.** Secrets should not enter your application as
  plain strings if they do not need to. Use environment variables, secret stores,
  or key-management services instead of embedding secrets in objects that get
  logged.
- **Replace encryption or access control.** Log files that contain masked values
  should still be access-controlled.
- **Replace legal privacy review.** Compliance with GDPR, HIPAA, PCI-DSS, or
  other regulations requires a legal assessment that goes beyond log redaction.

---

## False positives and false negatives

Regex-based detection is a trade-off:

- **False positives:** a value that looks like a credit card number but is not
  one (for example, a numeric product ID) may be redacted. Luhn validation
  reduces this for credit cards, but other rules can still over-match.
- **False negatives:** a secret that does not match any known pattern will not
  be detected. For example, a short random string used as a password will not
  be caught unless it appears next to a keyword like `password=`.

Use `audit()` and `assert_clean()` in tests to catch problems early and
calibrate your policy.

---

## The right mental model

Think of LogCleaner as a **seatbelt**, not a firewall.

- It should not be the only control that prevents sensitive data from appearing
  in logs.
- The first control is **not logging sensitive data in the first place**: avoid
  passing request bodies, user objects, or exception payloads directly to a
  logger.
- LogCleaner is the second control: it catches what slips through.
- `CleanerPolicy.production()` is the third control: it raises an exception
  when a blocked category is detected, turning a silent leak into a loud failure.

Using LogCleaner is not permission to log sensitive data carelessly.
