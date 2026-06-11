# Policies

A `CleanerPolicy` controls which rules are active, how findings are masked, and
what happens when a blocked category is detected.

Use one of the built-in factory methods as a starting point, then compose
further with `add_rules()`, `with_masking()`, or `block()`.

---

## CleanerPolicy.default()

**Best for:** general-purpose log cleaning.

Detects emails, credential key=value pairs, bearer tokens, API secrets, HTTP
URLs, and credit-card-like values (using Luhn validation to reduce false
positives).

```python
from logprivacy import clean, CleanerPolicy

clean("email=john@example.com password=hunter2")
# "email=[EMAIL] password=[SECRET]"
```

This is the policy used by `clean()`, `safe_print()`, and `get_safe_logger()`
when no explicit policy is provided.

---

## CleanerPolicy.strict()

**Best for:** environments where IP addresses and phone numbers must not appear
in logs.

Extends `default()` by adding:

- IPv4 address detection (`192.168.1.1` → `[IP_ADDRESS]`)
- Phone-number-like value detection

```python
from logprivacy import Cleaner, CleanerPolicy

cleaner = Cleaner(policy=CleanerPolicy.strict())
cleaner.clean("client_ip=192.168.1.10 email=john@example.com")
# "client_ip=[IP_ADDRESS] email=[EMAIL]"
```

Use strict mode for internal services where IP addresses are considered
operational data, or in any context subject to privacy regulations that treat
device identifiers as personal data.

---

## CleanerPolicy.web()

**Best for:** HTTP access log cleaning.

Focuses on web-specific patterns: URLs, credential key=value pairs, bearer
tokens, and API secrets. Does not include email, credit card, IP address, or
phone rules, which produce more false positives in high-volume request logs.

```python
from logprivacy import Cleaner, CleanerPolicy

cleaner = Cleaner(policy=CleanerPolicy.web())
cleaner.clean("GET /v1/users?token=abc123 HTTP/1.1")
# "GET /v1/users?token=[SECRET] HTTP/1.1"
```

---

## CleanerPolicy.production()

**Best for:** CI pipelines and production safety gates.

Extends `strict()` and **raises a `LogBlockedError`** when a credential, token,
secret, or credit-card-like value is detected, instead of silently masking it.

Use this when you want your application to fail loudly if sensitive data reaches
a log statement rather than quietly replace it.

```python
from logprivacy import Cleaner, CleanerPolicy, LogBlockedError

cleaner = Cleaner(policy=CleanerPolicy.production())

try:
    cleaner.clean("password=hunter2")
except LogBlockedError as exc:
    print(exc)
    # LogPrivacy blocked sensitive categories: credential
```

A `LogBlockedError` is typically a programming error: it means some code is
attempting to log data that should never be logged at all.

---

## Composing policies

All policies are immutable. Every method returns a new policy object.

```python
from logprivacy import CleanerPolicy, EmailRule

# Add a rule on top of default
policy = CleanerPolicy.default().add_rules(EmailRule())

# Replace all rules
policy = CleanerPolicy.default().with_rules(EmailRule())

# Change masking strategy
policy = CleanerPolicy.default(masking="partial")
policy = CleanerPolicy.strict().with_masking("hash")

# Block additional categories
policy = CleanerPolicy.default().block("email")

# Disable specific categories
policy = CleanerPolicy.strict().without_categories("ip_address")
```

---

## Masking strategies

All policies support three masking modes via the `masking` parameter or
`with_masking()`.

| Mode | Example output | When to use |
|---|---|---|
| `"placeholder"` | `[EMAIL]` | Default; readable and safe |
| `"partial"` | `j***@example.com` | When preserving shape helps debugging |
| `"hash"` | `[EMAIL:855f96e9]` | When correlating across log lines without exposing values |

The partial strategy keeps a few characters from the start and end of the
matched value. The hash strategy produces a stable short SHA-256 prefix so you
can find related entries across a log file without seeing the original value.

---

## Sensitive keys in structured data

When `clean()` or `audit()` traverses a dictionary, keys listed in
`policy.sensitive_keys` trigger full redaction of the corresponding value
without inspecting its content.

Default sensitive keys include: `password`, `passwd`, `pwd`, `secret`,
`token`, `api_key`, `apikey`, `access_key`, `access_token`, `refresh_token`,
`client_secret`, `private_key`, `authorization`, `cookie`, `set-cookie`.
