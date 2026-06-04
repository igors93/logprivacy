# Which API should I use?

A quick guide to picking the right LogPrivacy function for your situation.

---

## "I have a string that might contain sensitive data"

Use **`clean()`**.

```python
from logprivacy import clean

message = "Login failed for john@example.com with password=hunter2"
print(clean(message))
# Login failed for [EMAIL] with password=[SECRET]
```

`clean()` also accepts dicts, lists, and tuples — it traverses them recursively.

---

## "I use print() while debugging"

Use **`safe_print()`**.

```python
from logprivacy import safe_print

safe_print("token=abc123456789", {"password": "hunter2"})
# token=[SECRET] {'password': '[SECRET]'}
```

`safe_print()` is a drop-in replacement for `print()` that cleans values before
printing. It accepts `sep` and `end` just like the built-in.

---

## "I use Python's logging module"

Use **`get_safe_logger()`**.

```python
import logging
from logprivacy import get_safe_logger

logging.basicConfig(level=logging.INFO)
logger = get_safe_logger(__name__)

logger.info("User %s logged in with password=%s", "john@example.com", "hunter2")
# INFO User [EMAIL] logged in with password=[SECRET]
```

`get_safe_logger()` returns a standard `logging.Logger` with a cleaning filter
attached. You can use it everywhere you would use `logging.getLogger()`.

---

## "I want to check if a value contains sensitive data before logging it"

Use **`audit()`**.

```python
from logprivacy import audit

report = audit({"password": "hunter2", "user": "john"})

if not report.safe:
    print(f"Risk: {report.risk_level}")   # "high"
    print(f"Found: {report.categories}")  # ("credential",)
```

`audit()` never modifies the input. It works on strings, dicts, lists, and tuples.

---

## "I want my tests to fail when a secret appears in a log message"

Use **`assert_clean()`**.

```python
from logprivacy import assert_clean

def test_response_is_safe():
    response = {"username": "john", "status": "active"}
    assert_clean(response)  # passes

def test_no_password_in_error_message():
    msg = "Operation completed. User: john."
    assert_clean(msg)  # passes
```

`assert_clean()` raises `LogPrivacyAssertionError` (a subclass of `AssertionError`)
if sensitive data is found. Works on strings and structured values.

---

## "I need to clean a URL but keep the useful parts"

Use **`clean_url()`**.

```python
from logprivacy import clean_url

url = "https://api.example.com/search?q=python&page=1&token=abc123&api_key=xyz"
print(clean_url(url))
# https://api.example.com/search?q=python&page=1&token=[SECRET]&api_key=[SECRET]
```

`clean_url()` keeps the scheme, host, path, and safe query parameters visible.
Only known sensitive parameter names are redacted.

---

## "I need to clean an old log file"

Use **`clean_file()`** to write a cleaned copy, or **`scan_file()`** to get a
report without modifying the file.

```python
from logprivacy import scan_file, clean_file

# Check first
report = scan_file("app.log")
print(report.describe())

# Then clean
clean_file("app.log", output="app.clean.log")
```

---

## "I want more control over what gets detected"

Create a `Cleaner` with a custom `CleanerPolicy`.

```python
from logprivacy import Cleaner, CleanerPolicy

# Strict: also detects IP addresses and phone numbers
cleaner = Cleaner(policy=CleanerPolicy.strict())

# Custom: only detect emails
from logprivacy import EmailRule
cleaner = Cleaner(policy=CleanerPolicy.default().with_rules(EmailRule()))
```

See [policies.md](policies.md) for a full description of built-in policies.
