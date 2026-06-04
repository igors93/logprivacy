"""Use assert_clean() in tests to catch sensitive-data leaks early."""

from logprivacy import LogPrivacyAssertionError, assert_clean

# Passes silently when the value is safe
assert_clean("operation completed successfully")
assert_clean({"username": "john", "status": "active"})

# Raises LogPrivacyAssertionError when sensitive data is found
try:
    assert_clean({"password": "hunter2"})
except LogPrivacyAssertionError as exc:
    print(exc)
    # Sensitive data found: credential
