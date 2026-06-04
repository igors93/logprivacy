"""Use assert_clean() in tests to catch sensitive-data leaks early."""

from logcleaner import LogCleanerAssertionError, assert_clean

# Passes silently when the value is safe
assert_clean("operation completed successfully")
assert_clean({"username": "john", "status": "active"})

# Raises LogCleanerAssertionError when sensitive data is found
try:
    assert_clean({"password": "hunter2"})
except LogCleanerAssertionError as exc:
    print(exc)
    # Sensitive data found: credential
