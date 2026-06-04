# Structured Data

LogPrivacy cleans dictionaries, lists, and tuples recursively.

```python
from logprivacy import clean

clean({"email": "john@example.com", "password": "123"})
```

Sensitive keys such as `password`, `token`, and `api_key` have their values fully redacted.
