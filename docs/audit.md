# Auditing sensitive data

`audit()` inspects text and structured values without modifying the input. Every
finding includes a safe, human-readable `location`.

```python
from logprivacy import audit

report = audit(
    {
        "user": {
            "email": "john@example.com",
            "credentials": {"password": "demo-secret"},
        }
    }
)

print(report.locations)
# ('$.user.email', '$.user.credentials.password')

print(report.details())
# Safe per-finding metadata; matched values are not included.
```

Locations use a JSONPath-like form:

- `$` is the audited root value;
- `$.user.email` identifies mapping keys;
- `$.users[2]` identifies sequence indexes;
- unusual or sanitized keys use bracket notation, such as `$["[EMAIL]"]`.

`scan_file()` reports the sanitized file name, one-based line number, and
one-based character column:

```python
from logprivacy import scan_file

report = scan_file("application.log")
print(report.locations)
# ('application.log:14:8',)
```

Only the file name is included, not its absolute directory path. File names and
mapping keys are sanitized before they are placed in a report. `repr()`,
`summary()`, `details()`, and `describe()` do not include matched sensitive
values.

## Safe location formatting

Location components are bounded and encoded before they are exposed. Quotes and
backslashes use JSON escaping, while control and Unicode formatting characters
are rendered as inert escape sequences. Repeated findings at the same source
location appear only once in `report.locations`; per-finding entries remain
available through `report.details()`.

Location formatting never relies on arbitrary mapping-key `__str__()` or
`__repr__()` implementations. Unknown key objects are represented by a sanitized
type label instead.
