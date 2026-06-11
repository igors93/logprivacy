# Structured Data

LogPrivacy has two structured-data APIs:

- `clean()` keeps the simple historical behavior for strings, dictionaries,
  lists, and tuples.
- `to_safe_data()` converts supported Python values into sanitized JSON-safe
  data: `None`, booleans, finite numbers, strings, lists, and dictionaries with
  string keys.

Use `to_safe_data()` before structured logging, JSON responses, JSON files, or
anywhere arbitrary Python objects must not escape into output.

```python
from logprivacy import to_safe_data

to_safe_data({"email": "john@example.com", "password": "123"})
# {"email": "[EMAIL]", "password": "[SECRET]"}
```

## Supported Types

`to_safe_data()` supports these types without runtime dependencies:

- `None`, `bool`, `int`, finite `float`, and `str`;
- `dict` and other mappings;
- `list`, `tuple`, `set`, and `frozenset`;
- `bytes`, `bytearray`, and `memoryview`;
- dataclass instances;
- `Enum`;
- `Decimal`;
- `datetime`, `date`, and `time`;
- `UUID`;
- `Path`;
- exceptions.

Sets are returned as deterministically ordered lists when possible. Tuples are
returned as lists because JSON has no tuple type. `Decimal` values are returned
as strings to avoid precision loss.

Non-finite numbers such as `NaN`, `Infinity`, and `-Infinity` become
`[NON_FINITE_NUMBER]`.

## Fail-Closed Behavior

`to_safe_data()` never returns arbitrary unsupported objects. Unknown objects
become a placeholder such as `[UNSUPPORTED:CustomType]`.

When traversal cannot inspect a branch safely, LogPrivacy uses explicit safe
markers:

- `[MAX_DEPTH]` when nesting exceeds `policy.max_depth`;
- `[TRUNCATED]` when `policy.max_items` is exhausted;
- `[RECURSIVE]` for recursive structures;
- `[UNAVAILABLE]` when iteration or representation fails.

Mapping keys are converted to sanitized strings. If two keys collide after
conversion, deterministic suffixes such as `#2` preserve both entries.
Unknown mapping-key objects are treated fail-closed and their values are masked.

## Adapters

Use `AdapterRegistry` to teach LogPrivacy how to convert custom application
types. Adapter output is not trusted; it always goes back through sanitization.

```python
from logprivacy import AdapterRegistry, to_safe_data

class Request:
    def __init__(self, identifier: str, metadata: dict[str, object]) -> None:
        self.identifier = identifier
        self.metadata = metadata

adapters = AdapterRegistry.default()
adapters.register(
    Request,
    lambda value: {"identifier": value.identifier, "metadata": value.metadata},
)

to_safe_data(Request("req-1", {"token": "abc123456789"}), adapters=adapters)
# {"identifier": "req-1", "metadata": {"token": "[SECRET]"}}
```

`AdapterRegistry.default()` returns a fresh registry. Registering a converter in
one registry does not mutate another registry or global process state.

## Field Rules

`CleanerPolicy.sensitive_keys` is still supported. For more control, add
structured field rules:

```python
from logprivacy import CleanerPolicy, FieldRule, to_safe_data

policy = CleanerPolicy.default().add_field_rules(
    FieldRule.exact("password", action="mask"),
    FieldRule.contains("secret", action="remove"),
    FieldRule.regex(r".*_raw$", action="truncate", max_chars=500),
)

to_safe_data({"clientSecret": "value", "body_raw": "password=123"}, policy=policy)
# {"clientSecret": "[REMOVED]", "body_raw": "password=[SECRET]"}
```

Field names are normalized before matching: surrounding spaces are trimmed,
case is folded, camelCase boundaries are split, and spaces, hyphens, and
underscores are treated as the same separator.

Explicit field rules are evaluated in declaration order. If no field rule
matches, legacy `sensitive_keys` masking is applied.

## Actions

Field rules support four actions:

- `mask`: replace the value using the policy masking strategy;
- `remove`: keep the field but replace the value with `[REMOVED]`;
- `truncate`: keep only `max_chars` from textual values, then sanitize that
  preserved text;
- `block`: raise `LogBlockedError` without including the blocked value.

In this phase, `truncate` is intentionally limited to textual values
(`str`, `bytes`, `bytearray`, and `memoryview`). Non-text values become
`[TRUNCATED]`.

## Safe JSON

`safe_json_dumps()` and `safe_json_dump()` call `to_safe_data()` before using
Python's JSON encoder.

```python
from logprivacy import safe_json_dumps

safe_json_dumps({"email": "john@example.com", "password": "123"}, sort_keys=True)
# '{"email": "[EMAIL]", "password": "[SECRET]"}'
```

The JSON APIs reject `default=` so callers cannot bypass sanitization with
`default=str`. They force `allow_nan=False`; non-finite numbers are normalized
before serialization.

## Larger Example

```python
from dataclasses import dataclass
from pathlib import Path

from logprivacy import CleanerPolicy, FieldRule, safe_json_dumps

@dataclass
class JobEvent:
    job_id: str
    raw_payload: str
    output_path: Path

policy = CleanerPolicy.default().add_field_rules(
    FieldRule.exact("raw_payload", action="truncate", max_chars=100),
)

event = JobEvent(
    job_id="job-42",
    raw_payload="password=secret123 status=failed",
    output_path=Path("/tmp/job-42"),
)

safe_json_dumps(event, policy=policy)
# '{"job_id": "job-42", "raw_payload": "password=[SECRET] status=failed", ...}'
```

## Limitations

This phase does not implement JSONPath rules, JSONL helpers, Pydantic, attrs,
Structlog, Loguru, OpenTelemetry, rule packs, or framework-specific behavior.
Adapters are explicit and local to the registry you pass.
