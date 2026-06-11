# Structured Data

LogPrivacy has two structured-data APIs:

- `clean()` keeps the simple historical behavior for strings, dictionaries,
  lists, and tuples.
- `to_safe_data()` converts supported Python values into sanitized JSON-safe
  data: `None`, booleans, finite numbers, strings, lists, and dictionaries with
  string keys.
- `to_safe_data_with_result()` does the same and additionally returns completeness
  metadata, limitation identifiers, and per-call statistics.

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

### Dispatch Order

Adapter resolution runs **before** the built-in structural handlers for
`Mapping`, `list`/`tuple`, and `set`/`frozenset`. This means a custom subclass
registered in the adapter registry always takes precedence over the native
fallback, even if the subclass inherits from a built-in container type.

Dispatch order within `_normalize`:

1. Exact primitive types: `None`, `bool`, `int`, `float`, `str`, `bytes`,
   `bytearray`, `memoryview` — always handled by the core pipeline, never
   intercepted by adapters.
2. Adapter registry — MRO lookup first (no `isinstance`), then virtual/abstract
   types (protected `isinstance` calls).
3. Structural fallbacks — `str` subclasses, `Mapping`, `list`/`tuple`,
   `set`/`frozenset`, dataclasses, `Enum`, `Decimal`, date/time types, `UUID`,
   `Path`, exceptions.
4. Unsupported — becomes `[UNSUPPORTED:TypeName]`.

### Reserved Types

The following types are reserved for the core pipeline and cannot be used as
adapter targets. Attempting to register them raises `ValueError`:

`object`, `str`, `int`, `float`, `bool`, `bytes`, `bytearray`, `memoryview`,
`dict`, `list`, `tuple`, `set`, `frozenset`.

Custom subclasses are fully supported:

```python
class ExternalList(list):
    pass

adapters.register(ExternalList, lambda v: {"items": list(v), "source": "external"})
```

### Adapter Failures

If a converter raises, returns the original object, or if `__instancecheck__`
raises during virtual-type resolution, the value becomes
`[UNSUPPORTED:TypeName]` and `adapter_error` is added to limitations. The
original value is never exposed.

Converters are never called on reserved primitive types regardless of how the
registry was configured.

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

## Path Rules

`PathRule` matches the full traversal path, not just the field name. This lets
you target a field in a specific context:

```python
from logprivacy import CleanerPolicy, PathRule, to_safe_data

# "balance" inside "account" → remove; "balance" elsewhere → untouched
policy = CleanerPolicy.default().add_path_rules(
    PathRule.exact("account.balance", action="remove"),
)

to_safe_data(
    {"strategy": {"balance": 1000}, "account": {"balance": 25000}},
    policy=policy,
)
# {"strategy": {"balance": 1000}, "account": {"balance": "[REMOVED]"}}
```

Use `PathRule.glob` with a `*` wildcard to match any single segment:

```python
policy = CleanerPolicy.default().add_path_rules(
    PathRule.glob("orders.*.order_id", action="mask"),
)
```

**Precedence:** `PathRule` takes priority over `FieldRule`, `sensitive_keys`,
and the allowlist. The full precedence order is:
`block` → `PathRule` → `FieldRule` → `sensitive_keys` → `allowlist` →
`text sanitization`.

**Supported actions:** `mask`, `remove`, `truncate`, `block`, `pseudonymize`.

### Path Syntax

- Segments are separated by `.`.
- `*` matches exactly one segment in glob mode (not allowed in exact mode).
- `**` and partial wildcards (`q*`, `*.json`) are not supported.
- Empty segments, leading/trailing dots, and double dots are rejected.

```python
PathRule.exact("account.balance")         # exact two-segment path
PathRule.glob("orders.*.quantity")        # any order's quantity field
PathRule.glob("events.*.metadata.token")  # deeper nesting
```

Field name segments use the same normalization as `FieldRule`: camelCase is
split, separators are unified, case is folded. List indices match as their
string representation (`"0"`, `"1"`), or via `*` in glob mode.

## Actions

Both `FieldRule` and `PathRule` support these actions:

- `mask`: replace the value using the policy masking strategy;
- `remove`: replace the value with `[REMOVED]` (key is kept);
- `truncate`: sanitize the **full** text first, then cut to `max_chars` and
  append `[TRUNCATED]` if needed. This order ensures secrets after the cut
  point are never exposed.
- `block`: raise `LogBlockedError` without including the blocked value.
- `pseudonymize`: replace the value with a deterministic HMAC token (requires
  `policy.with_pseudonymizer(HMACMaskingStrategy(key=...))`).

`truncate` is limited to textual values (`str`, `bytes`, `bytearray`, and
`memoryview`). Non-text values become `[TRUNCATED]`.

### Field Rules on Exceptions

Field rules (and path rules) apply to the `type` and `message` fields produced
when an exception is sanitized:

```python
from logprivacy import CleanerPolicy, FieldRule, to_safe_data

policy = CleanerPolicy.default().add_field_rules(
    FieldRule.exact("message", action="remove"),
)

to_safe_data(ValueError("secret token: abc123"), policy=policy)
# {"type": "ValueError", "message": "[REMOVED]"}
```

## Pseudonymization

`HMACMaskingStrategy` replaces identifiers with deterministic correlation
tokens. The same key + value + category always produces the same token; rotate
the key to invalidate all existing tokens.

**This is pseudonymization, not anonymization.** A party with the key can
re-derive any token from the original value.

```python
from logprivacy import CleanerPolicy, HMACMaskingStrategy, PathRule, to_safe_data

key = b"your-secret-key-at-least-16-bytes"
policy = (
    CleanerPolicy.default()
    .add_path_rules(PathRule.glob("orders.*.order_id", action="pseudonymize", category="order_id"))
    .with_pseudonymizer(HMACMaskingStrategy(key=key))
)

to_safe_data({"orders": [{"order_id": "ORD-1234", "amount": 99.0}]}, policy=policy)
# {"orders": [{"order_id": "[ORDER_ID:hmac:a3b2c1d4e5f6]", "amount": 99.0}]}
```

The HMAC key never appears in `repr`, `str`, exceptions, `to_dict`, or `to_json`.

## Allowlist

When an allowlist is configured, any field whose path is not in the allowlist
(and does not lead to an allowed field) is removed from the output. Values of
allowed fields are still sanitized.

```python
from logprivacy import CleanerPolicy, to_safe_data

policy = CleanerPolicy.default().allow_paths(
    "event_type",
    "timestamp",
    "error.type",  # "error" parent is preserved automatically
)

to_safe_data(
    {"event_type": "login", "timestamp": "2026-01-01", "error": {"type": "ValueError", "message": "secret"}},
    policy=policy,
)
# {"event_type": "login", "timestamp": "2026-01-01", "error": {"type": "ValueError"}}
```

The allowlist supports `*` wildcards for single-segment matching:

```python
policy = CleanerPolicy.default().allow_paths("orders.*.status")
```

**Precedence:** PathRule and FieldRule actions still apply to allowed fields.
A `block` PathRule or FieldRule on an allowed field raises `LogBlockedError`.
Allowlist removal does **not** set `result.complete = False`; it is an
intentional policy decision, not a traversal failure.

The `stats.not_allowed` counter tracks how many fields were removed by the
allowlist.

## Rich Output with SafeDataResult

Use `to_safe_data_with_result()` when you need to know whether sanitization was
complete, which limits were reached, or how many fields were redacted:

```python
from logprivacy import to_safe_data_with_result

result = to_safe_data_with_result(payload)

if not result.complete:
    logger.warning("partial sanitization: %s", result.limitations)

log_event(result.cleaned)
```

`SafeDataResult` fields:

- `cleaned` — the sanitized value, equivalent to `to_safe_data(payload)`;
- `complete` — `False` when any traversal limit was reached or any branch could
  not be fully inspected;
- `limitations` — a tuple of stable string identifiers for each limit hit:
  `max_depth`, `max_items`, `iteration_error`, `representation_error`,
  `adapter_error`, `unsupported_type`, `recursive_value`;
- `stats` — a `SafeDataStats` dataclass with aggregate counters.

`SafeDataStats` fields:

| Field | Counts |
|---|---|
| `masked` | text findings redacted by the text pipeline plus structural mask actions and sensitive-key masking |
| `removed` | fields replaced with `[REMOVED]` by a `remove` rule |
| `truncated` | fields truncated by a `truncate` rule |
| `unsupported` | values replaced with `[UNSUPPORTED:TypeName]` |
| `adapter_errors` | converters that raised, returned self, or had `__instancecheck__` raise during resolution |
| `field_rule_matches` | total `FieldRule` matches across all fields |
| `path_rule_matches` | total `PathRule` matches across all fields |
| `not_allowed` | fields removed by the allowlist |
| `pseudonymized` | fields pseudonymized with `HMACMaskingStrategy` |

Both `SafeDataResult` and `SafeDataStats` are frozen dataclasses. Neither retains
any reference to the original value or raw converter output.

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

## Safe JSONL

Process JSON Lines files without loading the whole file into memory:

```python
from pathlib import Path
from logprivacy.jsonl import safe_jsonl_write, iter_safe_jsonl, clean_jsonl, scan_jsonl

# Write one sanitized record
with open("out.jsonl", "w") as f:
    safe_jsonl_write({"email": "user@example.com", "action": "login"}, f)

# Read and sanitize a JSONL file line by line
for record in iter_safe_jsonl(Path("events.jsonl"), on_error="skip"):
    print(record.line_number, record.result.cleaned)

# Clean a JSONL file atomically (temp file → os.replace)
result = clean_jsonl(Path("raw.jsonl"), output=Path("clean.jsonl"))
print(result.stats.lines_written)

# Scan for sensitive data without modifying
for scan_record in scan_jsonl(Path("events.jsonl")):
    print(scan_record.line_number, scan_record.findings)
```

`on_error` controls how invalid JSON lines are handled:
- `"raise"` — raise `JSONLProcessingError` (never includes the raw line);
- `"skip"` — silently omit the bad line;
- `"placeholder"` — emit `{"_logprivacy_error": "invalid_json", "_line": N}`.

`clean_jsonl` writes atomically: a temp file is created in the same directory,
then `os.replace` performs an atomic rename. If any step fails, the temp file
is removed and the original is untouched.

## Declarative Policies

Policies can be serialized to and from JSON for configuration files or sharing
across services:

```python
from logprivacy import CleanerPolicy

policy = CleanerPolicy.from_json("""
{
  "schema_version": 1,
  "base": "strict",
  "field_rules": [{"match": "password", "mode": "exact", "action": "mask"}],
  "path_rules": [{"path": "account.balance", "mode": "exact", "action": "remove"}],
  "allowlist": {"paths": ["timestamp", "event_type"]}
}
""")

# Export back
config_json = policy.to_json(sort_keys=True)
```

HMAC keys are **never** serialized. A policy that uses `pseudonymize` records
only the action and category; the key must be injected separately via
`policy.with_pseudonymizer(HMACMaskingStrategy(key=...))`.

Schema version 1 supports: `base`, `field_rules`, `path_rules`, `allowlist`.
Unknown fields, unknown bases, unknown actions, and unknown modes are rejected
with a `PolicyConfigurationError`.

## Limitations

Not implemented: JSONPath, `**` wildcards, YAML, Pydantic, attrs, Structlog,
Loguru, OpenTelemetry, plugins, or domain-specific rule packs. Adapters are
explicit and local to the registry you pass.
