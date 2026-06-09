# Structured traversal limits

LogPrivacy traverses dictionaries, lists, tuples, and other sequences with
explicit resource limits. The limits prevent recursive or extremely large input
from consuming unbounded CPU or memory.

```python
from dataclasses import replace

from logprivacy import Cleaner, CleanerPolicy

policy = replace(
    CleanerPolicy.default(),
    max_depth=20,
    max_items=10_000,
    max_findings=1_000,
)
cleaner = Cleaner(policy=policy)
```

The limits apply to one top-level `clean()` or `audit()` call:

- `max_depth` limits nested structured branches;
- `max_items` is a global budget for mapping entries and sequence items;
- `max_findings` caps findings retained by an audit report.

## Fail-closed cleaning

When a branch cannot be inspected safely, LogPrivacy does not return the
original uninspected value. It inserts an explicit safe marker:

- `[MAX_DEPTH]` when nesting exceeds `max_depth`;
- `[TRUNCATED]` when the global item budget is exhausted;
- `[RECURSIVE]` for a recursive container reference;
- `[UNAVAILABLE]` when safe iteration or representation fails.

## Incomplete audits

An audit report is safe only when the complete input was inspected and no
sensitive values were found.

```python
report = cleaner.audit(value)

report.safe         # False for incomplete audits
report.complete     # False when a limit or traversal failure occurred
report.truncated    # Convenience inverse of complete
report.limitations  # e.g. ("max_depth", "max_items")
```

An incomplete report uses the `unknown` risk level unless an already-detected
high-risk finding makes the level `high`. `assert_clean()` also rejects
incomplete audits.

Unknown mapping-key objects are never stringified. Their values are masked
fail-closed because their key representation cannot be trusted safely.
