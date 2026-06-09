# Bounded logging sanitization

`LogPrivacyFilter` sanitizes the complete `logging.LogRecord` before a handler
formats or emits it. Besides the rendered message, it protects positional and
named format arguments, exception text, stack information, and user-provided
`extra` attributes.

## Structured values

Nested dictionaries, tuples, lists, and other sequences are traversed with the
same policy limits used by `Cleaner`:

- `max_depth` limits nesting;
- `max_items` is shared across the structured values in one record;
- text generated from structured values is bounded;
- recursive containers produce `[RECURSIVE]`;
- exhausted item budgets produce `[TRUNCATED]`;
- failed iteration or representation produces `[UNAVAILABLE]`.

Uninspected source branches are never copied into the sanitized record.

```python
import logging
from dataclasses import replace

from logprivacy import Cleaner, CleanerPolicy, LogPrivacyFilter

policy = replace(CleanerPolicy.default(), max_depth=10, max_items=1_000)
handler = logging.StreamHandler()
handler.addFilter(LogPrivacyFilter(cleaner=Cleaner(policy=policy)))
```

## Safe mapping keys

Arbitrary mapping-key objects are not retained because a later formatter could
invoke their `__repr__()` and disclose data. Unknown keys are replaced with a
sanitized type label, their values are masked fail-closed, and collisions are
preserved with deterministic suffixes such as `#2` and `#3`.

Named interpolation dictionaries keep trusted built-in keys until the message is
rendered, so formats such as `%(user)s` continue to work. The original arguments
are cleared immediately after rendering.

## Compact and hostile values

Exact `range` objects remain compact instead of being expanded. Numeric
subclasses, sets, custom objects, and other unsupported values are converted
through the bounded safe renderer. Conversion and iteration failures do not
propagate their exception messages into logs.

Messages with malformed or truncated format arguments fall back to a sanitized
message template rather than exposing the original values or crashing the
handler.

## Blocking policies

Production blocking remains unchanged. If a configured blocked category is
found, `drop_blocked=True` drops the record and `drop_blocked=False` raises
`LogBlockedError`.
