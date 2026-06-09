# Masking

LogPrivacy supports three built-in masking styles:

- `placeholder`: replaces values with `[EMAIL]`, `[SECRET]`, or `[TOKEN]`
- `partial`: keeps a small amount of shape for debugging
- `hash`: creates a stable pseudonymous token for correlation

```python
from logprivacy import Cleaner, CleanerPolicy

partial = Cleaner(CleanerPolicy.default(masking="partial"))
unkeyed_hash = Cleaner(CleanerPolicy.default(masking="hash"))
```

## Keyed hash masking

For production correlation, provide a secret key and use HMAC-SHA-256:

```python
from logprivacy import Cleaner, CleanerPolicy, HashMaskingStrategy

strategy = HashMaskingStrategy(
    key=b"replace-with-at-least-16-secret-bytes",
    length=16,
)
policy = CleanerPolicy.default(masking=strategy)
cleaner = Cleaner(policy=policy)

print(cleaner.clean_text("password=demo-secret"))
# password=[SECRET:...]
```

The same key and input produce the same token. Different keys produce different
tokens, which prevents correlation across environments that use separate keys.
Store the key in a secret manager or environment-specific configuration; do not
commit it to source control.

Hash masking is **pseudonymization, not anonymization**. Low-entropy values may
still be guessed if unkeyed hashing is used. The string shortcut
`masking="hash"` remains deterministic for compatibility, but keyed HMAC is the
recommended production configuration.

The default output contains 16 hexadecimal digest characters. Values from 12 to
64 characters are accepted. `salt` remains available only for compatibility
with earlier releases and cannot be combined with `key`.
