# Masking

LogCleaner supports three built-in masking styles:

- `placeholder`: replaces values with `[EMAIL]`, `[SECRET]`, `[TOKEN]`
- `partial`: keeps a small amount of shape for debugging
- `hash`: uses a stable short SHA-256 hash for correlation

```python
from logcleaner import Cleaner, CleanerPolicy

Cleaner(CleanerPolicy.default(masking="partial"))
Cleaner(CleanerPolicy.default(masking="hash"))
```
