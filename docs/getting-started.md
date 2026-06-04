# Getting Started

```python
from logcleaner import clean

clean("email=john@example.com password=123")
```

For logging:

```python
from logcleaner import get_safe_logger

logger = get_safe_logger(__name__)
logger.info("password=123")
```

For tests:

```python
from logcleaner import assert_clean

assert_clean("operation completed")
```
