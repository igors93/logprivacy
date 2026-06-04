# Logging Integration

Use `get_safe_logger()` for the simplest path:

```python
from logcleaner import get_safe_logger

logger = get_safe_logger(__name__)
```

Or add a filter manually:

```python
import logging
from logcleaner import LogCleanerFilter

logger = logging.getLogger(__name__)
logger.addFilter(LogCleanerFilter())
```
