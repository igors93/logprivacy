# Custom Rules

```python
from logcleaner import Cleaner, CleanerPolicy, CustomRegexRule

rule = CustomRegexRule(
    name="employee_id",
    category="employee",
    pattern=r"EMP-\d{6}",
)

cleaner = Cleaner(CleanerPolicy.default().add_rules(rule))
```
