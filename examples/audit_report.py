"""Inspect a value for sensitive data without modifying it."""

from logcleaner import audit

report = audit({"password": "hunter2", "email": "john@example.com", "status": "failed"})

print(report.safe)  # False
print(report.risk_level)  # high
print(report.categories)  # ('credential', 'email')
print(report.describe())
