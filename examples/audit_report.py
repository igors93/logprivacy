from logcleaner import audit

report = audit("email=john@example.com password=123456")

print(report.describe())
print(report.summary())
