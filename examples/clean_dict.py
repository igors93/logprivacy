"""Clean a dictionary — sensitive keys are fully redacted, other values are scanned."""

from logcleaner import clean

payload = {
    "email": "john@example.com",
    "password": "hunter2",
    "status": "failed",
    "metadata": {
        "ip": "192.168.1.10",
        "attempt": 3,
    },
}

print(clean(payload))
# {
#   "email": "[EMAIL]",
#   "password": "[SECRET]",
#   "status": "failed",
#   "metadata": {"ip": "192.168.1.10", "attempt": 3},
# }
