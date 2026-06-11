"""Drop-in replacement for print() that cleans values before printing."""

from logprivacy import safe_print

safe_print("User john@example.com used token=abc123456789")
# User [EMAIL] used token=[SECRET]

safe_print("payload:", {"password": "hunter2", "status": "ok"})
# payload: {'password': '[SECRET]', 'status': 'ok'}
