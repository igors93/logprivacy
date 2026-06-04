# LogCleaner

**Simple by default, powerful by composition, safe by guidance.**

LogCleaner is a privacy-first Python library that removes sensitive data from logs before they are printed, stored, or sent to monitoring tools.

It helps Python projects prevent accidental leaks of emails, passwords, API keys, bearer tokens, access tokens, secrets, sensitive URLs, and private values inside structured logs.

## Quick start

```python
from logcleaner import clean

message = "Login failed for john@example.com with password=123456"
print(clean(message))
```

Output:

```text
Login failed for [EMAIL] with password=[SECRET]
```

## Clean structured data

```python
from logcleaner import clean

payload = {
    "email": "john@example.com",
    "password": "123456",
    "status": "failed",
}

print(clean(payload))
```

Output:

```python
{
    "email": "[EMAIL]",
    "password": "[SECRET]",
    "status": "failed",
}
```

## Logging integration

```python
import logging
from logcleaner import LogCleanerFilter

logger = logging.getLogger("app")
logger.addFilter(LogCleanerFilter())

logger.warning("User john@example.com used token=abc123")
```

## Design goals

1. Simple things should be simple.
2. Advanced usage should be composable.
3. Logs should be safe by default.
4. Rules should be modular and easy to test.
5. Output should be predictable and explainable.
6. Runtime dependencies should stay at zero.

## Status

Early development. Public API may still evolve.

## Development checks

Install the project with development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the full local CI suite:

```bash
./scripts/ci.sh
```

Or run checks individually:

```bash
./scripts/format.sh       # format code with Ruff
./scripts/lint.sh         # run Ruff lint checks
./scripts/fix.sh          # format and apply safe Ruff fixes
./scripts/typecheck.sh    # run mypy on src/
./scripts/test.sh         # run pytest
./scripts/build.sh        # build the package
```

Equivalent Python commands:

```bash
python -m ruff format .
python -m ruff format --check .
python -m ruff check .
python -m ruff check . --fix
python -m mypy src
python -m pytest
python -m build
```

GitHub Actions runs the same quality checks automatically on pushes and pull requests to `main`.
