# Quality Checks

Run locally on Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"

./scripts/ci.sh
```

Individual commands:

```bash
python3 -m ruff format .
python3 -m ruff format --check .
python3 -m ruff check .
python3 -m ruff check . --fix
python3 -m mypy src
python3 -m pytest
python3 -m build
```
