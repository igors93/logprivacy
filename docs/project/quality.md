# Quality Checks

## Setup

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run the full pipeline

```bash
./scripts/ci.sh
```

On Windows, run each command individually (see below) or use Git Bash / WSL.

## Individual commands

```bash
python -m ruff format .          # format code
python -m ruff check . --fix     # lint and auto-fix
python -m ruff format --check .  # verify formatting
python -m ruff check .           # lint only
python -m mypy src               # type check
python -m pytest -v              # run tests
python -m build                  # build distribution
```

## CI matrix

GitHub Actions runs the full test suite across:

| OS | Python versions |
|---|---|
| Linux (ubuntu-latest) | 3.10, 3.11, 3.12, 3.13, 3.14 |
| macOS (macos-latest) | 3.10, 3.11, 3.12, 3.13, 3.14 |
| Windows (windows-latest) | 3.10, 3.11, 3.12, 3.13 |

Quality checks (formatting, lint, type check) run on Python 3.12 on Linux
before the test matrix starts. The build job runs after all tests pass and
verifies the wheel installs cleanly into a fresh virtual environment.

Python 3.14 uses `allow-prereleases: true` in the setup action. Windows support
for 3.14 is added when it reaches GA.
