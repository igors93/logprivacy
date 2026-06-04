#!/usr/bin/env bash
set -euo pipefail

python3 -m ruff format --check .
python3 -m ruff check .
python3 -m mypy src
python3 -m pytest
python3 -m build
