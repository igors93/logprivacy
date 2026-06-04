#!/usr/bin/env bash
set -euo pipefail

python3 -m ruff format .
python3 -m ruff check . --fix
