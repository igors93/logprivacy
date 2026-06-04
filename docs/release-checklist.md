# Release checklist

Follow these steps to publish a new version of LogCleaner.

---

## 1. Update the version

Edit the version in two places:

- `pyproject.toml` — `version = "X.Y.Z"`
- `src/logcleaner/__init__.py` — `__version__ = "X.Y.Z"`

Both values must match.

---

## 2. Update CHANGELOG.md

- Rename the `Unreleased` section to the new version and today's date.
- Add a new empty `Unreleased` section at the top.
- Group changes under: `Added`, `Changed`, `Fixed`, `Documentation`, `Tests`.

---

## 3. Run the full CI pipeline locally

```bash
./scripts/ci.sh
```

This runs formatting, linting, type checks, tests, and a package build.
All steps must pass before continuing.

---

## 4. Confirm GitHub Actions is green

Push to a branch and open a pull request, or push directly to `main`.
Wait for all CI jobs (quality, tests, build) to pass on GitHub Actions.

---

## 5. Build the distribution

```bash
python3 -m build
```

This produces `dist/logcleaner-X.Y.Z.tar.gz` and `dist/logcleaner-X.Y.Z-py3-none-any.whl`.

---

## 6. (Optional) Test the wheel install locally

```bash
python3 -m venv /tmp/lc-test-env
source /tmp/lc-test-env/bin/activate
pip install dist/logcleaner-X.Y.Z-py3-none-any.whl
python3 -c "import logcleaner; print(logcleaner.__version__)"
deactivate
```

---

## 7. Create a git tag

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

---

## 8. Publish the release

```bash
python3 -m twine upload dist/*
```

You will need a PyPI API token configured in `~/.pypirc` or as an environment
variable.

---

## 9. Verify the install from PyPI

After the release is live (usually within a few minutes):

```bash
pip install logcleaner==X.Y.Z
python3 -c "import logcleaner; print(logcleaner.__version__)"
```

---

## Quick reference

| Step | Command |
|---|---|
| Format | `python3 -m ruff format .` |
| Lint | `python3 -m ruff check .` |
| Type check | `python3 -m mypy src` |
| Test | `python3 -m pytest` |
| Build | `python3 -m build` |
| Full pipeline | `./scripts/ci.sh` |
| Publish | `python3 -m twine upload dist/*` |
