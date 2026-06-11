# Release checklist

Follow these steps to publish a new version of LogPrivacy.

---

## 1. Update the version

Edit the version in two places:

- `pyproject.toml` — `version = "X.Y.Z"`
- `src/logprivacy/__init__.py` — `__version__ = "X.Y.Z"`

Both values must match.

---

## 2. Update CHANGELOG.md

- Rename the `[Unreleased]` section to the new version and today's date
  (e.g. `## 0.6.0 - 2026-06-11`).
- Add a new empty `## [Unreleased]` section at the top.
- Group changes under: `Added`, `Changed`, `Fixed`, `Documentation`, `Tests`,
  `Security`.

---

## 3. Run the full CI pipeline locally

```bash
./scripts/ci.sh
```

This runs formatting, linting, type checks, tests, and a package build.
All steps must pass before continuing.

**Windows:** run each step individually or use Git Bash / WSL.

---

## 4. Confirm GitHub Actions is green

Push to a branch and open a pull request, or push directly to `main`.
Wait for all CI jobs (quality, tests on all platforms, build) to pass.

The matrix must be green on:

| OS | Python |
|---|---|
| Linux | 3.10, 3.11, 3.12, 3.13, 3.14 |
| macOS | 3.10, 3.11, 3.12, 3.13, 3.14 |
| Windows | 3.10, 3.11, 3.12, 3.13 |

---

## 5. Build the distribution

```bash
python3 -m build
```

This produces `dist/logprivacy-X.Y.Z.tar.gz` and
`dist/logprivacy-X.Y.Z-py3-none-any.whl`.

---

## 6. (Optional) Test the wheel install locally

```bash
python3 -m venv /tmp/lc-test-env
source /tmp/lc-test-env/bin/activate
pip install dist/logprivacy-X.Y.Z-py3-none-any.whl
python3 -c "import logprivacy; print(logprivacy.__version__)"
deactivate
```

---

## 7. Create a git tag

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

---

## 8. Create a GitHub Release

Go to the repository's Releases page and create a new release for the tag
`vX.Y.Z`. Publishing the release triggers the `publish.yml` workflow, which
runs the full quality gate, builds the package, verifies the wheel, and
publishes to PyPI using OIDC trusted publishing (no API token required).

---

## 9. Verify the install from PyPI

After the release is live (usually within a few minutes):

```bash
pip install logprivacy==X.Y.Z
python3 -c "import logprivacy; print(logprivacy.__version__)"
```

---

## Quick reference

| Step | Command |
|---|---|
| Format | `python -m ruff format .` |
| Lint | `python -m ruff check .` |
| Type check | `python -m mypy src` |
| Test | `python -m pytest -v` |
| Build | `python -m build` |
| Full pipeline | `./scripts/ci.sh` |
