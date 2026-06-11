# Project Structure

LogPrivacy keeps implementation code under `src/logprivacy/`, tests under
`tests/`, documentation under `docs/`, and runnable examples under `examples/`.
Public module names such as `logprivacy.policy` and `logprivacy.cleaner` are
preserved as packages, so imports stay stable while the repository remains
easier to scan.

## Source Layout

```text
src/logprivacy/
  __init__.py
  __main__.py
  py.typed
  adapters/
  api/
  audit/
  cleaner/
  exceptions/
  field_rules/
  files/
  integrations/
  internal/
  json/
  masking/
  policy/
  result/
  rule_sets/
  rules/
  safe_data/
  structured/
  typing/
  url/
```

## Responsibilities

- `api/`: small public convenience functions such as `clean()` and `safe_print()`.
- `cleaner/`: core cleaning engine.
- `policy/`: immutable policy configuration and composition helpers.
- `rules/`: individual text redaction rules.
- `rule_sets/`: built-in rule presets.
- `masking/`: placeholder, partial, and hash masking strategies.
- `structured/`: structured traversal helpers for existing `clean()` behavior.
- `safe_data/`: JSON-safe normalization used by `to_safe_data()`.
- `field_rules/`: structured field matching and actions.
- `adapters/`: public custom type conversion registry.
- `json/`: safe JSON serialization APIs.
- `audit/` and `result/`: public report/result objects.
- `files/` and `url/`: file and URL helpers.
- `integrations/`: optional integration code.
- `internal/`: private helpers that are not public API.

## Package File Convention

`__init__.py` files should stay thin. They exist to define the public import
surface for a package, not to hold large implementation code.

Implementation should live in clearly named files:

```text
adapters/registry.py
api/public.py
audit/report.py
cleaner/engine.py
exceptions/errors.py
field_rules/rules.py
files/operations.py
json/serialization.py
policy/config.py
result/types.py
safe_data/normalization.py
typing/aliases.py
url/cleaning.py
```

For example, maintenance work on file cleaning belongs in
`files/operations.py`; `files/__init__.py` should only reexport
`scan_file()` and `clean_file()` so existing imports remain stable.

## Test Layout

```text
tests/
  api/
  audit/
  core/
  files/
  integrations/
  masking/
  output/
  rules/
  structured/
  url/
```

Tests are grouped by behavior instead of living as many files in the root. New
tests should usually go into the folder matching the feature area they cover.

## Documentation Layout

```text
docs/
  README.md
  core/
  data/
  guides/
  integrations/
  project/
  security/
```

- `guides/`: entry-point docs such as getting started and API selection.
- `core/`: concepts that define normal library use: policies, rules, masking,
  and custom rules.
- `data/`: audit, structured data, JSON-safe data, and traversal behavior.
- `integrations/`: logging and integration-oriented documentation.
- `security/`: threat model and safety boundaries.
- `project/`: maintainer docs such as structure, quality, roadmap, and release
  checklist.

## Example Layout

```text
examples/
  README.md
  audit/
  basics/
  files/
  logging/
  output/
  policies/
  rules/
  structured/
  url/
```

Examples are grouped by use case. New examples should go into the narrowest
folder that matches the workflow they demonstrate.
