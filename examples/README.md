# LogPrivacy Examples

Runnable examples are grouped by use case so related workflows stay together.

- `basics/`: first examples and the complete showcase.
- `audit/`: `audit()` and `assert_clean()` workflows.
- `files/`: log file scanning and cleaning.
- `logging/`: standard-library logging integrations.
- `output/`: terminal/debug output such as `safe_print()`.
- `policies/`: policy presets and stricter configurations.
- `rules/`: custom rule examples.
- `structured/`: dictionaries and structured payloads.
- `url/`: URL sanitization.

From a source checkout, run examples with paths such as:

```bash
python examples/basics/basic_clean.py
python examples/basics/logprivacy_showcase.py
python examples/logging/safe_logger.py
```
