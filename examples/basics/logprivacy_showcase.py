"""Standalone showcase for the public LogPrivacy API.

This example is not part of the library internals. It uses fictional values,
creates files only inside a temporary directory, and can be executed directly
from a source checkout:

    python examples/basics/logprivacy_showcase.py
"""

from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIRECTORY = PROJECT_ROOT / "src"

if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

import logprivacy as lp  # noqa: E402

DEMO_EMAIL = "john@example.com"
DEMO_PASSWORD = "demo-password-123"
DEMO_TOKEN = "abcdefgh1234567890"


def print_section(title: str) -> None:
    """Print a visual separator between examples."""
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def demonstrate_text_cleaning() -> None:
    """Clean common sensitive values from unstructured text."""
    print_section("1. Text cleaning")
    examples = (
        f"email={DEMO_EMAIL} password={DEMO_PASSWORD}",
        f"Authorization: Bearer {DEMO_TOKEN}",
        "Authorization: Basic dXNlcjpwYXNz",
        "api_key=sk_live_12345678901234567890",
        "card=4111 1111 1111 1111",
        "This line is safe",
    )

    for original in examples:
        print(f"Input:  {original}")
        print(f"Output: {lp.clean_text(original)}")
        print("-" * 44)


def demonstrate_structured_cleaning() -> None:
    """Clean nested mappings, lists, and tuples."""
    print_section("2. Structured data cleaning")
    payload = {
        "user": {
            "email": DEMO_EMAIL,
            "password": DEMO_PASSWORD,
        },
        "authorization": f"Bearer {DEMO_TOKEN}",
        "events": ["completed", "contact@example.com"],
    }

    print("Original:")
    print(payload)
    print("\nCleaned:")
    print(lp.clean(payload))


def demonstrate_masking_strategies() -> None:
    """Compare placeholder, partial, and stable hash masking."""
    print_section("3. Masking strategies")
    text = f"password={DEMO_PASSWORD} Authorization: Bearer {DEMO_TOKEN}"

    for name in ("placeholder", "partial", "hash"):
        policy = lp.CleanerPolicy.default(masking=name)
        print(f"{name.title():12} {lp.clean_text(text, policy=policy)}")

    structured = {"password": DEMO_PASSWORD}
    hash_policy = lp.CleanerPolicy.default(masking="hash")
    print(f"Structured   {lp.clean(structured, policy=hash_policy)}")


def demonstrate_url_cleaning() -> None:
    """Clean user information and sensitive URL parameters."""
    print_section("4. URL cleaning")
    urls = (
        "https://example.com/search?page=1&token=abc123",
        "https://alice:demo-password@example.com/private",
        "https://app.example/callback#access_token=abc123&id_token=jwt-demo",
    )

    for url in urls:
        print(f"Input:  {url}")
        print(f"Output: {lp.clean_url(url)}")


def demonstrate_audit() -> None:
    """Inspect content without changing the original value."""
    print_section("5. Audit")
    value = f"email={DEMO_EMAIL} password={DEMO_PASSWORD}"
    report = lp.audit(value)

    print(f"Safe:          {report.safe}")
    print(f"Risk level:    {report.risk_level}")
    print(f"Finding count: {report.finding_count}")
    print(f"Categories:    {report.categories}")
    print(f"Summary:       {report.summary()}")
    print(f"Safe repr:     {report!r}")


def demonstrate_safe_print() -> None:
    """Render arbitrary diagnostic values without exposing private data."""
    print_section("6. Safe diagnostic output")

    class UnsafeObject:
        def __str__(self) -> str:
            return f"owner={DEMO_EMAIL} password={DEMO_PASSWORD}"

    lp.safe_print(UnsafeObject())
    lp.safe_print({"password": DEMO_PASSWORD, "object": UnsafeObject()})
    lp.safe_print(range(1_000_000_000))
    lp.safe_print(list(range(100)), max_items=10)


def demonstrate_logging() -> None:
    """Protect standard-library logging messages and custom fields."""
    print_section("7. Logging integration")
    logger_name = "logprivacy.showcase"
    logger = logging.getLogger(logger_name)
    old_handlers = list(logger.handlers)
    old_filters = list(logger.filters)
    old_level = logger.level
    old_propagate = logger.propagate

    try:
        logger.handlers.clear()
        logger.filters.clear()
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s | %(name)s | %(message)s"))
        logger.addHandler(handler)

        safe_logger = lp.get_safe_logger(logger_name, level=logging.DEBUG)
        safe_logger.info("email=%s password=%s", DEMO_EMAIL, DEMO_PASSWORD)

        try:
            raise RuntimeError(f"password={DEMO_PASSWORD} email={DEMO_EMAIL}")
        except RuntimeError:
            safe_logger.exception("Fictional request failure")
    finally:
        logger.handlers[:] = old_handlers
        logger.filters[:] = old_filters
        logger.setLevel(old_level)
        logger.propagate = old_propagate


def demonstrate_production_policy() -> None:
    """Show high-risk values being blocked instead of silently masked."""
    print_section("8. Production policy")

    try:
        lp.clean({"password": DEMO_PASSWORD}, policy=lp.CleanerPolicy.production())
    except lp.LogBlockedError as error:
        print(f"Blocked categories: {error.categories}")


def demonstrate_atomic_file_cleaning() -> None:
    """Clean a file in place without truncating or partially replacing it."""
    print_section("9. Atomic file cleaning")

    with tempfile.TemporaryDirectory(prefix="logprivacy-showcase-") as directory:
        path = Path(directory) / "application.log"
        path.write_text(
            f"email={DEMO_EMAIL}\npassword={DEMO_PASSWORD}\nstatus=ok\n",
            encoding="utf-8",
        )

        print("Before:")
        print(path.read_text(encoding="utf-8"))
        lp.clean_file(path, output=path)
        print("After:")
        print(path.read_text(encoding="utf-8"))


def main() -> None:
    """Run every standalone demonstration."""
    print("LogPrivacy — complete showcase")
    print(f"Library version: {lp.__version__}")
    print(f"Python version:  {sys.version.split()[0]}")

    demonstrate_text_cleaning()
    demonstrate_structured_cleaning()
    demonstrate_masking_strategies()
    demonstrate_url_cleaning()
    demonstrate_audit()
    demonstrate_safe_print()
    demonstrate_logging()
    demonstrate_production_policy()
    demonstrate_atomic_file_cleaning()

    print_section("SHOWCASE COMPLETED")
    print("All examples executed successfully.")


if __name__ == "__main__":
    main()
