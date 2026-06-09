"""
Standalone demonstration of the LogPrivacy library.

This file is NOT part of the library's internal implementation and is NOT
required for the package to work. It exists only to demonstrate, manually test,
and document the main features of the project.

Recommended location:
    examples/logprivacy_showcase.py

Run it from the project root:

    python examples/logprivacy_showcase.py

On Windows, you may also run:

    python3 examples\\logprivacy_showcase.py

This demonstration:

- uses fictional data only;
- does not modify project source files;
- creates temporary files that are deleted automatically;
- can run directly from the repository without installing the package;
- demonstrates text, URL, structured data, logging, and file sanitization;
- compares the available masking strategies.

This file may be published on GitHub as an official usage example.
"""

from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Local project setup
# ---------------------------------------------------------------------------
#
# This project uses the common "src layout", which means the package is stored
# under:
#
#     logprivacy/src/logprivacy
#
# The following code temporarily adds the "src" directory to Python's import
# path. This makes it possible to run the example directly from the repository,
# even if the package has not yet been installed with:
#
#     python -m pip install -e .
#
# This modification affects only the current Python process. It does not change
# any permanent system or project configuration.
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIRECTORY = PROJECT_ROOT / "src"

if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))


# These imports must happen after adding the "src" directory to sys.path.
import logprivacy  # noqa: E402
from logprivacy import (  # noqa: E402
    Cleaner,
    CleanerPolicy,
    LogBlockedError,
    audit,
    clean,
    clean_file,
    clean_text,
    clean_url,
    clean_with_result,
    get_safe_logger,
    safe_print,
)

# All values used by this demonstration are fictional.
DEMO_EMAIL = "john@example.com"
DEMO_PASSWORD = "demo-password-123"
DEMO_TOKEN = "abcdefgh1234567890"


def print_section(title: str) -> None:
    """Print a visual separator between demonstration sections."""

    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def demonstrate_text_cleaning() -> None:
    """Demonstrate string sanitization for several sensitive-data formats."""

    print_section("1. Text cleaning")

    examples = [
        f"email={DEMO_EMAIL} password={DEMO_PASSWORD}",
        f"Authorization: Bearer {DEMO_TOKEN}",
        "Authorization: Basic dXNlcjpwYXNz",
        "api_key=sk_live_12345678901234567890",
        "card=4111 1111 1111 1111",
        "This text does not contain sensitive information",
    ]

    for original in examples:
        cleaned = clean_text(original)

        print(f"Input:  {original}")
        print(f"Output: {cleaned}")
        print("-" * 44)


def demonstrate_structured_data() -> None:
    """Demonstrate recursive cleaning of dictionaries, lists, and tuples."""

    print_section("2. Structured data cleaning")

    payload = {
        "user": {
            "name": "Demo User",
            "email": DEMO_EMAIL,
            "password": DEMO_PASSWORD,
        },
        "authorization": f"Bearer {DEMO_TOKEN}",
        "events": [
            "operation completed",
            "contact@example.com",
            {
                "client_secret": "client-demo-secret",
                "status": "ok",
            },
        ],
        "metadata": (
            "safe value",
            "other@example.com",
        ),
    }

    cleaned_payload = clean(payload)

    print("Original structure:")
    print(payload)

    print("\nCleaned structure:")
    print(cleaned_payload)


def demonstrate_url_cleaning() -> None:
    """Demonstrate credential and sensitive-parameter sanitization in URLs."""

    print_section("3. URL cleaning")

    urls = [
        "https://example.com/search?page=1&token=abc123",
        "https://alice:demo-password@example.com/private",
        (
            "https://app.example/callback"
            "#access_token=abc123&id_token=jwt-demo&state=ok"
        ),
        (
            "https://api.example/resource"
            "?client_secret=plain-secret&safe_parameter=ok"
        ),
        "https://example.com/users/john@example.com",
    ]

    for original in urls:
        cleaned = clean_url(original)

        print(f"Input:  {original}")
        print(f"Output: {cleaned}")
        print("-" * 44)


def demonstrate_audit() -> None:
    """
    Demonstrate content auditing.

    Auditing detects sensitive information without returning a cleaned string.
    It is useful when an application needs to decide whether a value is safe to
    log, transmit, or store.
    """

    print_section("4. Content audit")

    value = (
        f"email={DEMO_EMAIL} "
        f"password={DEMO_PASSWORD} "
        f"Authorization: Bearer {DEMO_TOKEN}"
    )

    report = audit(value)

    print("Analyzed text:")
    print(value)

    print("\nAudit result:")
    print(f"Safe:                 {report.safe}")
    print(f"Risk level:           {report.risk_level}")
    print(f"Finding count:        {report.finding_count}")
    print(f"Categories:           {report.categories}")
    print(f"Summary:              {report.summary()}")

    print("\nSafe report representation:")
    print(repr(report))


def demonstrate_detailed_result() -> None:
    """
    Demonstrate clean_with_result().

    This function returns the cleaned content together with information about
    the sensitive values that were detected.
    """

    print_section("5. Detailed cleaning result")

    text = (
        f"email={DEMO_EMAIL} "
        f"password={DEMO_PASSWORD} "
        f"Authorization: Bearer {DEMO_TOKEN}"
    )

    result = clean_with_result(text)

    print(f"Changed:              {result.changed}")
    print(f"Finding count:        {result.finding_count}")
    print(f"Categories:           {result.categories}")
    print(f"Cleaned result:       {result.cleaned}")
    print(f"Summary:              {result.summary()}")

    print("\nExplanation:")
    print(result.explain())

    print("\nSafe object representation:")
    print(repr(result))


def demonstrate_masking_strategies() -> None:
    """Compare placeholder, partial, and hash masking strategies."""

    print_section("6. Masking strategies")

    text = (
        f"email={DEMO_EMAIL} "
        "api_key=sk_live_12345678901234567890"
    )

    placeholder_cleaner = Cleaner(
        policy=CleanerPolicy.default(masking="placeholder")
    )
    partial_cleaner = Cleaner(
        policy=CleanerPolicy.default(masking="partial")
    )
    hash_cleaner = Cleaner(
        policy=CleanerPolicy.default(masking="hash")
    )

    print(f"Original:    {text}")
    print(f"Placeholder: {placeholder_cleaner.clean_text(text)}")
    print(f"Partial:     {partial_cleaner.clean_text(text)}")
    print(f"Hash:        {hash_cleaner.clean_text(text)}")


def demonstrate_safe_print() -> None:
    """
    Demonstrate safe_print() with arbitrary values and custom objects.

    safe_print() is intended for diagnostic output where arbitrary objects may
    contain sensitive information in their __str__ or __repr__ methods.
    """

    print_section("7. Safe diagnostic output")

    class UnsafeDemoObject:
        """Fictional object whose string representation contains private data."""

        def __str__(self) -> str:
            return (
                f"owner={DEMO_EMAIL} "
                f"password={DEMO_PASSWORD}"
            )

        def __repr__(self) -> str:
            return (
                "UnsafeDemoObject("
                f"email={DEMO_EMAIL}, "
                f"password={DEMO_PASSWORD})"
            )

    print("Custom object:")
    safe_print(UnsafeDemoObject())

    print("\nCustom object inside a nested structure:")
    safe_print(
        {
            "password": DEMO_PASSWORD,
            "object": UnsafeDemoObject(),
            "users": [
                "alice@example.com",
                "bob@example.com",
            ],
        }
    )

    print("\nVery large range preserved in compact form:")
    safe_print(range(1_000_000_000))

    print("\nList limited to the first items:")
    safe_print(
        list(range(100)),
        max_items=10,
    )

    print("\nOutput limited by character count:")
    safe_print(
        ["item-" + str(index) for index in range(100)],
        max_chars=120,
    )


def demonstrate_logging() -> None:
    """
    Demonstrate integration with Python's standard logging module.

    The logger used here is configured temporarily for this example. Its
    previous configuration is restored when the demonstration finishes.
    """

    print_section("8. Logging integration")

    logger_name = "logprivacy.showcase"
    logger = logging.getLogger(logger_name)

    # Save the previous configuration to avoid leaving global side effects.
    original_handlers = list(logger.handlers)
    original_filters = list(logger.filters)
    original_level = logger.level
    original_propagate = logger.propagate

    try:
        logger.handlers.clear()
        logger.filters.clear()
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(levelname)s | %(name)s | %(message)s"
            )
        )
        logger.addHandler(handler)

        # get_safe_logger() should be called after handlers are configured.
        safe_logger = get_safe_logger(
            logger_name,
            level=logging.DEBUG,
        )

        safe_logger.info(
            "Login: email=%s password=%s",
            DEMO_EMAIL,
            DEMO_PASSWORD,
        )

        safe_logger.warning(
            "Authorization: Bearer %s",
            DEMO_TOKEN,
        )

        try:
            raise RuntimeError(
                f"Failure with password={DEMO_PASSWORD} "
                f"and email={DEMO_EMAIL}"
            )
        except RuntimeError:
            safe_logger.exception(
                "Fictional error during request processing"
            )

    finally:
        # Restore the logger so this example remains self-contained.
        logger.handlers[:] = original_handlers
        logger.filters[:] = original_filters
        logger.setLevel(original_level)
        logger.propagate = original_propagate


def demonstrate_production_policy() -> None:
    """
    Demonstrate the production policy.

    This policy raises LogBlockedError when high-risk categories are detected,
    instead of only masking them.
    """

    print_section("9. Production policy")

    cleaner = Cleaner(
        policy=CleanerPolicy.production()
    )

    try:
        cleaner.clean_text(
            f"password={DEMO_PASSWORD}"
        )
    except LogBlockedError as error:
        print("The value was blocked successfully.")
        print(f"Error:      {error}")
        print(f"Categories: {error.categories}")


def demonstrate_atomic_file_cleaning() -> None:
    """
    Demonstrate atomic file cleaning.

    The file is created inside a temporary operating-system directory. Nothing
    is written permanently inside the repository.

    The same path is used for input and output to prove that in-place cleaning
    does not truncate or corrupt the file.
    """

    print_section("10. Atomic file cleaning")

    with tempfile.TemporaryDirectory(
        prefix="logprivacy-showcase-"
    ) as temporary_directory:
        log_path = Path(temporary_directory) / "application.log"

        log_path.write_text(
            f"INFO email={DEMO_EMAIL}\n"
            f"DEBUG password={DEMO_PASSWORD}\n"
            "INFO status=ok\n",
            encoding="utf-8",
        )

        print("Content before cleaning:")
        print(log_path.read_text(encoding="utf-8"))

        # Input and output intentionally point to the same file.
        clean_file(
            log_path,
            output=log_path,
        )

        cleaned_content = log_path.read_text(
            encoding="utf-8"
        )

        print("Content after cleaning:")
        print(cleaned_content)

        # Simple assertions make the example self-validating.
        assert DEMO_EMAIL not in cleaned_content
        assert DEMO_PASSWORD not in cleaned_content
        assert "[EMAIL]" in cleaned_content
        assert "[SECRET]" in cleaned_content

        print("In-place file cleaning completed successfully.")


def main() -> None:
    """Run every LogPrivacy demonstration."""

    print("LogPrivacy — complete showcase")
    print(f"Library version: {logprivacy.__version__}")
    print(f"Python version:  {sys.version.split()[0]}")
    print(f"Project root:    {PROJECT_ROOT}")

    demonstrate_text_cleaning()
    demonstrate_structured_data()
    demonstrate_url_cleaning()
    demonstrate_audit()
    demonstrate_detailed_result()
    demonstrate_masking_strategies()
    demonstrate_safe_print()
    demonstrate_logging()
    demonstrate_production_policy()
    demonstrate_atomic_file_cleaning()

    print_section("SHOWCASE COMPLETED")
    print("All examples were executed successfully.")


if __name__ == "__main__":
    main()
