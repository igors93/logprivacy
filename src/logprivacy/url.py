"""URL sanitization helpers."""

from __future__ import annotations

from urllib.parse import parse_qsl, quote_plus, urlsplit, urlunsplit

from logprivacy.cleaner import Cleaner
from logprivacy.policy import CleanerPolicy

_SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "signature",
    "sig",
    "email",
}


def clean_url(url: str, *, policy: CleanerPolicy | None = None, redact_full: bool = False) -> str:
    """
    Clean a URL, redacting sensitive query parameters.

    The scheme, host, path, and safe query parameters are preserved.
    Sensitive query parameter values are replaced with readable placeholders
    such as ``[SECRET]`` or ``[EMAIL]``.

    The output is intended for logging and display. Values are not re-encoded,
    so placeholders remain readable rather than appearing as ``%5BSECRET%5D``.

    Example::

        clean_url("https://api.example.com/users?page=1&token=abc&email=j@x.com")
        # "https://api.example.com/users?page=1&token=[SECRET]&email=[EMAIL]"
    """
    cleaner = Cleaner(policy=policy or CleanerPolicy.default())
    if redact_full:
        return cleaner.policy.masking.mask_category("url")

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return cleaner.clean_text(url)

    query_items = parse_qsl(parts.query, keep_blank_values=True)

    # Build the query string manually so that placeholder tokens like [SECRET]
    # are kept as human-readable text instead of being percent-encoded.
    query_parts: list[str] = []
    for key, value in query_items:
        encoded_key = quote_plus(key)
        normalized = key.lower().replace("-", "_")
        if normalized in _SENSITIVE_QUERY_KEYS:
            replacement_category = "email" if normalized == "email" else "secret"
            placeholder = cleaner.policy.masking.mask_category(replacement_category)
            query_parts.append(f"{encoded_key}={placeholder}")
        else:
            # Clean the value but keep it unencoded for readability in logs
            cleaned_value = cleaner.clean_text(value)
            query_parts.append(f"{encoded_key}={cleaned_value}")

    cleaned_query = "&".join(query_parts)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, cleaned_query, parts.fragment))
