"""URL sanitization helpers."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from logcleaner.cleaner import Cleaner
from logcleaner.policy import CleanerPolicy

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
    Clean a URL.

    By default, the scheme, host, path, and safe query parameters are preserved,
    while sensitive query parameter values are redacted.
    """
    cleaner = Cleaner(policy=policy or CleanerPolicy.default())
    if redact_full:
        return cleaner.policy.masking.mask_category("url")

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return cleaner.clean_text(url)

    query_items = parse_qsl(parts.query, keep_blank_values=True)
    cleaned_items: list[tuple[str, str]] = []
    for key, value in query_items:
        normalized = key.lower().replace("-", "_")
        if normalized in _SENSITIVE_QUERY_KEYS:
            replacement_category = "email" if normalized == "email" else "secret"
            cleaned_items.append((key, cleaner.policy.masking.mask_category(replacement_category)))
        else:
            cleaned_items.append((key, cleaner.clean_text(value)))

    cleaned_query = urlencode(cleaned_items, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, cleaned_query, parts.fragment))
