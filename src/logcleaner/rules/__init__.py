"""Built-in redaction rules."""

from logcleaner.rules.base import RedactionRule, RegexRedactionRule
from logcleaner.rules.credential import CredentialRule
from logcleaner.rules.credit_card import CreditCardRule
from logcleaner.rules.custom import CustomRegexRule
from logcleaner.rules.email import EmailRule
from logcleaner.rules.ip_address import IPAddressRule
from logcleaner.rules.phone import PhoneRule
from logcleaner.rules.secret import SecretRule
from logcleaner.rules.token import TokenRule
from logcleaner.rules.url import UrlRule

__all__ = [
    "CredentialRule",
    "CreditCardRule",
    "CustomRegexRule",
    "EmailRule",
    "IPAddressRule",
    "PhoneRule",
    "RegexRedactionRule",
    "RedactionRule",
    "SecretRule",
    "TokenRule",
    "UrlRule",
]
