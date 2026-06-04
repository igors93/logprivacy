"""Configuration object for LogCleaner."""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from logcleaner.masking.strategy import MaskingStrategy, PlaceholderMaskingStrategy
from logcleaner.rules.base import RedactionRule
_DEFAULT_SENSITIVE_KEYS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key", "access_token", "refresh_token", "client_secret", "private_key", "authorization", "cookie", "set-cookie")

@dataclass(frozen=True, slots=True)
class CleanerPolicy:
    """Configuration for Cleaner."""
    rules: tuple[RedactionRule, ...] = field(default_factory=tuple)
    masking: MaskingStrategy = field(default_factory=PlaceholderMaskingStrategy)
    sensitive_keys: tuple[str, ...] = _DEFAULT_SENSITIVE_KEYS
    clean_mapping_keys: bool = False
    max_depth: int = 20
    clean_unknown_objects: bool = False
    def __post_init__(self) -> None:
        if not self.rules:
            from logcleaner.rule_sets.default import default_rules
            object.__setattr__(self, "rules", default_rules())
    @classmethod
    def default(cls) -> "CleanerPolicy":
        from logcleaner.rule_sets.default import default_rules
        return cls(rules=default_rules())
    @classmethod
    def strict(cls) -> "CleanerPolicy":
        from logcleaner.rule_sets.strict import strict_rules
        return cls(rules=strict_rules())
    @classmethod
    def web(cls) -> "CleanerPolicy":
        from logcleaner.rule_sets.web import web_rules
        return cls(rules=web_rules())
    def add_rules(self, *rules: RedactionRule) -> "CleanerPolicy":
        return replace(self, rules=(*self.rules, *rules))
    def with_rules(self, *rules: RedactionRule) -> "CleanerPolicy":
        return replace(self, rules=tuple(rules))
    def without_categories(self, *categories: str) -> "CleanerPolicy":
        blocked = set(categories)
        return replace(self, rules=tuple(rule for rule in self.rules if rule.category not in blocked))
    def is_sensitive_key(self, key: object) -> bool:
        normalized = str(key).strip().lower().replace("-", "_")
        return normalized in {item.replace("-", "_") for item in self.sensitive_keys}
