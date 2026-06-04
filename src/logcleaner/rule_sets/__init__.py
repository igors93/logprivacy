"""Ready-to-use rule sets."""
from logcleaner.rule_sets.default import default_rules
from logcleaner.rule_sets.strict import strict_rules
from logcleaner.rule_sets.web import web_rules
__all__ = ["default_rules", "strict_rules", "web_rules"]
