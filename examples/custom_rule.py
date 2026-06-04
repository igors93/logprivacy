from logcleaner import Cleaner, CleanerPolicy, CustomRegexRule

order_rule = CustomRegexRule(name="order_id", category="order", pattern=r"ORDER-[0-9]{6}")
cleaner = Cleaner(policy=CleanerPolicy.default().add_rules(order_rule))
print(cleaner.clean("Failed order ORDER-123456"))
