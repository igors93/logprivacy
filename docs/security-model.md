# Security Model

LogCleaner reduces accidental sensitive-data exposure in logs.

It does not guarantee perfect anonymization and does not replace:

- secret management
- encryption
- access control
- legal privacy review
- data-loss-prevention systems

Regex-based detection can have false positives and false negatives.
Use `audit()` and `assert_clean()` to catch problems early.
