"""Clean a string that contains an email address and a password."""

from logprivacy import clean

message = "Login failed for john@example.com with password=123456"
print(clean(message))
# Login failed for [EMAIL] with password=[SECRET]
