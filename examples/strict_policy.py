"""Strict policy also detects IP addresses and phone-number-like values."""

from logprivacy import Cleaner, CleanerPolicy

cleaner = Cleaner(policy=CleanerPolicy.strict())

print(cleaner.clean("client_ip=192.168.1.10 email=john@example.com"))
# client_ip=[IP_ADDRESS] email=[EMAIL]
