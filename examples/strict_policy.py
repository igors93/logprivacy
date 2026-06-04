from logcleaner import Cleaner, CleanerPolicy

cleaner = Cleaner(policy=CleanerPolicy.strict())
print(cleaner.clean("client_ip=192.168.1.10 email=john@example.com"))
