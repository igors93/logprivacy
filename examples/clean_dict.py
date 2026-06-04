from logcleaner import clean

payload = {"email": "john@example.com", "password": "123456", "status": "failed"}
print(clean(payload))
