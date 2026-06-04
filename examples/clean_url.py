from logcleaner import clean_url

url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"
print(clean_url(url))
