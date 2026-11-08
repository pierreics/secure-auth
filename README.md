# Secure Auth — Build & Break

A small authentication server built with **Node.js** and **Express**, used as a
hands-on project to learn backend development *and* web security from both
sides: I build each feature, then I attack it with my own scripts, then I
harden it — documenting every step.

> This is a learning project. It intentionally starts with weaknesses so I can
> exploit and then fix them. Do not use it as-is in production.

## What it does

- User **registration** with a password-complexity policy
- **Login / logout** with server-side sessions
- **Password change** (verifies the current password)
- **Account deletion** (verifies the password)
- A per-user **vault** to store a secret
- **Role-based** areas (`user` / `admin`)

**Stack:** Node.js · Express · express-session · bcrypt

## Security approach

Some defenses were built in from the start:

- **Password hashing with bcrypt** — a slow, salted, adaptive hash. The work
  factor makes brute-force expensive and the per-password salt defeats
  rainbow-table attacks (unlike fast hashes such as MD5/SHA-256).
- **Timing-safe user enumeration defense** — when the username does not exist,
  a dummy `bcrypt.compare` still runs, so the response time stays constant and
  does not leak whether an account exists.
- **Generic error messages** — login never reveals whether the username or the
  password was wrong, to prevent username enumeration from the response content.
- **Access control** — protected routes require an authenticated session, and
  the admin area additionally checks the user's role.
- **Password complexity policy** — enforced length and character variety.

## The security journey

Each vulnerability is exploited with a script (in `attacks/`), then fixed, then
written up (in `docs/`). The vulnerable version is kept runnable via a Git tag
so each finding is reproducible.

| Vulnerability | Type | Exploit | Status |
| --- | --- | --- | --- |
| Stored XSS in the vault | XSS | `attacks/xss_vault.py` | 🔜 Planned |
| No rate limiting on login | Brute force | `attacks/brute_login.py` | 🔜 Planned |
| No CSRF protection | CSRF | — | 🔜 Planned |
| Duplicate username on register | Logic flaw | — | 🔜 Planned |
| Weak session cookie flags & fallback secret | Misconfig | — | 🔜 Planned |
| Hardcoded admin password in source | Hardcoded credentials | — | 🔜 Planned |

*(Status: 🔜 Planned · 🛠️ In progress · ✅ Fixed — updated as I go.)*

## Project structure

```
.
├── server.js       # the Express server
├── views/          # HTML pages
├── attacks/        # scripts that exploit this app (my own target only)
├── docs/           # write-ups: each vulnerability, exploit, and fix
└── README.md
```

## Run it locally

```bash
npm install
node server.js
```

Then open `http://localhost:3000`.

Set a session secret via environment variable:

```bash
SECRET_KEY="a-long-random-string" ADMIN_PASSWORD="another-strong-one" node server.js
```

## Versions

- `v1-vulnerable` — the initial build, before hardening (`git checkout v1-vulnerable`)
- `main` — the current, progressively hardened version

## Disclaimer

Built for learning. All attacks target only this application, on my own machine.
