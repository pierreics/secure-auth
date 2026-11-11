# Secure Auth — Build & Break (JSON REST API)

A lightweight authentication and backend server built from scratch using Node.js, Express, and SQLite3. This is used as a hands-on project to learn backend development and web security from both sides: I build each feature, attack it with my own scripts, and then harden it—documenting every step.

This is a learning project. It intentionally starts with weaknesses so I can exploit and then fix them. Do not use it as-is in production.

## What it does
- **User registration** with a strict password-complexity policy
- **Login / logout** with server-side sessions and secure HttpOnly cookies
- **User profile retrieval** (`/api/users/me`)
- **Password change** (verifies current password and hashes the new one)
- **Account deletion** (requires password verification before removing the user)
- **Per-user private vault** to store and update a secret
- **Role-based access control** (isolated standard user / admin areas)

## Tech Stack
Node.js · Express · SQLite3 · express-session · session-file-store · bcrypt · express-rate-limit

## Security Approach & Architectural Shift

### Built-in Defenses
- **Password hashing with bcrypt** — a slow, salted, adaptive hash to defeat brute-force and rainbow table attacks.
- **Timing-safe user enumeration defense** — dummy `bcrypt.compare` execution when user doesn't exist to keep response times constant.
- **Generic error messages** — avoids leaking whether username or password was incorrect.
- **Access control** — protected routes backed by `requireAuth` middleware + role verification (`admin`).
- **Password complexity policy** — enforced length and character variety.
- **Rate limiting** — IP-based request throttling on `/api/login` and `/api/register` via `express-rate-limit`.

### Architectural Impact on Vulnerabilities
Migrating from a hybrid HTML-rendering server to a **Pure JSON REST API** significantly reduced the overall attack surface:
- **Server-Side XSS**: Endpoints now return raw JSON (`application/json`) instead of rendering untrusted HTML strings dynamically (`res.send`). HTML rendering is completely decoupled from the backend.
- **Classic Form CSRF**: Cross-origin state-changing requests sending `application/json` trigger browser CORS preflights (`OPTIONS`), rendering simple cross-site HTML form POST attacks ineffective against modern browsers.
- **Legacy Exploits**: Legacy PoC scripts targeting the HTML-rendering phase are preserved in `attacks/` and remain fully testable by checking out the `v1-vulnerable` Git tag.

## The Security Journey

| Vulnerability                                   | Type                  | Exploit / PoC             | Status                                                                |
| :---------------------------------------------- | :-------------------- | :------------------------ | :-------------------------------------------------------------------- |
| **No rate limiting on login/register**          | Brute Force / DoS     | `attacks/brute_login.py`  | ✅ Fixed (`express-rate-limit`)                                        |
| **Stored XSS in vault (HTML Era)**              | Server XSS            | `attacks/xss_vault.py`    | ✅ Mitigated by REST Architecture (Valid on `v1-vulnerable`)           |
| **Cross-Site Request Forgery (HTML Form)**      | CSRF                  | `attacks/csrf_vault.html` | ✅ Mitigated by REST Architecture (Valid on `v1-vulnerable`)           |
| **Weak session cookie flags & fallback secret** | Misconfig             | —                         | ✅ Fixed (`req.session.regenerate(), httpOnly : true, sameSite : lax`) |
| **Hardcoded admin credentials**                 | Hardcoded credentials | —                         | ✅ Fixed (`dotenv`)                                                    |

*(Status legend: 🔜 Planned · 🛠️ In progress · 🔄 Mitigated by Architecture · ✅ Fixed)*

## Project Structure
.
├── server.js           # Express REST API server
├── utils.js            # Shared helpers (validations, error handler, auth middleware)
├── database.js         # SQLite database setup and connection
├── attacks/            # Exploit scripts & PoCs
│   ├── brute_login.py  # Python PoC for API brute-force attack
│   ├── csrf_vault.html # Legacy CSRF exploit (v1-vulnerable tag)
│   └── xss_vault.py    # Legacy XSS exploit (v1-vulnerable tag)
├── docs/               # Write-ups: vulnerability analysis & fixes
└── README.md

## Run It Locally

1. Install dependencies:
   `npm install`

2. Start the server:
   `node server.js`
   The API will run at `http://localhost:3000`.

3. Set a session secret via environment variable if desired:
   `SECRET_KEY="a-long-random-string" node server.js`

*(Note: Since this is a Pure JSON REST API, test and interact with it using tools like cURL, Postman, or custom test scripts rather than a browser UI).*

## Main API Endpoints Reference

### Public Routes
- `POST /api/register` — Register a new user (rate limited)
- `POST /api/login` — Authenticate and create a server session (rate limited)

### Protected Routes (Requires Session Cookie)
- `GET /api/users/me` — Get current logged-in user info
- `POST /api/logout` — Destroy session and clear cookie
- `GET /api/adminsecrets` — View all users and their secrets (Admin only)
- `POST /api/changepassword` — Update password securely
- `GET /api/vault` — Retrieve user's private secret
- `POST /api/vault` — Update user's private secret
- `POST /api/deleteaccount` — Permanently delete user account

## Versions
- `v1-vulnerable` — initial hybrid HTML build before architectural refactoring and hardening (`git checkout v1-vulnerable`)
- `main` — current Pure JSON REST API, progressively hardened

## Disclaimer
Built for learning purposes. All attacks target only this application, running locally on my own machine.