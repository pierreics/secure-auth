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
Node.js · Express · SQLite3 · express-session · session-file-store · bcrypt

## Security Approach
Some defenses were built in from the start:
- **Password hashing with bcrypt** — a slow, salted, adaptive hash. The work factor makes brute-force expensive and per-password salts defeat rainbow-table attacks (unlike fast hashes like MD5/SHA-256).
- **Timing-safe user enumeration defense** — when a username does not exist, a dummy `bcrypt.compare` still runs so the response time stays constant and does not leak whether an account exists.
- **Generic error messages** — login never reveals whether the username or the password was wrong, preventing username enumeration.
- **Access control** — protected routes require an authenticated session (`requireAuth` middleware), and the admin route (`/api/adminsecrets`) checks the user's role.
- **Password complexity policy** — enforced length and character variety.

## Project Structure
.
├── server.js       # the Express REST API server
├── utils.js        # shared helpers (validation, error handler, auth middleware)
├── database.js     # SQLite database setup and connection
├── attacks/        # scripts that exploit this app (my own target only)
├── docs/           # write-ups: each vulnerability, exploit, and fix
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
- `POST /api/register` — Register a new user
- `POST /api/login` — Authenticate and create a server session

### Protected Routes (Requires Session Cookie)
- `GET /api/users/me` — Get current logged-in user info
- `POST /api/logout` — Destroy session and clear cookie
- `GET /api/adminsecrets` — View all users and their secrets (Admin only)
- `POST /api/changepassword` — Update password securely
- `GET /api/vault` — Retrieve user's private secret
- `POST /api/vault` — Update user's private secret
- `POST /api/deleteaccount` — Permanently delete user account

## Versions
- `v1-vulnerable` — the initial build, before hardening (`git checkout v1-vulnerable`)
- `main` — the current, progressively hardened version

## Disclaimer
Built for learning purposes. All attacks target only this application, running locally on my own machine.