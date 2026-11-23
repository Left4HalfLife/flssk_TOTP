# Security review record

Post-build security check of the account template (`user_auth/`, `totp_2fa/`,
Docker/Compose, `configure.py`). Re-run these checks after any change to the
authentication code.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Static analysis | `bandit -r user_auth totp_2fa app.py configure.py example_app.py` | 0 high, 0 medium, 2 low (false positives, below) |
| Dependency audit | `pip-audit -r requirements.txt` | No known vulnerabilities found |
| Manual code review | Authentication, session, WebAuthn, admin, CSRF, XSS, SQL, container config | No exploitable issues found |
| Test suite | `python -m pytest -q` | 49 passed |
| Docker end-to-end | `docker compose up --build` followed by HTTP flow script | All steps passed (below) |

### Bandit low-severity findings

| # | Severity | File | Lines | Finding | Disposition |
|---|----------|------|-------|---------|-------------|
| 1 | ⚪ LOW | user_auth/__init__.py | 35 | B105 "hardcoded password" `'user_auth.password_change'` | False positive: Flask endpoint name |
| 2 | ⚪ LOW | user_auth/database.py | 169 | B105 "hardcoded password" placeholder string | False positive: rejects the `.env.example` placeholder |

### Earlier findings (fixed during development)

| # | Severity | Area | Issue | Fix |
|---|----------|------|-------|-----|
| 1 | 🟠 HIGH | TOTP enrollment | Pre-existing sessions survived TOTP activation | Enrollment bumps `auth_version`, revoking all prior sessions |
| 2 | 🟡 MEDIUM | Logout | Copied session cookies remained valid after logout | Server-side session tokens are revoked on logout |

## Verified properties

- `full` access is reachable only with a passkey, password + TOTP/recovery code,
  or by confirming a first method during restricted onboarding. Password-only
  sessions are limited to password change/enrollment.
- `auth_version` bumps (password change, enrollment, method removal, admin
  actions) delete the user's sessions and challenges. Tokens are hashed at rest.
- Sensitive actions re-check freshness (5 minutes) and admin rights inside the
  write transaction. Admin deletes are scoped by user ID, and self-delete,
  last-admin delete, and self-removal of the last method are blocked.
- TOTP time steps cannot be replayed, and recovery codes are single-use and hashed.
- WebAuthn checks a fixed RP ID/origin, user verification, single-use bound
  challenges, user handle, signature, and sign count.
- CSRF is required on every POST. Cookies are SameSite=Strict, HttpOnly, and
  Secure on HTTPS. CSP blocks inline scripts. SQL is parameterized.
- The container runs non-root with a read-only root FS, `cap_drop: ALL`, and
  no-new-privileges, bound to `127.0.0.1`. Redis is not published.

## Docker end-to-end flow verified

1. Bootstrap admin from `.env` leads to a forced password change. The dashboard
   and admin pages are blocked until a method is enrolled.
2. TOTP enrollment shows recovery codes once. The old password is rejected.
3. Password alone leads to the TOTP prompt. Password + TOTP lands on the admin
   user page.
4. The admin creates a user, who must change the password and enroll. Force
   password change revokes that user's session. The admin deletes the user. Self-revoking
   the last method returns 400.
5. Data persists across a container restart.
