# Flask accounts, TOTP and passkeys

A reusable Python 3.10+ Flask login/user-management template with SQLite users,
encrypted TOTP, WebAuthn passkeys, mandatory onboarding, revocable sessions,
CSRF protection, rate limiting, and administrator tools.

**Login policy:** a verified passkey **OR** password + TOTP/recovery code.
Password-only access is restricted to explicitly authorized initial/reset
onboarding and can never reach protected pages.

## Docker quickstart

Requires Docker with the Compose plugin and Python 3.10+ for the bootstrap helper.

```bash
git clone https://github.com/Left4HalfLife/flssk_TOTP.git
cd flssk_TOTP
python3 configure.py --username admin
docker compose up --build
```

`configure.py` uses only the Python standard library. It prompts for a unique
initial admin password (12-128 characters), generates both encryption/session
keys, and creates a private `.env` without overwriting an existing file.
Alternatively copy `.env.example` to `.env` and replace the placeholders.
For a Fernet key:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Open **http://localhost:8000** (not `127.0.0.1`, since the configured WebAuthn
origin is localhost). Log in with the configured admin username/password,
immediately change the password, then enroll TOTP, a passkey, or both. TOTP
confirmation displays ten single-use recovery codes **once**. After confirming
one method you can add the other under **Security methods**.

Admin logins lead to **Users**, where you can create accounts, force a password
change, revoke individual TOTP/passkeys, reset onboarding with a new temporary
password, and delete users. New users always change their temporary password
before enrolling a method. All credential/reset actions require a login in
the last five minutes; log in again if prompted.

Bootstrap runs only once per database. Changing `ADMIN_USERNAME` or
`ADMIN_INITIAL_PASSWORD` later does not change the existing account. Remove the
initial password from `.env` after onboarding; preserve `SECRET_KEY` and
`TOTP_ENCRYPTION_KEY`. Never commit `.env`.

Compose runs a non-root, read-only Gunicorn container with a writable persistent
`accounts` volume and private Redis rate-limit storage. It publishes only
`127.0.0.1:8000`; Redis is not published. `docker compose down` retains users.
**`docker compose down -v` permanently destroys the account database.**

## Policy and security behavior

- Forced password-change flags do **not** bypass an enrolled factor: users
  authenticate with password + TOTP or passkey before changing their password.
- Passkey-only accounts cannot log in using just a password. Passkeys require
  discoverable credentials and device user verification (PIN/biometrics).
- Removing another user's last method locks login, rather than allowing
  password-only access. An admin must deliberately reset the account with a
  **new temporary password**, which removes all methods and grants restricted
  onboarding. Users cannot remove their own last method or delete themselves
  as the active admin.
- Enrollment, password changes, resets and method revocations invalidate old
  server-side sessions. Logout revokes the current session, including copied
  cookies. Sessions expire absolutely after one hour (restricted stages:
  ten minutes), and after fifteen minutes idle.
- SQLite stores UUID user IDs, case-normalized unique usernames, scrypt password
  hashes, 0/1 password-change/admin flags, Fernet-encrypted active/pending TOTP
  secrets, hashed recovery codes, public passkey keys/counters, sessions, and
  an administrative audit trail. No passkey private keys are stored.
- WebAuthn challenges are browser/account/ceremony-bound, expire after five
  minutes, and are consumed even when verification fails. Origin, RP ID,
  user handle, signature, counter and user verification are checked.

## Local development and tests

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python configure.py             # Skip if .env already exists.
python app.py                  # Reads .env; localhost:8000.
python -m pytest -q
python -m pip_audit --progress-spinner off
```

Local development defaults to process-local limiter storage. Compose uses
Redis across both workers. Do not deploy the Flask development server.

Tests cover onboarding, role checks, forced changes, factor revocation, account
deletion, copied-cookie logout, session expiry, enrollment binding, TOTP drift/
replay/recovery/concurrency, and real cryptographic WebAuthn registration/login
and rejection cases. No external authenticator service is needed.
`pip-audit` checks installed dependencies against published vulnerability data;
it requires network access. Development/container tooling upgrades pip to a
patched version as well.

## Drop into another Flask app

Read [user_auth/README.md](user_auth/README.md) for the full account Blueprint
API and integration contract. Copy both `user_auth/` and `totp_2fa/` (including
templates/static assets) and install `requirements.txt`, or `pip install .`.
Replace the reference dashboard with your application and use
`user_auth.login_required` on every protected route.

The smaller, independently reusable TOTP-only module remains in `totp_2fa/`;
see [its guide](totp_2fa/README.md). `example_app.py` still runs that older
single-account demonstration; **`app.py` is the new full account application**.
Both references now revoke old sessions on enrollment and copied cookies on
logout.

## Production checklist

Use HTTPS with a trusted reverse proxy. Set `PUBLIC_ORIGIN` to the exact HTTPS
origin and `WEBAUTHN_RP_ID` to its hostname; secure cookies and HSTS then enable
automatically. Origin/RP configuration is intentionally strict (exact host,
not a parent-domain RP). Existing passkeys cannot move between RP hostnames.
Change the Compose bind/proxy arrangement intentionally; no arbitrary forwarded
headers are trusted by the application.

Keep servers NTP-synchronized, use persistent protected keys and backups, pin
reviewed dependencies/container images for your deployment, and retain shared
rate limits. Never log passwords, QR/provisioning secrets, or recovery codes.
For key rotation, migrate both active and pending Fernet values with the old
key before retiring it; simply replacing the key makes existing factors
unreadable. Protect/administer the audit trail and design your own verified
human account-recovery process; there is no anonymous reset endpoint.

The application is a security-oriented reference, not a claim of exhaustive
security certification. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for the
latest security-check results. Review [LICENSE](LICENSE) before reuse.
