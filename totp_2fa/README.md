# Integrating `totp_2fa`

For a runnable demo, environment/key generation commands, and test instructions,
see the [repository quickstart](../README.md).

## 1. Install and configure

Copy this package (including `templates/`) into your project and install the
repository's `requirements.txt`, or install the repository with pip.

Set `SECRET_KEY`, `TOTP_ENCRYPTION_KEY`, and `TOTP_ISSUER_NAME` in the Flask
config or environment. Registration fails explicitly when a required setting
is absent or the encryption key is invalid.

Generate a Fernet key once, store it in a secret manager, and reuse it:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Fernet keys are URL-safe base64 encodings of 32 random bytes; a password or
arbitrary string is not a valid replacement. `SECRET_KEY` signs Flask sessions;
it is a separate secret, not the encryption key.

## 2. Register the extension

Create one extension instance per Flask app inside its application factory:

```python
from pathlib import Path
from flask import Flask
from werkzeug.security import check_password_hash
from totp_2fa import SQLiteStore, TOTP2FA

def create_app():
    app = Flask(__name__)  # Load your normal config first.
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(Path(app.instance_path) / "totp.sqlite3")

    def account_name(user_id: str) -> str:
        return users.get(user_id).username  # Your existing account repository.

    def verify_password(user_id: str, password: str) -> bool:
        user = users.get(user_id)
        return user is not None and check_password_hash(user.password_hash, password)

    TOTP2FA(
        store,
        account_name=account_name,
        verify_password=verify_password,
        success_endpoint="dashboard",  # Or "main.dashboard", etc.
    ).init_app(app, url_prefix="/2fa")
    return app
```

`users` above is your app's repository, not a bundled model. The extension
exposes its service and limiter through `app.extensions["totp_2fa"]`. Templates
live under `totp_2fa/`; override them in your app's template directory without
changing the Blueprint. Blueprint endpoint names stay `totp_2fa.setup`,
`totp_2fa.confirm`, `totp_2fa.verify`, and `totp_2fa.disable` even if the URL
prefix changes.

## 3. Replace or implement persistence

`SQLiteStore` stores only 2FA state, keyed by your stable string user ID. It
does not store or validate passwords. It creates its table automatically and
needs a file-backed database, not `:memory:`. A missing state is initialized
as disabled.

To use an existing ORM, implement `TwoFactorStore.transaction(user_id)` as a
context manager yielding mutable `TwoFactorState`, then pass your adapter
instead of `SQLiteStore`:

| Field | Storage |
| --- | --- |
| `secret` | Active Fernet ciphertext, or `None` |
| `pending_secret` | Pending Fernet ciphertext, or `None` |
| `pending_expires_at` | UNIX timestamp; setup lasts ten minutes |
| `last_used_timecode` | Largest consumed TOTP step, initially `-1` |
| `backup_hashes` | List of SHA-256 recovery-code digests |
| `session_tokens` | Server-side session token digests mapped to absolute expiry |

**Atomicity is mandatory:** lock the user row across the entire read/check/write
operation, persist the yielded state on successful exit, and roll back on any
exception. For SQLAlchemy, use an appropriate transaction with
`SELECT ... FOR UPDATE` on databases that support row locks. Handle initial-row
creation races using your DB's constraints/locking; `FOR UPDATE` on a missing
row alone is insufficient. SQLite's reference adapter uses `BEGIN IMMEDIATE`.
Do not implement verification as separate read and save calls: concurrent
requests could otherwise reuse a TOTP or recovery code.

Recovery codes contain 80 random bits each; unsalted SHA-256 is appropriate for
these high-entropy tokens, **not** for user passwords. Plaintext codes appear
only in the successful confirmation response; there is no retrieval endpoint.
Protect the database, backups, and encryption key separately.

## 4. Wire password login and protected routes

```python
from flask import redirect, session, url_for
from totp_2fa import begin_login, login_and_2fa_required

# Inside your login view, ONLY after checking the username/password:
pending = begin_login(str(user.id))
return redirect(url_for("totp_2fa.verify" if pending else "dashboard"))

@app.get("/dashboard")
@login_and_2fa_required
def dashboard():
    return "Authenticated"
```

`begin_login` clears the old session and sets `user_id` plus `auth_state`:
`2fa_pending` for enrolled users, `authenticated` otherwise. Only successful
`/2fa/verify` upgrades pending sessions; it clears the session again and rotates
the CSRF token. The guard denies anonymous access and redirects pending HTML
requests to verification (JSON requests receive 403).

The demo's `example_app.py` shows the complete working password, dashboard, and
POST logout flow. The extension owns these session keys; adapt your existing
login framework deliberately rather than assuming `Flask-Login.login_required`
alone enforces the second stage. `session.clear()` does not regenerate the
session identifier of every server-side session backend; regenerate that ID
using your backend's API at authentication transitions.

Enabling/disabling 2FA revokes all earlier module sessions. The successful
initiating request receives a new server-tracked token; stale password-only
cookies cannot authorize the newly enrolled account. Use `end_login()` for
logout so a copied cookie is revoked too (not just `session.clear()`).
Module sessions expire after one hour, or ten minutes while 2FA is pending.
Your host app must still implement account deletion/suspension checks and
revocation after password changes (clear the user's `session_tokens` atomically).
The guard authorizes a completed session; it does not enforce mandatory
enrollment for all users. Enforce that policy separately if desired.

For a full SQLite user/admin/passkey template with mandatory onboarding,
password-change flags and a strict passkey-or-password+TOTP policy, use
[`user_auth`](../user_auth/README.md) instead.

## 5. HTML and JSON endpoints

All endpoints require password authentication. Setup, confirmation, and disable
require a completed login; verify requires `2fa_pending`.

| Endpoint | Behavior |
| --- | --- |
| `GET /2fa/setup` | Display pending enrollment or the start button; never generate a new secret |
| `POST /2fa/setup` | Create/reuse encrypted pending enrollment; return QR, URI, manual secret |
| `POST /2fa/confirm` | Activate after a valid six-digit code; return ten recovery codes once |
| `GET/POST /2fa/verify` | Show prompt / consume TOTP or recovery code and finish login |
| `GET/POST /2fa/disable` | Show prompt / require current password **or** unused TOTP/recovery code, clear state |

Re-enrollment requires disabling first. Confirmation consumes its time step,
so that code cannot immediately be reused for login or disable. TOTP accepts
`valid_window=1` (current step +/- one 30-second step); any matched step at or
below `last_used_timecode` is rejected. Consuming a future-window code also
blocks earlier steps until the clock catches up.

Send `Accept: application/json` for GET JSON responses; JSON POST bodies select
JSON automatically. A setup response has
`enrollment: {secret, provisioning_uri, qr_data_uri}` (or `null` on an initial
GET), confirmation has `backup_codes`, verification success has
`authenticated: true`, and disable success has `disabled: true`.

Every JSON success also includes `csrf_token`. Send it in `X-CSRF-Token` on
every POST; HTML forms use the hidden `csrf_token` input. Keep same-origin
session cookies. After password login the token changes, so fetch the appropriate
GET endpoint before the next POST. The host password-login and logout endpoints
must also validate CSRF (see `validate_csrf` in the example).

```javascript
const page = await fetch("/2fa/verify", {
  headers: {Accept: "application/json"}
}).then(r => r.json());
const result = await fetch("/2fa/verify", {
  method: "POST",
  headers: {"Content-Type": "application/json", "X-CSRF-Token": page.csrf_token},
  body: JSON.stringify({code: "123456"})
});
```

Expected factor failures return 400 with `{error: "..."}` for JSON; authorization,
CSRF, malformed requests, and limiter failures use Flask's standard HTTP errors
(which may be HTML). Adapt your app's HTTP error handlers if it requires a
uniform JSON error envelope. Decryption failure is logged and returns 500;
never silently reset encrypted state when a key is wrong.

## Production checklist

- Synchronize servers with NTP; use HTTPS, secure/HttpOnly/SameSite cookies, a
  strong persistent `SECRET_KEY`, and appropriate session lifetime/revocation.
- Replace the demo account with your own password hashing and account lifecycle.
  Protect every private route with the two-stage guard or equivalent policy.
- Use shared limiter storage for multiple workers/hosts:
  set `RATELIMIT_STORAGE_URI=redis://...` and install the Redis dependency
  (`pip install 'Flask-Limiter[redis]'`). `memory://` is local-demo only.
  The Blueprint limits each POST endpoint to five attempts/minute per user;
  password login also needs its own rate limit (the demo limits it per IP).
  Keep CSRF validation on; it is independent of rate limiting.
- Configure proxy trust explicitly before relying on client IPs. Add host-level
  anti-abuse controls, monitoring, and a restrictive CSP permitting local QR
  images via `img-src 'self' data:`. Never log codes, provisioning URIs, or keys.
- Rotate encryption keys with an explicit offline/restricted migration:
  decrypt both active and pending values with the old key, encrypt with the
  new key atomically, coordinate deployment, then retire the old key. Simply
  changing the environment key makes existing factors unreadable. Consider
  `MultiFernet` in a custom service for staged rotation; it is not configured here.
- Back up encrypted state securely and test restore. Lost factors and exhausted
  recovery codes require a separately designed, audited account-recovery
  procedure; there is intentionally no unauthenticated reset endpoint.
- Do not use Flask's development server or in-memory rate limits in production.
  Review the repository license and adapt the reference to your threat model.
