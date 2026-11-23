# Reusing the full account Blueprint

The [root README](../README.md) covers Compose, environment setup, login policy,
and production requirements. This package adds users/passkeys/admin management
while reusing `totp_2fa.service.TOTPService`.

## Integration

```python
from pathlib import Path
from flask import Flask
from user_auth import UserAuth, login_required
from user_auth.database import Database

def create_app():
    app = Flask(__name__)
    # Supply these settings from your secret manager/environment.
    app.config.update(
        SECRET_KEY=your_random_session_key,
        TOTP_ENCRYPTION_KEY=your_persistent_fernet_key,
        TOTP_ISSUER_NAME="Your App",
        PUBLIC_ORIGIN="https://app.example.com",
        WEBAUTHN_RP_ID="app.example.com",
        RATELIMIT_STORAGE_URI="redis://redis:6379/0",
    )
    database = Database(Path(app.instance_path) / "accounts.sqlite3")
    accounts = UserAuth(database)
    accounts.init_app(app, url_prefix="/auth")
    # First startup only; no effect after bootstrap succeeds.
    database.bootstrap(initial_admin_username, initial_admin_password)

    @app.get("/private")
    @login_required
    def private():
        return "Your application"

    return app
```

The convenience `user_auth.create_app(config=None)` reads `.env`, constructs
SQLite storage, bootstraps the first admin, and registers the Blueprint.
`app.py` exposes it to Gunicorn. Create one extension per app.

`g.login` is a validated server-side `Login` record or `None`. Its `user` is a
fresh database `User`, never a role/ID trusted from an incoming cookie.
The signed Flask cookie holds only an opaque session token and a CSRF token.
`login_required` accepts only `phase == "full"`; restricted stages redirect to
the mandatory password-change, enrollment, or TOTP page.

Use `app.extensions["user_auth"]` for the extension, its `.db`, `.totp`, and
`.passkeys` services. Do not manufacture sessions with `Database.issue` or bypass
route guards; it is an internal transition API, not proof of authentication.
For privileged writes, recheck the current session inside the same transaction
using `Database.assert_login`. Password/TOTP and credential activation preserve
atomic consumption and version changes.

## Database and lifecycle

Tables are created automatically: `users`, `two_factor`, `passkeys`, `sessions`,
`challenges`, `totp_enrollments`, `audit`, and `metadata`. Foreign keys are enabled
on every connection. Every write uses `BEGIN IMMEDIATE`; this serialized adapter
is intentionally simple, suitable for modest applications rather than a
high-throughput multi-host database.

The `require_password_change` field is a constrained 0/1 integer.
`enrollment_allowed` explicitly permits initial/admin-reset onboarding and is
cleared when a method activates. Absence of methods alone never authorizes
password-only onboarding for an existing account. `auth_version` increments
when credentials/security policy change, and all affected sessions/challenges
are deleted atomically.

To adapt to a different database, preserve these invariants rather than copying
only the columns. Use UUID/stable IDs, unique normalized usernames, appropriate
row locks, compare-and-swap for counters/session versions, transactional
single-use factors, and cascading credential/session deletion. The account
adapter is separate from the generic `TwoFactorStore` interface; the full
account/admin/session API is SQLite-specific in this reference.

There is intentionally no registration-by-the-public, emailed reset token,
anonymous recovery, role editing, or privileged backdoor. Admins create accounts
and deliver temporary credentials through a separately trusted channel.
Revoking the last method locks a user; explicit admin reset changes their
password, deletes all methods, flags password change, and permits onboarding.

## Routes and customization

All endpoint names begin with `user_auth.`. URL prefixes are configurable, and
templates use `url_for` (including WebAuthn JavaScript endpoints), so mounting
under `/auth` does not break the flow. Override templates under
`user_auth/` in your host app. Static WebAuthn JavaScript is bundled locally.

| Routes | Purpose |
| --- | --- |
| `/`, `/logout` | Password login / server-side logout |
| `/verify-totp` | TOTP/recovery second login stage |
| `/password-change` | Required/voluntary password change |
| `/methods`, `/methods/remove` | Enrollment prompt and own method removal |
| `/totp/setup`, `/totp/confirm` | Bound encrypted enrollment and confirmation |
| `/passkeys/register/options`, `/passkeys/register/complete` | UV-required registration |
| `/passkeys/login/options`, `/passkeys/login/complete` | Discoverable passkey login |
| `/dashboard` | Example protected page |
| `/admin/users` | Admin list/create/force-change/revoke/reset/delete |
| `/health` | Database readiness without account data |

Every mutation is POST and validates CSRF. HTML forms use `csrf_token`; JSON
requests use `X-CSRF-Token`. The base template exposes the token in
`meta[name="csrf-token"]`. It rotates at every authentication transition; refresh
the page afterward. WebAuthn JSON failures have `{error: ...}` for expected
verification failures; Flask HTTP errors may be HTML. API-only apps can supply
uniform HTTP error handlers, but must retain cookie/CSRF and challenge binding.

Password strings are not normalized or stripped. Usernames are lowercased and
limited to 3-64 ASCII letters/digits/dot/underscore/hyphen. Passwords use
Werkzeug's scrypt and must be 12-128 characters for creation/change. Temporary
bootstrap `.env` passwords must also follow dotenv escaping/interpolation rules;
`configure.py` rejects `$`/line-break/NUL characters specifically for that file.

Security headers, trusted hosts, cookie flags, and maximum request size are
configured by `init_app` for the host app as a whole. Review these global settings
when integrating with an existing application. It does not install `ProxyFix`;
configure strictly bounded proxy trust separately if required. The limiter
defaults to per-IP 120/minute, tighter login/ceremony limits, and per-account
password/TOTP limits. Redis failure fails closed rather than bypassing limits.
