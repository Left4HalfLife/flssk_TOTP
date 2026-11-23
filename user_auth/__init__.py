"""Drop-in account blueprint: passkey OR password + TOTP, never password-only."""

import json
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import asdict
from functools import wraps
from pathlib import Path
from typing import ParamSpec
from urllib.parse import urlsplit

from cryptography.fernet import InvalidToken
from dotenv import load_dotenv
from flask import (
    Blueprint, Flask, Response, abort, current_app, g, jsonify, redirect,
    render_template, request, session, url_for,
)
from flask.typing import ResponseReturnValue
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

from totp_2fa import csrf_token, validate_csrf
from totp_2fa.service import FactorError, TOTPService
from totp_2fa.storage import TwoFactorState

from .database import AccountError, AccountTOTPStore, Database, Login, digest, validate_password
from .passkeys import Passkeys

P = ParamSpec("P")
PHASE_ENDPOINTS = {
    "totp": "user_auth.verify_totp",
    "password_change": "user_auth.password_change",
    "enroll": "user_auth.methods",
}


def field(name: str) -> str:
    data = request.get_json() if request.is_json else request.form
    if request.is_json and not isinstance(data, dict):
        abort(400, description="JSON body must be an object.")
    value = data.get(name, "")
    if not isinstance(value, str):
        abort(400, description=f"{name} must be a string.")
    return value


def credential_body() -> dict:
    data = request.get_json()
    if not isinstance(data, dict) or not isinstance(data.get("credential"), dict):
        abort(400, description="A credential object is required.")
    return data["credential"]


def phase_required(*phases: str, admin: bool = False, fresh: bool = False):
    def decorate(view: Callable[P, ResponseReturnValue]) -> Callable[P, ResponseReturnValue]:
        @wraps(view)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> ResponseReturnValue:
            login: Login | None = g.login
            if login is None:
                if request.is_json or request.method != "GET":
                    abort(401, description="Log in first.")
                return redirect(url_for("user_auth.login"))
            if login.phase not in phases:
                if request.is_json:
                    abort(403, description="Complete password change and enrollment first.")
                return redirect(url_for(PHASE_ENDPOINTS.get(login.phase, "user_auth.dashboard")))
            if admin and not login.user.is_admin:
                abort(403, description="Administrator access required.")
            if fresh and login.auth_at + 300 <= current_app.extensions["user_auth"].db.clock():
                abort(403, description="Log in again for recent authentication.")
            return view(*args, **kwargs)
        return wrapped
    return decorate


login_required = phase_required("full")


class UserAuth:
    def __init__(self, database: Database) -> None:
        self.db = database

    def init_app(self, app: Flask, *, url_prefix: str = "") -> None:
        if "user_auth" in app.extensions:
            raise ValueError("UserAuth is already registered.")
        if (
            not app.config.get("SECRET_KEY") or len(app.config["SECRET_KEY"]) < 32
            or app.config["SECRET_KEY"].startswith("replace-with-")
        ):
            raise ValueError("SECRET_KEY must contain at least 32 random characters.")
        origin = app.config["PUBLIC_ORIGIN"].rstrip("/")
        parsed = urlsplit(origin)
        rp_id = app.config["WEBAUTHN_RP_ID"]
        if (
            parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.path or parsed.query or parsed.fragment or parsed.username
            or parsed.password or parsed.hostname != rp_id
            or (parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1"})
        ):
            raise ValueError("PUBLIC_ORIGIN must be an exact HTTPS origin (HTTP only on localhost), with host matching WEBAUTHN_RP_ID.")
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
            SESSION_COOKIE_SECURE=parsed.scheme == "https",
            TRUSTED_HOSTS=[parsed.hostname],
            MAX_CONTENT_LENGTH=32 * 1024,
        )
        try:
            self.store = AccountTOTPStore(self.db)
            self.totp = TOTPService(
                self.store, app.config["TOTP_ENCRYPTION_KEY"],
                app.config["TOTP_ISSUER_NAME"], clock=self.db.clock,
            )
        except (ValueError, TypeError) as error:
            raise ValueError("Generate TOTP_ENCRYPTION_KEY with Fernet.generate_key().") from error
        self.passkeys = Passkeys(self.db, rp_id, origin, app.config["TOTP_ISSUER_NAME"])
        self.dummy_hash = generate_password_hash("not-a-real-password-" + os.urandom(16).hex())
        self.limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=app.config.get("RATELIMIT_STORAGE_URI", "memory://"),
            default_limits=["120 per minute"],
        )
        app.extensions["user_auth"] = self
        app.jinja_env.globals["csrf_token"] = csrf_token
        blueprint = Blueprint(
            "user_auth", __name__, template_folder="templates",
            static_folder="static", static_url_path="/auth-static",
        )

        @app.before_request
        def load_login() -> None:
            token = session.get("_auth_token")
            g.login = self.db.load_login(token if isinstance(token, str) else None)

        self.limiter.init_app(app)

        @blueprint.before_request
        def protect_post() -> None:
            if request.method == "POST":
                validate_csrf()

        @app.after_request
        def security_headers(response: Response) -> Response:
            response.headers.update({
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
            })
            if parsed.scheme == "https":
                response.headers["Strict-Transport-Security"] = "max-age=31536000"
            return response

        @blueprint.errorhandler(AccountError)
        @blueprint.errorhandler(FactorError)
        def expected_error(error: ValueError) -> ResponseReturnValue:
            if request.is_json:
                return jsonify(error=str(error)), 400
            return render_template("user_auth/error.html", message=str(error)), 400

        @blueprint.errorhandler(InvalidToken)
        def decrypt_error(error: InvalidToken) -> ResponseReturnValue:
            app.logger.error("Stored TOTP ciphertext could not be decrypted", exc_info=error)
            return jsonify(error="2FA data unavailable. Contact an administrator."), 500

        @blueprint.get("/health")
        def health() -> ResponseReturnValue:
            with self.db.write() as connection:
                connection.execute("SELECT 1")
            return jsonify(status="ok")

        @blueprint.route("/", methods=["GET", "POST"])
        @self.limiter.limit("5 per minute", methods=["POST"])
        @self.limiter.limit(
            "10 per minute",
            key_func=lambda: digest(field("username").lower()),
            methods=["POST"],
        )
        def login() -> ResponseReturnValue:
            if request.method == "POST":
                username, password = field("username"), field("password")
                user = self.db.find_user(username)
                valid = len(password) <= 128 and check_password_hash(
                    user.password_hash if user else self.dummy_hash, password
                )
                if not user or not valid:
                    return render_template("user_auth/login.html", error="Invalid credentials."), 401
                with self.db.write() as connection:
                    user = self.db.user(connection, user.id)
                    # Recheck against the current hash under the transaction.
                    if not check_password_hash(user.password_hash, password):
                        raise AccountError("Credentials changed. Log in again.")
                    if self.db.has_totp(connection, user.id):
                        phase = "totp"
                    elif not self.db.has_passkey(connection, user.id) and user.enrollment_allowed:
                        phase = "password_change" if user.require_password_change else "enroll"
                    else:
                        return render_template(
                            "user_auth/login.html",
                            error="Use your passkey. Password login requires an enrolled TOTP.",
                        ), 401
                self.replace_login(user.id, user.auth_version, phase, "password")
                return self.next_page()
            return render_template("user_auth/login.html")

        @blueprint.post("/logout")
        def logout() -> ResponseReturnValue:
            self.db.revoke(session.get("_auth_token"))
            session.clear()
            return redirect(url_for("user_auth.login"))

        @blueprint.route("/verify-totp", methods=["GET", "POST"])
        @phase_required("totp")
        @self.limiter.limit("5 per minute", methods=["POST"])
        @self.limiter.limit(
            "5 per minute", key_func=lambda: g.login.user.id, methods=["POST"]
        )
        def verify_totp() -> ResponseReturnValue:
            login: Login = g.login
            if request.method == "POST":
                with self.store.authorized(login):
                    self.totp.verify(login.user.id, field("code").strip())
                phase = "password_change" if login.user.require_password_change else "full"
                self.replace_login(login.user.id, login.user.auth_version, phase, "password_totp")
                return self.next_page()
            return render_template("user_auth/verify.html")

        @blueprint.route("/password-change", methods=["GET", "POST"])
        @phase_required("password_change", "full", fresh=True)
        @self.limiter.limit("5 per minute", methods=["POST"])
        def password_change() -> ResponseReturnValue:
            login: Login = g.login
            if request.method == "POST":
                password = field("new_password")
                validate_password(password)
                with self.db.write() as connection:
                    user = self.db.assert_login(connection, login, fresh=True)
                    if login.method != "passkey" and not check_password_hash(
                        user.password_hash, field("current_password")
                    ):
                        raise AccountError("Current password is incorrect.")
                    if check_password_hash(user.password_hash, password):
                        raise AccountError("Choose a different password.")
                    connection.execute(
                        "UPDATE users SET password_hash=?,require_password_change=0 WHERE id=?",
                        (generate_password_hash(password), user.id),
                    )
                    self.db.bump(connection, user.id)
                    self.db.audit(connection, user.id, user.id, "password_changed")
                phase = "full" if login.method in {"passkey", "password_totp"} else "enroll"
                self.replace_login(
                    user.id, user.auth_version + 1, phase, login.method, auth_at=login.auth_at
                )
                return self.next_page()
            return render_template("user_auth/password.html", login=login)

        @blueprint.get("/dashboard")
        @login_required
        def dashboard() -> ResponseReturnValue:
            return render_template("user_auth/dashboard.html", login=g.login)

        @blueprint.get("/methods")
        @phase_required("enroll", "full")
        def methods() -> ResponseReturnValue:
            with self.db.write() as connection:
                credentials = connection.execute(
                    "SELECT credential_id,name FROM passkeys WHERE user_id=?", (g.login.user.id,)
                ).fetchall()
                enabled = self.db.has_totp(connection, g.login.user.id)
            return render_template(
                "user_auth/methods.html", login=g.login, passkeys=credentials, totp_enabled=enabled
            )

        @blueprint.route("/totp/setup", methods=["GET", "POST"])
        @phase_required("enroll", "full", fresh=True)
        @self.limiter.limit("5 per minute", methods=["POST"])
        def totp_setup() -> ResponseReturnValue:
            login: Login = g.login
            if request.method == "POST":
                self.claim_enrollment(login)
            with self.db.write() as connection:
                owner = connection.execute(
                    "SELECT token_hash FROM totp_enrollments WHERE user_id=?", (login.user.id,)
                ).fetchone()
            enrollment = None
            if owner and owner["token_hash"] == login.token_hash:
                with self.store.authorized(login):
                    enrollment = self.totp.setup(
                        login.user.id, login.user.username, create=request.method == "POST"
                    )
            return render_template("user_auth/totp_setup.html", enrollment=enrollment)

        @blueprint.post("/totp/confirm")
        @phase_required("enroll", "full", fresh=True)
        @self.limiter.limit("5 per minute")
        def totp_confirm() -> ResponseReturnValue:
            login: Login = g.login
            with self.db.write() as connection:
                self.db.assert_login(connection, login, fresh=True)
                owner = connection.execute(
                    "SELECT token_hash FROM totp_enrollments WHERE user_id=?", (login.user.id,)
                ).fetchone()
                if not owner or owner["token_hash"] != login.token_hash:
                    raise AccountError("Start enrollment in this session first.")
            with self.store.authorized(login):
                codes = self.totp.confirm(login.user.id, field("code").strip())
            self.replace_login(login.user.id, login.user.auth_version + 1, "full", "password_totp")
            return render_template("user_auth/recovery.html", backup_codes=codes)

        @blueprint.post("/passkeys/register/options")
        @phase_required("enroll", "full", fresh=True)
        @self.limiter.limit("5 per minute")
        def register_options() -> ResponseReturnValue:
            challenge_id, options = self.passkeys.registration_options(g.login)
            return jsonify(challenge_id=challenge_id, options=options)

        @blueprint.post("/passkeys/register/complete")
        @phase_required("enroll", "full", fresh=True)
        @self.limiter.limit("5 per minute")
        def register_complete() -> ResponseReturnValue:
            login: Login = g.login
            version = self.passkeys.register(
                login, field("challenge_id"), credential_body(), field("name")
            )
            self.replace_login(login.user.id, version, "full", "passkey")
            return jsonify(redirect=url_for("user_auth.methods"))

        @blueprint.post("/passkeys/login/options")
        @self.limiter.limit("5 per minute")
        def passkey_options() -> ResponseReturnValue:
            challenge_id, options = self.passkeys.authentication_options(digest(csrf_token()))
            return jsonify(challenge_id=challenge_id, options=options)

        @blueprint.post("/passkeys/login/complete")
        @self.limiter.limit("5 per minute")
        def passkey_complete() -> ResponseReturnValue:
            user = self.passkeys.authenticate(
                field("challenge_id"), digest(csrf_token()), credential_body()
            )
            phase = "password_change" if user.require_password_change else "full"
            self.replace_login(user.id, user.auth_version, phase, "passkey")
            return jsonify(redirect=self.next_url())

        @blueprint.post("/methods/remove")
        @phase_required("full", fresh=True)
        @self.limiter.limit("5 per minute")
        def remove_method() -> ResponseReturnValue:
            login: Login = g.login
            with self.db.write() as connection:
                user = self.db.assert_login(connection, login, fresh=True)
                self.remove_credential(connection, user.id, field("method"), field("credential_id"))
                if not self.db.has_totp(connection, user.id) and not self.db.has_passkey(connection, user.id):
                    raise AccountError("Enroll another method before removing your last method.")
                self.db.bump(connection, user.id)
                self.db.audit(connection, user.id, user.id, "method_removed")
            self.db.revoke(session.get("_auth_token"))
            session.clear()
            return redirect(url_for("user_auth.login"))

        @blueprint.route("/admin/users", methods=["GET", "POST"])
        @phase_required("full", admin=True)
        @self.limiter.limit("10 per minute", methods=["POST"])
        def admin_users() -> ResponseReturnValue:
            if request.method == "POST":
                self.admin_action(g.login)
                return redirect(url_for("user_auth.admin_users"))
            with self.db.write() as connection:
                users = connection.execute("SELECT * FROM users ORDER BY username").fetchall()
                rows = [
                    {
                        **dict(row), "totp": self.db.has_totp(connection, row["id"]),
                        "passkeys": connection.execute(
                            "SELECT credential_id,name FROM passkeys WHERE user_id=?", (row["id"],)
                        ).fetchall(),
                    }
                    for row in users
                ]
            return render_template("user_auth/users.html", users=rows, login=g.login)

        app.register_blueprint(blueprint, url_prefix=url_prefix)

    def replace_login(
        self, user_id: str, version: int, phase: str, method: str, *,
        auth_at: float | None = None,
    ) -> None:
        token = self.db.issue(
            user_id, version, phase, method,
            old_token=session.get("_auth_token"), auth_at=auth_at,
        )
        session.clear()
        session["_auth_token"] = token
        csrf_token()
        g.login = self.db.load_login(token)

    def next_url(self) -> str:
        login: Login = g.login
        endpoint = PHASE_ENDPOINTS.get(login.phase)
        if endpoint is None:
            endpoint = "user_auth.admin_users" if login.user.is_admin else "user_auth.dashboard"
        return url_for(endpoint)

    def next_page(self) -> ResponseReturnValue:
        return redirect(self.next_url())

    def claim_enrollment(self, login: Login) -> None:
        with self.db.write() as connection:
            self.db.assert_login(connection, login, fresh=True)
            owner = connection.execute(
                "SELECT e.token_hash,s.expires FROM totp_enrollments e "
                "JOIN sessions s ON s.token_hash=e.token_hash WHERE e.user_id=?",
                (login.user.id,),
            ).fetchone()
            if owner and owner["token_hash"] != login.token_hash and owner["expires"] > self.db.clock():
                raise AccountError("Enrollment is already in progress in another session.")
            if not owner or owner["token_hash"] != login.token_hash:
                row = connection.execute(
                    "SELECT state FROM two_factor WHERE user_id=?", (login.user.id,)
                ).fetchone()
                state = TwoFactorState(**json.loads(row["state"])) if row else TwoFactorState()
                state.pending_secret = None
                state.pending_expires_at = None
                connection.execute(
                    "INSERT INTO two_factor VALUES (?,?) "
                    "ON CONFLICT(user_id) DO UPDATE SET state=excluded.state",
                    (login.user.id, json.dumps(asdict(state))),
                )
            connection.execute(
                "INSERT INTO totp_enrollments VALUES (?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash",
                (login.user.id, login.token_hash),
            )

    def remove_credential(
        self, connection: sqlite3.Connection, user_id: str, method: str, credential_id: str
    ) -> None:
        if method == "totp":
            connection.execute(
                "UPDATE two_factor SET state=? WHERE user_id=?",
                (json.dumps(asdict(TwoFactorState())), user_id),
            )
        elif method == "passkey":
            cursor = connection.execute(
                "DELETE FROM passkeys WHERE user_id=? AND credential_id=?",
                (user_id, credential_id),
            )
            if not cursor.rowcount:
                raise AccountError("Passkey is unavailable.")
        else:
            raise AccountError("Unknown authentication method.")

    def admin_action(self, login: Login) -> None:
        action, target = field("action"), field("user_id")
        with self.db.write() as connection:
            actor = self.db.assert_login(connection, login, admin=True, fresh=True)
            if action == "create":
                target = self.db.create_user(
                    connection, field("username"), field("temporary_password"),
                    is_admin=field("is_admin") == "1",
                )
            else:
                user = self.db.user(connection, target)
                if action == "force_password":
                    connection.execute("UPDATE users SET require_password_change=1 WHERE id=?", (target,))
                    self.db.bump(connection, target)
                elif action == "reset":
                    if target == actor.id:
                        raise AccountError("Use your own password-change page instead.")
                    password = field("temporary_password")
                    validate_password(password)
                    connection.execute(
                        "UPDATE users SET password_hash=?,require_password_change=1,"
                        "enrollment_allowed=1 WHERE id=?",
                        (generate_password_hash(password), target),
                    )
                    connection.execute("DELETE FROM passkeys WHERE user_id=?", (target,))
                    connection.execute("DELETE FROM two_factor WHERE user_id=?", (target,))
                    self.db.bump(connection, target)
                elif action == "remove_method":
                    self.remove_credential(connection, target, field("method"), field("credential_id"))
                    if target == actor.id and not (
                        self.db.has_totp(connection, target) or self.db.has_passkey(connection, target)
                    ):
                        raise AccountError("Cannot revoke your own last method.")
                    self.db.bump(connection, target)
                elif action == "delete":
                    if target == actor.id:
                        raise AccountError("Cannot delete the current administrator.")
                    count = connection.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0]
                    if user.is_admin and count <= 1:
                        raise AccountError("Cannot delete the last administrator.")
                    connection.execute("DELETE FROM users WHERE id=?", (target,))
                else:
                    raise AccountError("Unknown administrator action.")
            self.db.audit(connection, actor.id, target, action)


def create_app(config: dict[str, object] | None = None) -> Flask:
    load_dotenv()
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        TOTP_ENCRYPTION_KEY=os.environ.get("TOTP_ENCRYPTION_KEY"),
        TOTP_ISSUER_NAME=os.environ.get("TOTP_ISSUER_NAME", "Flask Accounts"),
        PUBLIC_ORIGIN=os.environ.get("PUBLIC_ORIGIN", "http://localhost:8000"),
        WEBAUTHN_RP_ID=os.environ.get("WEBAUTHN_RP_ID", "localhost"),
        ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_INITIAL_PASSWORD=os.environ.get("ADMIN_INITIAL_PASSWORD", ""),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "accounts.sqlite3")),
        RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    )
    if config:
        app.config.update(config)
    database = Database(app.config["DATABASE_PATH"], clock=app.config.get("AUTH_CLOCK", time.time))
    extension = UserAuth(database)
    extension.init_app(app)
    database.bootstrap(app.config["ADMIN_USERNAME"], app.config["ADMIN_INITIAL_PASSWORD"])
    app.config.pop("ADMIN_INITIAL_PASSWORD")
    return app
