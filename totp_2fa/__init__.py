"""Public integration API for the TOTP blueprint."""

import hmac
import hashlib
import os
import secrets
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, cast

from cryptography.fernet import InvalidToken
from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .service import FactorError, TOTPService
from .storage import SQLiteStore, TwoFactorState, TwoFactorStore

__all__ = [
    "TOTP2FA", "SQLiteStore", "TwoFactorState", "TwoFactorStore",
    "begin_login", "end_login", "login_and_2fa_required", "csrf_token", "validate_csrf",
]

P = ParamSpec("P")


def wants_json() -> bool:
    return request.is_json or (
        request.accept_mimetypes.best_match(["text/html", "application/json"])
        == "application/json"
    )


def csrf_token() -> str:
    token = session.get("_2fa_csrf")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["_2fa_csrf"] = token
    return token


def validate_csrf() -> None:
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get("_2fa_csrf")
    if (
        not isinstance(expected, str)
        or not isinstance(supplied, str)
        or not hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))
    ):
        abort(400, description="Missing or invalid CSRF token.")


def _extension() -> "TOTP2FA":
    return cast(TOTP2FA, current_app.extensions["totp_2fa"])


def _user_id() -> str:
    user_id = session.get("user_id")
    if not isinstance(user_id, str) or not user_id:
        abort(401, description="Password authentication is required.")
    token = session.get("_2fa_session_id")
    if not isinstance(token, str):
        abort(401, description="Log in again.")
    service = _extension().service
    with service.store.transaction(user_id) as state:
        expires = state.session_tokens.get(hashlib.sha256(token.encode()).hexdigest(), 0)
        if expires <= service.clock():
            abort(401, description="Session expired or revoked. Log in again.")
    return user_id


def login_and_2fa_required(
    view: Callable[P, ResponseReturnValue],
) -> Callable[P, ResponseReturnValue]:
    @wraps(view)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> ResponseReturnValue:
        _user_id()
        if session.get("auth_state") != "authenticated":
            if wants_json():
                abort(403, description="Complete two-factor authentication first.")
            return redirect(url_for("totp_2fa.verify"))
        return view(*args, **kwargs)

    return wrapped


def begin_login(user_id: str) -> bool:
    """Call ONLY after password validation; return whether a factor is required."""
    service = _extension().service
    token = secrets.token_urlsafe(32)
    with service.store.transaction(user_id) as state:
        required = state.secret is not None
        state.session_tokens = {
            key: expiry for key, expiry in state.session_tokens.items()
            if expiry > service.clock()
        }
        state.session_tokens[hashlib.sha256(token.encode()).hexdigest()] = (
            service.clock() + (600 if required else 3600)
        )
    session.clear()
    session["user_id"] = user_id
    session["auth_state"] = "2fa_pending" if required else "authenticated"
    session["_2fa_session_id"] = token
    csrf_token()
    return required


def end_login() -> None:
    """Revoke the current session server-side before removing its browser cookie."""
    user_id, token = session.get("user_id"), session.get("_2fa_session_id")
    if isinstance(user_id, str) and isinstance(token, str):
        with _extension().store.transaction(user_id) as state:
            state.session_tokens.pop(hashlib.sha256(token.encode()).hexdigest(), None)
    session.clear()


def _transition(token: str) -> tuple[str, str]:
    return (
        hashlib.sha256(session["_2fa_session_id"].encode()).hexdigest(),
        hashlib.sha256(token.encode()).hexdigest(),
    )


def _complete_login(user_id: str, token: str) -> None:
    session.clear()
    session.update(user_id=user_id, auth_state="authenticated", _2fa_session_id=token)
    csrf_token()


def _field(name: str) -> str:
    data = request.get_json() if request.is_json else request.form
    if request.is_json and not isinstance(data, dict):
        abort(400, description="JSON body must be an object.")
    value = data.get(name, "")
    if not isinstance(value, str):
        abort(400, description=f"{name} must be a string.")
    return value


def _reply(template: str, **data: object) -> ResponseReturnValue:
    if wants_json():
        return jsonify(**data, csrf_token=csrf_token())
    return render_template(f"totp_2fa/{template}.html", **data)


class TOTP2FA:
    def __init__(
        self,
        store: TwoFactorStore,
        *,
        account_name: Callable[[str], str],
        verify_password: Callable[[str, str], bool],
        success_endpoint: str = "dashboard",
    ) -> None:
        self.store = store
        self.account_name = account_name
        self.verify_password = verify_password
        self.success_endpoint = success_endpoint

    def init_app(self, app: Flask, *, url_prefix: str = "/2fa") -> None:
        if "totp_2fa" in app.extensions:
            raise ValueError("TOTP2FA is already registered on this app.")
        for key in ("SECRET_KEY", "TOTP_ENCRYPTION_KEY", "TOTP_ISSUER_NAME"):
            if not app.config.get(key):
                app.config[key] = os.environ.get(key)
            if not app.config.get(key):
                raise ValueError(
                    f"{key} is required. Generate a Fernet key with: "
                    "python -c 'from cryptography.fernet import Fernet; "
                    "print(Fernet.generate_key().decode())'"
                )
        try:
            self.service = TOTPService(
                self.store, app.config["TOTP_ENCRYPTION_KEY"], app.config["TOTP_ISSUER_NAME"]
            )
        except (ValueError, TypeError) as error:
            raise ValueError("TOTP_ENCRYPTION_KEY must be a valid Fernet key.") from error
        app.extensions["totp_2fa"] = self
        app.jinja_env.globals["csrf_token"] = csrf_token
        self.limiter = Limiter(
            key_func=lambda: str(session.get("user_id") or get_remote_address()),
            storage_uri=app.config.get("RATELIMIT_STORAGE_URI", "memory://"),
        )
        self.limiter.init_app(app)
        blueprint = Blueprint("totp_2fa", __name__, template_folder="templates")

        @blueprint.before_request
        def guard() -> None:
            _user_id()
            if request.method == "POST":
                validate_csrf()

        @blueprint.after_request
        def no_cache(response: Response) -> Response:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["Referrer-Policy"] = "no-referrer"
            return response

        @blueprint.errorhandler(FactorError)
        def factor_error(error: FactorError) -> ResponseReturnValue:
            if wants_json():
                return jsonify(error=str(error)), 400
            return render_template("totp_2fa/error.html", message=str(error)), 400

        @blueprint.errorhandler(InvalidToken)
        def encryption_error(error: InvalidToken) -> ResponseReturnValue:
            current_app.logger.error("Unable to decrypt stored TOTP secret", exc_info=error)
            message = "Stored 2FA data could not be decrypted. Contact support."
            if wants_json():
                return jsonify(error=message), 500
            return render_template("totp_2fa/error.html", message=message), 500

        @blueprint.route("/setup", methods=["GET", "POST"])
        @login_and_2fa_required
        @self.limiter.limit("5 per minute", methods=["POST"])
        def setup() -> ResponseReturnValue:
            user_id = _user_id()
            enrollment = self.service.setup(
                user_id, self.account_name(user_id), create=request.method == "POST"
            )
            return _reply("setup", enrollment=enrollment)

        @blueprint.post("/confirm")
        @login_and_2fa_required
        @self.limiter.limit("5 per minute")
        def confirm() -> ResponseReturnValue:
            user_id = _user_id()
            token = secrets.token_urlsafe(32)
            codes = self.service.confirm(
                user_id, _field("code").strip(), session_transition=_transition(token)
            )
            _complete_login(user_id, token)
            return _reply("recovery", backup_codes=codes)

        @blueprint.route("/verify", methods=["GET", "POST"])
        @self.limiter.limit("5 per minute", methods=["POST"])
        def verify() -> ResponseReturnValue:
            if session.get("auth_state") != "2fa_pending":
                abort(403, description="No two-factor login is pending.")
            if request.method == "POST":
                user_id = _user_id()
                token = secrets.token_urlsafe(32)
                self.service.verify(
                    user_id, _field("code").strip(), session_transition=_transition(token)
                )
                _complete_login(user_id, token)
                if wants_json():
                    return _reply("verify", authenticated=True)
                return redirect(url_for(self.success_endpoint))
            return _reply("verify", authenticated=False)

        @blueprint.route("/disable", methods=["GET", "POST"])
        @login_and_2fa_required
        @self.limiter.limit("5 per minute", methods=["POST"])
        def disable() -> ResponseReturnValue:
            if request.method == "POST":
                user_id = _user_id()
                password = _field("password")
                token = secrets.token_urlsafe(32)
                self.service.disable(
                    user_id,
                    _field("code").strip(),
                    password_verified=bool(password) and self.verify_password(user_id, password),
                    session_transition=_transition(token),
                )
                _complete_login(user_id, token)
                return _reply("disabled", disabled=True)
            return _reply("disable")

        app.register_blueprint(blueprint, url_prefix=url_prefix)
