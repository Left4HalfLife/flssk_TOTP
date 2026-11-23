"""Single-account demo; replace password login with your app's account system."""

import os
from pathlib import Path

from flask import Flask, Response, redirect, render_template, request, session, url_for
from flask.typing import ResponseReturnValue
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

from totp_2fa import (
    SQLiteStore,
    TOTP2FA,
    begin_login,
    end_login,
    login_and_2fa_required,
    validate_csrf,
)


def create_app(config: dict[str, object] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        TOTP_ENCRYPTION_KEY=os.environ.get("TOTP_ENCRYPTION_KEY"),
        TOTP_ISSUER_NAME=os.environ.get("TOTP_ISSUER_NAME", "Flask TOTP Demo"),
        DEMO_USERNAME=os.environ.get("DEMO_USERNAME", "demo"),
        DEMO_PASSWORD=os.environ.get("DEMO_PASSWORD"),
        RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)
    if not app.config["DEMO_PASSWORD"]:
        raise ValueError("Set DEMO_PASSWORD to a strong local demo password.")
    username = app.config["DEMO_USERNAME"]
    password_hash = generate_password_hash(app.config["DEMO_PASSWORD"])
    # The plaintext is only needed to bootstrap this demonstration account.
    app.config.pop("DEMO_PASSWORD")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(app.config.get("TOTP_DATABASE", Path(app.instance_path) / "totp.sqlite3"))

    def verify_password(user_id: str, password: str) -> bool:
        return user_id == username and check_password_hash(password_hash, password)

    two_factor = TOTP2FA(
        store, account_name=lambda user_id: user_id, verify_password=verify_password
    )
    two_factor.init_app(app)

    @app.route("/", methods=["GET", "POST"])
    @two_factor.limiter.limit("5 per minute", key_func=get_remote_address, methods=["POST"])
    def login() -> ResponseReturnValue:
        if request.method == "POST":
            validate_csrf()
            if (
                request.form.get("username") != username
                or not verify_password(username, request.form.get("password", ""))
            ):
                return render_template("login.html", error="Invalid credentials."), 401
            pending = begin_login(username)
            return redirect(url_for("totp_2fa.verify" if pending else "dashboard"))
        return render_template("login.html")

    @app.get("/dashboard")
    @login_and_2fa_required
    def dashboard() -> ResponseReturnValue:
        return render_template("dashboard.html", enabled=two_factor.service.enabled(username))

    @app.post("/logout")
    def logout() -> ResponseReturnValue:
        validate_csrf()
        end_login()
        return redirect(url_for("login"))

    @app.after_request
    def no_cache(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        return response

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000)
