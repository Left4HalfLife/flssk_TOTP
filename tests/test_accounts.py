import base64
import hashlib
import json
import secrets

import cbor2
import pyotp
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from user_auth import create_app

INITIAL = "initial-admin-password"
CHANGED = "changed-admin-password"
USER_INITIAL = "initial-user-password"
USER_CHANGED = "changed-user-password"


@pytest.fixture
def app(tmp_path):
    now = [1_800_000_015.0]
    app = create_app({
        "TESTING": True, "SECRET_KEY": secrets.token_hex(32),
        "TOTP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "TOTP_ISSUER_NAME": "Account Tests", "ADMIN_USERNAME": "admin",
        "ADMIN_INITIAL_PASSWORD": INITIAL,
        "DATABASE_PATH": str(tmp_path / "accounts.sqlite3"),
        "PUBLIC_ORIGIN": "http://localhost:8000", "WEBAUTHN_RP_ID": "localhost",
        "RATELIMIT_ENABLED": False, "AUTH_CLOCK": lambda: now[0],
    })
    app.config["TEST_CLOCK"] = now
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    with client.session_transaction() as session:
        return session["_2fa_csrf"]


def post(client, path, **data):
    return client.post(path, data={**data, "csrf_token": csrf(client)})


def json_post(client, path, **data):
    return client.post(path, json=data, headers={"X-CSRF-Token": csrf(client)})


def password_login(client, username="admin", password=INITIAL):
    client.get("/")
    return post(client, "/", username=username, password=password)


def change_password(client, old=INITIAL, new=CHANGED):
    return post(client, "/password-change", current_password=old, new_password=new)


def enroll_totp(app, client):
    response = post(client, "/totp/setup")
    assert response.status_code == 200
    extension = app.extensions["user_auth"]
    with client.session_transaction() as session:
        login = extension.db.load_login(session["_auth_token"])
    with extension.store.transaction(login.user.id) as state:
        secret = extension.totp._decrypt(state.pending_secret)
    response = post(
        client, "/totp/confirm", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])
    )
    assert response.status_code == 200
    return secret


@pytest.fixture
def admin(app, client):
    assert password_login(client).location.endswith("/password-change")
    assert change_password(client).location.endswith("/methods")
    secret = enroll_totp(app, client)
    return client, secret


def login_totp(app, client, secret, username="admin", password=CHANGED):
    response = password_login(client, username, password)
    assert response.location.endswith("/verify-totp")
    app.config["TEST_CLOCK"][0] += 30
    return post(client, "/verify-totp", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0]))


def create_user(admin_client, username="alice"):
    response = post(
        admin_client, "/admin/users", action="create", username=username,
        temporary_password=USER_INITIAL,
    )
    assert response.status_code == 302


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class VirtualPasskey:
    """Real ECDSA signatures and WebAuthn packets, not a mocked verifier."""

    def __init__(self, user_id):
        self.user_id = user_id
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.count = 0

    def registration(self, options, *, origin="http://localhost:8000", flags=0x45):
        public = self.key.public_key().public_numbers()
        cose = cbor2.dumps({
            1: 2, 3: -7, -1: 1,
            -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big"),
        })
        auth_data = (
            hashlib.sha256(b"localhost").digest() + bytes([flags]) + b"\0" * 4
            + b"\0" * 16 + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id + cose
        )
        client_data = json.dumps({
            "type": "webauthn.create", "challenge": options["challenge"], "origin": origin,
        }).encode()
        return {
            "id": b64(self.credential_id), "rawId": b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data),
                "attestationObject": b64(cbor2.dumps({
                    "fmt": "none", "attStmt": {}, "authData": auth_data,
                })),
            },
        }

    def assertion(
        self, options, *, origin="http://localhost:8000", flags=0x05,
        user_id=None, challenge=None, rp_id="localhost",
    ):
        self.count += 1
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest() + bytes([flags])
            + self.count.to_bytes(4, "big")
        )
        client_data = json.dumps({
            "type": "webauthn.get", "challenge": challenge or options["challenge"],
            "origin": origin,
        }).encode()
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64(self.credential_id), "rawId": b64(self.credential_id),
            "type": "public-key", "response": {
                "clientDataJSON": b64(client_data), "authenticatorData": b64(auth_data),
                "signature": b64(signature),
                "userHandle": b64((user_id or self.user_id).encode()),
            },
        }


def register_passkey(app, client):
    user = app.extensions["user_auth"].db.find_user("admin")
    key = VirtualPasskey(user.id)
    options = json_post(client, "/passkeys/register/options").json
    response = json_post(
        client, "/passkeys/register/complete", challenge_id=options["challenge_id"],
        credential=key.registration(options["options"]), name="Test device",
    )
    assert response.status_code == 200, response.data
    return key


def passkey_login(client, key, **kwargs):
    client.get("/")
    options = json_post(client, "/passkeys/login/options").json
    credential = key.assertion(options["options"], **kwargs)
    return json_post(
        client, "/passkeys/login/complete", challenge_id=options["challenge_id"],
        credential=credential,
    )


def test_bootstrap_and_restricted_onboarding(app, client):
    user = app.extensions["user_auth"].db.find_user("admin")
    assert user.require_password_change == 1 and user.is_admin == 1
    assert user.password_hash != INITIAL and user.password_hash.startswith("scrypt:")
    assert "ADMIN_INITIAL_PASSWORD" not in app.config
    assert password_login(client).location.endswith("/password-change")
    for path in ("/dashboard", "/admin/users", "/methods", "/totp/setup"):
        assert client.get(path).location.endswith("/password-change")
    assert post(client, "/password-change", current_password=INITIAL, new_password=INITIAL).status_code == 400
    assert change_password(client).location.endswith("/methods")
    assert client.get("/admin/users").location.endswith("/methods")
    assert post(client, "/methods/remove", method="totp").location.endswith("/methods")
    enroll_totp(app, client)
    assert client.get("/admin/users").status_code == 200
    user = app.extensions["user_auth"].db.find_user("admin")
    assert user.require_password_change == 0 and user.enrollment_allowed == 0


def test_all_future_password_logins_require_totp(app, admin):
    client, secret = admin
    assert password_login(client, password=CHANGED).location.endswith("/verify-totp")
    assert client.get("/admin/users").location.endswith("/verify-totp")
    assert post(client, "/verify-totp", code="bad").status_code == 400
    app.config["TEST_CLOCK"][0] += 30
    assert post(client, "/verify-totp", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])).location.endswith("/admin/users")


def test_user_creation_admin_access_and_force_password_change(app, admin):
    client, _ = admin
    create_user(client)
    other = app.test_client()
    assert password_login(other, "alice", USER_INITIAL).location.endswith("/password-change")
    change_password(other, USER_INITIAL, USER_CHANGED)
    secret = enroll_totp(app, other)
    assert other.get("/admin/users").status_code == 403
    user = app.extensions["user_auth"].db.find_user("alice")
    assert post(client, "/admin/users", action="force_password", user_id=user.id).status_code == 302
    assert other.get("/dashboard").location == "/"
    # The flag does NOT bypass the existing second factor.
    assert password_login(other, "alice", USER_CHANGED).location.endswith("/verify-totp")
    app.config["TEST_CLOCK"][0] += 30
    assert post(other, "/verify-totp", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])).location.endswith("/password-change")
    assert change_password(other, USER_CHANGED, "another-user-password").location.endswith("/dashboard")


def test_admin_revocation_locks_last_method_until_explicit_reset(app, admin):
    client, _ = admin
    create_user(client)
    other = app.test_client()
    password_login(other, "alice", USER_INITIAL)
    change_password(other, USER_INITIAL, USER_CHANGED)
    enroll_totp(app, other)
    user = app.extensions["user_auth"].db.find_user("alice")
    assert post(client, "/admin/users", action="remove_method", user_id=user.id, method="totp").status_code == 302
    assert other.get("/dashboard").location == "/"
    assert password_login(other, "alice", USER_CHANGED).status_code == 401
    assert post(
        client, "/admin/users", action="reset", user_id=user.id,
        temporary_password="new-temporary-password",
    ).status_code == 302
    assert password_login(other, "alice", "new-temporary-password").location.endswith("/password-change")
    assert other.get("/dashboard").location.endswith("/password-change")


def test_delete_user_revokes_sessions_and_cascades(app, admin):
    client, _ = admin
    create_user(client)
    other = app.test_client()
    password_login(other, "alice", USER_INITIAL)
    change_password(other, USER_INITIAL, USER_CHANGED)
    enroll_totp(app, other)
    user = app.extensions["user_auth"].db.find_user("alice")
    assert post(client, "/admin/users", action="delete", user_id=user.id).status_code == 302
    assert other.get("/dashboard").location == "/"
    with app.extensions["user_auth"].db.write() as connection:
        for table in ("two_factor", "sessions", "passkeys"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table} WHERE user_id=?", (user.id,)).fetchone()[0] == 0
    own = app.extensions["user_auth"].db.find_user("admin")
    assert post(client, "/admin/users", action="delete", user_id=own.id).status_code == 400


def test_logout_revokes_copied_cookie(app, admin):
    client, _ = admin
    cookie = client.get_cookie("session").value
    assert post(client, "/logout").status_code == 302
    attacker = app.test_client()
    attacker.set_cookie("session", cookie)
    assert attacker.get("/dashboard").location == "/"


def test_enrollment_revokes_other_password_only_sessions(app, client):
    password_login(client)
    change_password(client)
    other = app.test_client()
    password_login(other, password=CHANGED)
    assert other.get("/dashboard").location.endswith("/methods")
    enroll_totp(app, client)
    assert other.get("/dashboard").location == "/"
    assert post(other, "/totp/confirm", code="123456").status_code == 401


def test_enrollment_bound_to_initiating_session(app, client):
    password_login(client)
    change_password(client)
    post(client, "/totp/setup")
    other = app.test_client()
    password_login(other, password=CHANGED)
    assert post(other, "/totp/setup").status_code == 400
    assert b"Manual-entry secret" not in other.get("/totp/setup").data
    assert post(other, "/totp/confirm", code="123456").status_code == 400


def test_passkey_only_login_and_forced_password_change(app, client):
    password_login(client)
    change_password(client)
    key = register_passkey(app, client)
    assert client.get("/admin/users").status_code == 200
    assert password_login(client, password=CHANGED).status_code == 401
    assert passkey_login(client, key).json["redirect"].endswith("/admin/users")
    user = app.extensions["user_auth"].db.find_user("admin")
    assert post(client, "/admin/users", action="force_password", user_id=user.id).status_code == 302
    assert passkey_login(client, key).json["redirect"].endswith("/password-change")
    assert post(client, "/password-change", new_password="new-passkey-authorized-password").location.endswith("/admin/users")


@pytest.mark.parametrize("invalid", ["origin", "challenge", "uv", "handle", "rp", "signature"])
def test_passkey_rejects_invalid_assertions_and_consumes_challenge(app, admin, invalid):
    client, _ = admin
    key = register_passkey(app, client)
    post(client, "/logout")
    client.get("/")
    options = json_post(client, "/passkeys/login/options").json
    kwargs = {
        "origin": {"origin": "https://attacker.example"},
        "challenge": {"challenge": b64(b"wrong challenge")},
        "uv": {"flags": 0x01},
        "handle": {"user_id": "another-user"},
        "rp": {"rp_id": "attacker.example"},
        "signature": {},
    }[invalid]
    packet = key.assertion(options["options"], **kwargs)
    if invalid == "signature":
        packet["response"]["signature"] = b64(b"invalid signature")
    data = {"challenge_id": options["challenge_id"], "credential": packet}
    assert json_post(client, "/passkeys/login/complete", **data).status_code == 400
    valid = key.assertion(options["options"])
    assert json_post(
        client, "/passkeys/login/complete", challenge_id=options["challenge_id"],
        credential=valid,
    ).status_code == 400
    assert client.get("/dashboard").location == "/"


def test_passkey_challenge_is_browser_bound_and_replay_protected(app, admin):
    client, _ = admin
    key = register_passkey(app, client)
    post(client, "/logout")
    client.get("/")
    other = app.test_client()
    other.get("/")
    options = json_post(client, "/passkeys/login/options").json
    packet = key.assertion(options["options"])
    data = {"challenge_id": options["challenge_id"], "credential": packet}
    assert json_post(other, "/passkeys/login/complete", **data).status_code == 400
    assert json_post(client, "/passkeys/login/complete", **data).status_code == 200
    assert json_post(client, "/passkeys/login/complete", **data).status_code == 400


@pytest.mark.parametrize("bad", ["origin", "uv"])
def test_passkey_registration_requires_origin_and_uv(app, client, bad):
    password_login(client)
    change_password(client)
    user = app.extensions["user_auth"].db.find_user("admin")
    key = VirtualPasskey(user.id)
    options = json_post(client, "/passkeys/register/options").json
    packet = key.registration(
        options["options"],
        **({"origin": "https://attacker.example"} if bad == "origin" else {"flags": 0x41}),
    )
    assert json_post(
        client, "/passkeys/register/complete", challenge_id=options["challenge_id"],
        credential=packet, name="Invalid",
    ).status_code == 400
    assert client.get("/dashboard").location.endswith("/methods")


def test_passkey_admin_revoke_and_own_last_method_protection(app, admin):
    client, _ = admin
    key = register_passkey(app, client)
    assert post(client, "/methods/remove", method="totp").status_code == 302
    assert passkey_login(client, key).status_code == 200
    assert post(client, "/methods/remove", method="passkey", credential_id=b64(key.credential_id)).status_code == 400
    user = app.extensions["user_auth"].db.find_user("admin")
    assert post(
        client, "/admin/users", action="remove_method", user_id=user.id,
        method="passkey", credential_id=b64(key.credential_id),
    ).status_code == 400


def test_expiry_fresh_auth_csrf_and_trusted_host(app, admin):
    client, _ = admin
    assert client.post("/admin/users", data={"action": "create"}).status_code == 400
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400
    app.config["TEST_CLOCK"][0] += 301
    assert post(client, "/admin/users", action="force_password", user_id="bogus").status_code == 400
    assert json_post(client, "/passkeys/register/options").status_code == 403
    # Touching a session does not extend its absolute lifetime.
    for _ in range(5):
        app.config["TEST_CLOCK"][0] += 700
        client.get("/dashboard")
    assert client.get("/dashboard").location == "/"


def test_missing_keys_invalid_origin_and_duplicate_username(app, admin, tmp_path):
    client, _ = admin
    create_user(client)
    assert post(
        client, "/admin/users", action="create", username="ALICE",
        temporary_password=USER_INITIAL,
    ).status_code == 400
    assert post(client, "/admin/users", action="create", username="sql';--", temporary_password=USER_INITIAL).status_code == 400
    with pytest.raises(ValueError, match="exact HTTPS origin"):
        create_app({
            **app.config, "DATABASE_PATH": str(tmp_path / "bad.sqlite3"),
            "PUBLIC_ORIGIN": "http://example.com", "WEBAUTHN_RP_ID": "example.com",
        })


def test_bootstrap_does_not_reset_existing_admin(app):
    db = app.extensions["user_auth"].db
    first = db.find_user("admin")
    db.bootstrap("changed-env-admin", "changed-initial-password")
    assert db.find_user("changed-env-admin") is None
    assert db.find_user("admin") == first


def test_example_placeholders_fail_closed(app, tmp_path):
    with pytest.raises(ValueError, match="32 random"):
        create_app({
            **app.config, "DATABASE_PATH": str(tmp_path / "placeholder.sqlite3"),
            "SECRET_KEY": "replace-with-at-least-32-random-characters",
        })


def test_anonymous_html_redirects_but_json_and_posts_are_rejected(client):
    assert client.get("/admin/users").location == "/"
    assert client.get("/methods", headers={"Content-Type": "application/json"}, data="{}").status_code == 401
    client.get("/")
    assert post(client, "/admin/users", action="create").status_code == 401
