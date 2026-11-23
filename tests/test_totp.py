import base64
from concurrent.futures import ThreadPoolExecutor

import pyotp
import pytest
from cryptography.fernet import Fernet

from example_app import create_app
from totp_2fa import SQLiteStore, TwoFactorState
from totp_2fa.service import FactorError


@pytest.fixture
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-session-key",
            "TOTP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "TOTP_ISSUER_NAME": "Tests",
            "DEMO_PASSWORD": "test-password",
            "TOTP_DATABASE": str(tmp_path / "test.sqlite3"),
            "RATELIMIT_ENABLED": False,
        }
    )
    now = [1_800_000_015.0]
    app.extensions["totp_2fa"].service.clock = lambda: now[0]
    app.config["TEST_CLOCK"] = now
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def token(client):
    with client.session_transaction() as session:
        return session["_2fa_csrf"]


def post(client, path, **body):
    return client.post(path, json=body, headers={"X-CSRF-Token": token(client)})


def login(client):
    client.get("/")
    return client.post(
        "/",
        data={"username": "demo", "password": "test-password", "csrf_token": token(client)},
    )


def enroll(app, client):
    login(client)
    response = post(client, "/2fa/setup")
    secret = response.json["enrollment"]["secret"]
    code = pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])
    response = post(client, "/2fa/confirm", code=code)
    assert response.status_code == 200
    return secret, response.json["backup_codes"]


def pending_login(client):
    response = login(client)
    assert response.location.endswith("/2fa/verify")
    with client.session_transaction() as session:
        assert session["auth_state"] == "2fa_pending"


def test_setup_confirmation_encryption_and_once_only_codes(app, client):
    login(client)
    initial = client.get("/2fa/setup", headers={"Accept": "application/json"})
    assert initial.json["enrollment"] is None
    setup = post(client, "/2fa/setup")
    enrollment = setup.json["enrollment"]
    secret = enrollment["secret"]
    assert enrollment["provisioning_uri"].startswith("otpauth://totp/Tests:")
    png = base64.b64decode(enrollment["qr_data_uri"].split(",", 1)[1])
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert setup.headers["Cache-Control"] == "no-store"
    assert post(client, "/2fa/setup").json["enrollment"]["secret"] == secret
    service = app.extensions["totp_2fa"].service
    with service.store.transaction("demo") as state:
        assert state.secret is None
        assert state.pending_secret != secret
        assert service._decrypt(state.pending_secret) == secret
    with client.session_transaction() as session:
        assert secret not in repr(dict(session))
    assert post(client, "/2fa/confirm", code="not-a-code").status_code == 400
    result = post(
        client, "/2fa/confirm", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])
    )
    codes = result.json["backup_codes"]
    assert len(codes) == len(set(codes)) == 10
    with service.store.transaction("demo") as state:
        assert state.pending_secret is None
        assert state.pending_expires_at is None
        assert service._decrypt(state.secret) == secret
        assert all(code not in state.backup_hashes for code in codes)
        assert len(state.backup_hashes) == 10
    assert post(client, "/2fa/confirm", code="123456").status_code == 400
    assert client.get("/2fa/confirm").status_code == 405
    assert post(client, "/2fa/setup").status_code == 400


def test_valid_invalid_and_protected_route_enforcement(app, client):
    assert client.get("/dashboard").status_code == 401
    assert client.get("/2fa/setup").status_code == 401
    secret, _ = enroll(app, client)
    assert client.get("/dashboard").status_code == 200
    pending_login(client)
    assert client.get("/dashboard").location.endswith("/2fa/verify")
    assert client.get("/dashboard", headers={"Accept": "application/json"}).status_code == 403
    for path in ("/2fa/setup", "/2fa/confirm", "/2fa/disable"):
        assert post(client, path, code="123456").status_code == 403
    assert post(client, "/2fa/verify", code="abcdef").status_code == 400
    app.config["TEST_CLOCK"][0] += 30
    totp = pyotp.TOTP(secret)
    assert post(client, "/2fa/verify", code=totp.at(app.config["TEST_CLOCK"][0] - 90)).status_code == 400
    old_csrf = token(client)
    response = post(client, "/2fa/verify", code=totp.at(app.config["TEST_CLOCK"][0]))
    assert response.json["authenticated"] is True
    assert token(client) != old_csrf
    assert client.get("/dashboard").status_code == 200
    assert post(client, "/2fa/verify", code="123456").status_code == 403


@pytest.mark.parametrize("offset", [-30, 0, 30])
def test_clock_drift_window(app, client, offset):
    secret, _ = enroll(app, client)
    app.config["TEST_CLOCK"][0] += 90
    pending_login(client)
    code = pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0] + offset)
    assert post(client, "/2fa/verify", code=code).status_code == 200


@pytest.mark.parametrize("offset", [-60, 60])
def test_outside_clock_drift_window(app, client, offset):
    secret, _ = enroll(app, client)
    app.config["TEST_CLOCK"][0] += 90
    pending_login(client)
    code = pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0] + offset)
    assert post(client, "/2fa/verify", code=code).status_code == 400


def test_replay_and_earlier_step_rejected(app, client):
    secret, _ = enroll(app, client)
    pending_login(client)
    totp = pyotp.TOTP(secret)
    now = app.config["TEST_CLOCK"]
    assert post(client, "/2fa/verify", code=totp.at(now[0])).status_code == 400
    now[0] += 60
    future = totp.at(now[0] + 30)
    assert post(client, "/2fa/verify", code=future).status_code == 200
    pending_login(client)
    assert post(client, "/2fa/verify", code=future).status_code == 400
    assert post(client, "/2fa/verify", code=totp.at(now[0])).status_code == 400
    now[0] += 60
    assert post(client, "/2fa/verify", code=totp.at(now[0])).status_code == 200


def test_backup_code_consumed_and_other_codes_remain(app, client):
    _, codes = enroll(app, client)
    pending_login(client)
    assert post(client, "/2fa/verify", code=codes[0].upper()).status_code == 200
    pending_login(client)
    assert post(client, "/2fa/verify", code=codes[0]).status_code == 400
    assert post(client, "/2fa/verify", code=codes[1]).status_code == 200
    with app.extensions["totp_2fa"].store.transaction("demo") as state:
        assert len(state.backup_hashes) == 8


@pytest.mark.parametrize("factor", ["password", "totp", "backup"])
def test_disable_requires_confirmation_and_allows_reset(app, client, factor):
    secret, codes = enroll(app, client)
    assert post(client, "/2fa/disable").status_code == 400
    assert post(client, "/2fa/disable", password="wrong").status_code == 400
    assert post(client, "/2fa/disable", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])).status_code == 400
    app.config["TEST_CLOCK"][0] += 30
    body = {
        "password": {"password": "test-password"},
        "totp": {"code": pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])},
        "backup": {"code": codes[0]},
    }[factor]
    assert post(client, "/2fa/disable", **body).json["disabled"] is True
    with app.extensions["totp_2fa"].store.transaction("demo") as state:
        assert state.secret is None
        assert state.pending_secret is None
        assert state.backup_hashes == []
        assert state.last_used_timecode == -1
    assert login(client).location.endswith("/dashboard")
    new_secret = post(client, "/2fa/setup").json["enrollment"]["secret"]
    assert new_secret != secret


def test_expired_enrollment_and_get_does_not_generate(app, client):
    login(client)
    secret = post(client, "/2fa/setup").json["enrollment"]["secret"]
    app.config["TEST_CLOCK"][0] += 600
    assert post(client, "/2fa/confirm", code=pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])).status_code == 400
    assert client.get("/2fa/setup", headers={"Accept": "application/json"}).json["enrollment"] is None
    assert post(client, "/2fa/setup").json["enrollment"]["secret"] != secret


def test_csrf_and_malformed_json(app, client):
    login(client)
    assert client.post("/2fa/setup", json={}).status_code == 400
    assert client.post("/2fa/setup", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 400
    assert post(client, "/2fa/confirm", code=123456).status_code == 400
    assert client.post("/2fa/confirm", json=[], headers={"X-CSRF-Token": token(client)}).status_code == 400


def test_html_form_flow(app, client):
    login(client)
    setup = client.post("/2fa/setup", data={"csrf_token": token(client)})
    assert b'data:image/png;base64,' in setup.data
    assert b'name="code"' in setup.data
    service = app.extensions["totp_2fa"].service
    with service.store.transaction("demo") as state:
        secret = service._decrypt(state.pending_secret)
    result = client.post(
        "/2fa/confirm",
        data={"csrf_token": token(client), "code": pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])},
    )
    assert b"Save these recovery codes" in result.data
    pending_login(client)
    assert b"Verify your login" in client.get("/2fa/verify").data
    app.config["TEST_CLOCK"][0] += 30
    verified = client.post(
        "/2fa/verify",
        data={"csrf_token": token(client), "code": pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])},
    )
    assert verified.location.endswith("/dashboard")


@pytest.mark.parametrize("factor", ["totp", "backup"])
def test_concurrent_consumption_only_one_request_succeeds(app, client, factor):
    secret, codes = enroll(app, client)
    app.config["TEST_CLOCK"][0] += 30
    code = codes[0] if factor == "backup" else pyotp.TOTP(secret).at(app.config["TEST_CLOCK"][0])
    service = app.extensions["totp_2fa"].service

    def attempt():
        try:
            service.verify("demo", code)
            return True
        except FactorError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(lambda _: attempt(), range(2))) == [False, True]


def test_transaction_rollback_and_persistence(tmp_path):
    path = tmp_path / "state.sqlite3"
    store = SQLiteStore(path)
    with store.transaction("alice") as state:
        state.last_used_timecode = 123
    with pytest.raises(RuntimeError):
        with store.transaction("alice") as state:
            state.last_used_timecode = 999
            raise RuntimeError("rollback")
    with SQLiteStore(path).transaction("alice") as state:
        assert state.last_used_timecode == 123
    with store.transaction("bob") as state:
        assert state == TwoFactorState()


@pytest.mark.parametrize("path", ["/2fa/confirm", "/2fa/verify"])
def test_rate_limit_enforced(tmp_path, path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-key",
            "TOTP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "DEMO_PASSWORD": "test-password",
            "TOTP_DATABASE": str(tmp_path / "limit.sqlite3"),
        }
    )
    client = app.test_client()
    if path == "/2fa/verify":
        app.config["TEST_CLOCK"] = [1_800_000_015.0]
        app.extensions["totp_2fa"].service.clock = lambda: app.config["TEST_CLOCK"][0]
        enroll(app, client)
        pending_login(client)
    else:
        login(client)
    for _ in range(5):
        assert post(client, path, code="invalid").status_code == 400
    assert post(client, path, code="invalid").status_code == 429


def test_disable_preserves_password_whitespace(app, client):
    enroll(app, client)
    app.extensions["totp_2fa"].verify_password = (
        lambda user_id, password: user_id == "demo" and password == " password with spaces "
    )
    assert post(client, "/2fa/disable", password="password with spaces").status_code == 400
    assert post(client, "/2fa/disable", password=" password with spaces ").status_code == 200


def test_corrupt_ciphertext_surfaces_error_without_reset(app, client, caplog):
    enroll(app, client)
    service = app.extensions["totp_2fa"].service
    with service.store.transaction("demo") as state:
        state.secret = "corrupt-ciphertext"
    pending_login(client)
    response = post(client, "/2fa/verify", code="123456")
    assert response.status_code == 500
    assert "Contact support" in response.json["error"]
    assert "Unable to decrypt stored TOTP secret" in caplog.text
    with service.store.transaction("demo") as state:
        assert state.secret == "corrupt-ciphertext"
    assert client.get("/dashboard", headers={"Accept": "application/json"}).status_code == 403


def test_invalid_key_fails_at_startup(tmp_path):
    with pytest.raises(ValueError, match="valid Fernet key"):
        create_app(
            {
                "SECRET_KEY": "test-key",
                "TOTP_ENCRYPTION_KEY": "invalid",
                "DEMO_PASSWORD": "test-password",
                "TOTP_DATABASE": str(tmp_path / "bad.sqlite3"),
            }
        )


def test_enrollment_revokes_old_password_only_session(app, client):
    login(client)
    other = app.test_client()
    login(other)
    enroll(app, client)
    assert other.get("/dashboard").status_code == 401
    assert post(other, "/2fa/disable", password="test-password").status_code == 401


def test_logout_revokes_copied_cookie(app, client):
    login(client)
    cookie = client.get_cookie("session").value
    client.post("/logout", data={"csrf_token": token(client)})
    other = app.test_client()
    other.set_cookie("session", cookie)
    assert other.get("/dashboard").status_code == 401
