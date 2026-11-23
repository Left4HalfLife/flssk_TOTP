"""WebAuthn ceremonies bound to configured origin, account and browser session."""

import json
import secrets
import sqlite3

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .database import AccountError, Database, Login, User


class Passkeys:
    def __init__(self, database: Database, rp_id: str, origin: str, name: str) -> None:
        self.db = database
        self.rp_id = rp_id
        self.origin = origin
        self.name = name

    def _challenge(
        self, connection: sqlite3.Connection, kind: str, binding: str,
        challenge: bytes, user: User | None,
    ) -> str:
        challenge_id = secrets.token_urlsafe(32)
        connection.execute("DELETE FROM challenges WHERE binding=? AND kind=?", (binding, kind))
        connection.execute(
            "INSERT INTO challenges VALUES (?,?,?,?,?,?,?)",
            (challenge_id, user.id if user else None, binding, kind, challenge,
             user.auth_version if user else None, self.db.clock() + 300),
        )
        return challenge_id

    def _take(self, challenge_id: str, binding: str, kind: str) -> sqlite3.Row:
        # Commit consumption even when verification fails, preventing challenge replay.
        with self.db.write() as connection:
            row = connection.execute(
                "SELECT * FROM challenges WHERE id=? AND binding=? AND kind=?",
                (challenge_id, binding, kind),
            ).fetchone()
            if row:
                connection.execute("DELETE FROM challenges WHERE id=?", (challenge_id,))
        if not row or row["expires"] <= self.db.clock():
            raise AccountError("Passkey challenge expired. Start again.")
        return row

    def registration_options(self, login: Login) -> tuple[str, dict]:
        with self.db.write() as connection:
            user = self.db.assert_login(connection, login, fresh=True)
            credentials = connection.execute(
                "SELECT credential_id FROM passkeys WHERE user_id=?", (user.id,)
            ).fetchall()
            options = generate_registration_options(
                rp_id=self.rp_id, rp_name=self.name, user_id=user.id.encode(),
                user_name=user.username,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    require_resident_key=True,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                exclude_credentials=[
                    PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
                    for row in credentials
                ],
            )
            challenge_id = self._challenge(
                connection, "register", login.token_hash, options.challenge, user
            )
        return challenge_id, json.loads(options_to_json(options))

    def register(self, login: Login, challenge_id: str, credential: dict, name: str) -> int:
        challenge = self._take(challenge_id, login.token_hash, "register")
        if challenge["user_id"] != login.user.id:
            raise AccountError("Passkey account mismatch.")
        try:
            verified = verify_registration_response(
                credential=credential, expected_challenge=challenge["challenge"],
                expected_rp_id=self.rp_id, expected_origin=self.origin,
                require_user_verification=True,
            )
        except WebAuthnException as error:
            raise AccountError("Passkey registration could not be verified.") from error
        with self.db.write() as connection:
            user = self.db.assert_login(connection, login, fresh=True)
            if user.auth_version != challenge["auth_version"]:
                raise AccountError("Account changed during enrollment. Log in again.")
            try:
                connection.execute(
                    "INSERT INTO passkeys VALUES (?,?,?,?,?,?)",
                    (bytes_to_base64url(verified.credential_id), user.id,
                     verified.credential_public_key, verified.sign_count,
                     name[:64] or "Passkey", self.db.clock()),
                )
            except sqlite3.IntegrityError as error:
                raise AccountError("Passkey is already registered.") from error
            connection.execute("UPDATE users SET enrollment_allowed=0 WHERE id=?", (user.id,))
            self.db.bump(connection, user.id)
            self.db.audit(connection, user.id, user.id, "passkey_added")
            return user.auth_version + 1

    def authentication_options(self, binding: str) -> tuple[str, dict]:
        # Discoverable credentials avoid username enumeration and support username-free login.
        options = generate_authentication_options(
            rp_id=self.rp_id, user_verification=UserVerificationRequirement.REQUIRED
        )
        with self.db.write() as connection:
            challenge_id = self._challenge(
                connection, "authenticate", binding, options.challenge, None
            )
        return challenge_id, json.loads(options_to_json(options))

    def authenticate(self, challenge_id: str, binding: str, credential: dict) -> User:
        challenge = self._take(challenge_id, binding, "authenticate")
        credential_id = credential.get("id")
        if not isinstance(credential_id, str) or len(credential_id) > 1024:
            raise AccountError("Invalid passkey.")
        with self.db.write() as connection:
            row = connection.execute(
                "SELECT * FROM passkeys WHERE credential_id=?", (credential_id,)
            ).fetchone()
            if not row:
                raise AccountError("Passkey authentication failed.")
            user = self.db.user(connection, row["user_id"])
            try:
                response = credential.get("response")
                if not isinstance(response, dict):
                    raise AccountError("Invalid passkey response.")
                handle = response.get("userHandle")
                if not isinstance(handle, str) or base64url_to_bytes(handle) != user.id.encode():
                    raise AccountError("Passkey user handle does not match the account.")
                verified = verify_authentication_response(
                    credential=credential, expected_challenge=challenge["challenge"],
                    expected_rp_id=self.rp_id, expected_origin=self.origin,
                    credential_public_key=row["public_key"],
                    credential_current_sign_count=row["sign_count"],
                    require_user_verification=True,
                )
            except (WebAuthnException, ValueError) as error:
                raise AccountError("Passkey authentication failed.") from error
            connection.execute(
                "UPDATE passkeys SET sign_count=? WHERE credential_id=?",
                (verified.new_sign_count, credential_id),
            )
            return user
