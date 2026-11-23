import base64
import hashlib
import hmac
import io
import re
import secrets
import time
from collections.abc import Callable

import pyotp
import qrcode
from cryptography.fernet import Fernet

from .storage import TwoFactorState, TwoFactorStore


class FactorError(ValueError):
    """An expected enrollment or verification failure safe to show to users."""


class TOTPService:
    def __init__(
        self,
        store: TwoFactorStore,
        encryption_key: str | bytes,
        issuer: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.cipher = Fernet(encryption_key)
        self.issuer = issuer
        self.clock = clock

    def enabled(self, user_id: str) -> bool:
        with self.store.transaction(user_id) as state:
            return state.secret is not None

    def _decrypt(self, encrypted: str) -> str:
        return self.cipher.decrypt(encrypted.encode("ascii")).decode("ascii")

    def setup(
        self, user_id: str, account_name: str, *, create: bool
    ) -> dict[str, str] | None:
        with self.store.transaction(user_id) as state:
            if state.secret:
                raise FactorError("2FA is already enabled. Disable it before re-enrolling.")
            now = self.clock()
            if state.pending_expires_at is None or state.pending_expires_at <= now:
                state.pending_secret = None
                state.pending_expires_at = None
            if create and not state.pending_secret:
                state.pending_secret = self.cipher.encrypt(
                    pyotp.random_base32().encode("ascii")
                ).decode("ascii")
                state.pending_expires_at = now + 600
            if not state.pending_secret:
                return None
            secret = self._decrypt(state.pending_secret)
        uri = pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=self.issuer)
        image = qrcode.make(uri)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return {
            "secret": secret,
            "provisioning_uri": uri,
            "qr_data_uri": "data:image/png;base64,"
            + base64.b64encode(buffer.getvalue()).decode("ascii"),
        }

    def _timecode(self, secret: str, code: str, last_used: int) -> int:
        if re.fullmatch(r"[0-9]{6}", code) is None:
            raise FactorError("Invalid or already used code.")
        totp = pyotp.TOTP(secret)
        now = self.clock()
        if not totp.verify(code, for_time=now, valid_window=1):
            raise FactorError("Invalid or already used code.")
        current = int(now) // totp.interval
        # Matching the exact step allows drift without accepting replays.
        for step in (current, current - 1, current + 1):
            if step >= 0 and hmac.compare_digest(totp.at(step * totp.interval), code):
                if step <= last_used:
                    raise FactorError("Invalid or already used code.")
                return step
        raise FactorError("Invalid or already used code.")

    @staticmethod
    def _backup_hash(code: str) -> str:
        return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()

    def _check_session(
        self, state: TwoFactorState, transition: tuple[str, str] | None
    ) -> None:
        if transition and state.session_tokens.get(transition[0], 0) <= self.clock():
            raise FactorError("Session expired or revoked. Log in again.")

    def _rotate_session(
        self, state: TwoFactorState, transition: tuple[str, str] | None
    ) -> None:
        if transition:
            state.session_tokens.pop(transition[0], None)
            state.session_tokens[transition[1]] = self.clock() + 3600

    def confirm(
        self, user_id: str, code: str, *,
        session_transition: tuple[str, str] | None = None,
    ) -> list[str]:
        with self.store.transaction(user_id) as state:
            self._check_session(state, session_transition)
            if state.secret:
                raise FactorError("2FA is already enabled.")
            if (
                not state.pending_secret
                or state.pending_expires_at is None
                or state.pending_expires_at <= self.clock()
            ):
                raise FactorError("Enrollment expired. Start setup again.")
            step = self._timecode(self._decrypt(state.pending_secret), code, -1)
            codes = []
            for _ in range(10):
                raw = secrets.token_hex(10)
                codes.append("-".join(raw[i : i + 4] for i in range(0, 20, 4)))
            state.secret = state.pending_secret
            state.pending_secret = None
            state.pending_expires_at = None
            state.last_used_timecode = step
            state.backup_hashes = [self._backup_hash(value) for value in codes]
            state.session_tokens.clear()
            self._rotate_session(state, session_transition)
            return codes

    def _consume(self, state: TwoFactorState, code: str) -> None:
        if not state.secret:
            raise FactorError("2FA is not enabled.")
        if len(code) > 200:
            raise FactorError("Invalid or already used code.")
        if re.fullmatch(r"[0-9]{6}", code):
            state.last_used_timecode = self._timecode(
                self._decrypt(state.secret), code, state.last_used_timecode
            )
            return
        digest = self._backup_hash(code)
        for index, stored in enumerate(state.backup_hashes):
            if hmac.compare_digest(stored, digest):
                del state.backup_hashes[index]
                return
        raise FactorError("Invalid or already used code.")

    def verify(
        self, user_id: str, code: str, *,
        session_transition: tuple[str, str] | None = None,
    ) -> None:
        with self.store.transaction(user_id) as state:
            self._check_session(state, session_transition)
            self._consume(state, code)
            self._rotate_session(state, session_transition)

    def disable(
        self, user_id: str, code: str, *, password_verified: bool,
        session_transition: tuple[str, str] | None = None,
    ) -> None:
        with self.store.transaction(user_id) as state:
            self._check_session(state, session_transition)
            if not state.secret:
                raise FactorError("2FA is not enabled.")
            if not password_verified:
                self._consume(state, code)
            state.secret = None
            state.pending_secret = None
            state.pending_expires_at = None
            state.last_used_timecode = -1
            state.backup_hashes.clear()
            state.session_tokens.clear()
            self._rotate_session(state, session_transition)
