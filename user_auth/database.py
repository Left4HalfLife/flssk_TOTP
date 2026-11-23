"""SQLite accounts and revocable sessions; all credential changes are atomic."""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextvars import ContextVar
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from totp_2fa.storage import TwoFactorState


class AccountError(ValueError):
    pass


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def validate_password(password: str) -> None:
    if not 12 <= len(password) <= 128:
        raise AccountError("Passwords must contain 12 to 128 characters.")


def normalize_username(username: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username) is None:
        raise AccountError("Use 3-64 letters, digits, dots, underscores or hyphens for usernames.")
    return username.lower()


@dataclass(frozen=True)
class User:
    id: str
    username: str
    password_hash: str
    is_admin: int
    require_password_change: int
    enrollment_allowed: int
    auth_version: int


@dataclass(frozen=True)
class Login:
    token_hash: str
    user: User
    phase: str
    method: str
    auth_at: float
    expires: float


class Database:
    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("Use a file-backed SQLite database.")
        self.clock = clock
        new_file = not Path(self.path).exists()
        Path(self.path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.write() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
                    require_password_change INTEGER NOT NULL DEFAULT 1
                        CHECK(require_password_change IN (0,1)),
                    enrollment_allowed INTEGER NOT NULL DEFAULT 1
                        CHECK(enrollment_allowed IN (0,1)),
                    auth_version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS two_factor (
                    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    state TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS passkeys (
                    credential_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    auth_version INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    method TEXT NOT NULL,
                    auth_at REAL NOT NULL,
                    expires REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS challenges (
                    id TEXT PRIMARY KEY,
                    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                    binding TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    challenge BLOB NOT NULL,
                    auth_version INTEGER,
                    expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS totp_enrollments (
                    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    created REAL NOT NULL
                );
            """)
        if new_file:
            os.chmod(self.path, 0o600)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def user(connection: sqlite3.Connection, user_id: str) -> User:
        row = connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            raise AccountError("Account is unavailable.")
        return User(**dict(row))

    def find_user(self, username: str) -> User | None:
        with self.write() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username=?", (username.lower(),)
            ).fetchone()
            return User(**dict(row)) if row else None

    def bootstrap(self, username: str, password: str) -> None:
        with self.write() as connection:
            if connection.execute("SELECT 1 FROM metadata WHERE key='bootstrapped'").fetchone():
                return
            if not password or password == "replace-with-a-unique-long-initial-password":
                raise AccountError("ADMIN_INITIAL_PASSWORD is required for first startup.")
            self.create_user(connection, username, password, is_admin=True)
            connection.execute("INSERT INTO metadata VALUES ('bootstrapped','1')")

    def create_user(
        self, connection: sqlite3.Connection, username: str, password: str, *, is_admin: bool
    ) -> str:
        username = normalize_username(username)
        validate_password(password)
        user_id = str(uuid.uuid4())
        try:
            connection.execute(
                "INSERT INTO users (id,username,password_hash,is_admin) VALUES (?,?,?,?)",
                (user_id, username, generate_password_hash(password), int(is_admin)),
            )
        except sqlite3.IntegrityError as error:
            raise AccountError("Username already exists.") from error
        return user_id

    def load_login(self, token: str | None) -> Login | None:
        if not token:
            return None
        with self.write() as connection:
            row = connection.execute(
                "SELECT s.* FROM sessions s JOIN users u ON u.id=s.user_id "
                "WHERE s.token_hash=? AND s.auth_version=u.auth_version",
                (digest(token),),
            ).fetchone()
            now = self.clock()
            if not row:
                return None
            if row["expires"] <= now or row["last_seen"] + 900 <= now:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (digest(token),))
                return None
            connection.execute(
                "UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, digest(token))
            )
            return Login(
                digest(token), self.user(connection, row["user_id"]),
                row["phase"], row["method"], row["auth_at"], row["expires"],
            )

    def issue(
        self, user_id: str, version: int, phase: str, method: str, *,
        old_token: str | None = None, auth_at: float | None = None,
    ) -> str:
        token = secrets.token_urlsafe(32)
        with self.write() as connection:
            user = self.user(connection, user_id)
            if user.auth_version != version:
                raise AccountError("Authentication changed. Log in again.")
            if old_token:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (digest(old_token),))
            now = self.clock()
            connection.execute("DELETE FROM sessions WHERE expires<=?", (now,))
            connection.execute("DELETE FROM challenges WHERE expires<=?", (now,))
            connection.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                (digest(token), user_id, version, phase, method,
                 now if auth_at is None else auth_at,
                 now + (3600 if phase == "full" else 600), now),
            )
        return token

    def revoke(self, token: str | None) -> None:
        if token:
            with self.write() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (digest(token),))
                connection.execute("DELETE FROM challenges WHERE binding=?", (digest(token),))

    def assert_login(
        self, connection: sqlite3.Connection, login: Login, *, admin: bool = False,
        fresh: bool = False,
    ) -> User:
        row = connection.execute(
            "SELECT * FROM sessions WHERE token_hash=?", (login.token_hash,)
        ).fetchone()
        user = self.user(connection, login.user.id)
        now = self.clock()
        if (
            not row or row["auth_version"] != user.auth_version
            or row["expires"] <= now or row["last_seen"] + 900 <= now
            or (admin and (not user.is_admin or row["phase"] != "full"))
            or (fresh and row["auth_at"] + 300 <= now)
        ):
            raise AccountError("Session expired or authorization changed. Log in again.")
        return user

    def bump(self, connection: sqlite3.Connection, user_id: str) -> None:
        connection.execute("UPDATE users SET auth_version=auth_version+1 WHERE id=?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        connection.execute("DELETE FROM challenges WHERE user_id=?", (user_id,))

    def has_totp(self, connection: sqlite3.Connection, user_id: str) -> bool:
        row = connection.execute(
            "SELECT state FROM two_factor WHERE user_id=?", (user_id,)
        ).fetchone()
        return bool(row and json.loads(row["state"])["secret"])

    def has_passkey(self, connection: sqlite3.Connection, user_id: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM passkeys WHERE user_id=?", (user_id,)
        ).fetchone() is not None

    def audit(self, connection: sqlite3.Connection, actor: str, target: str, event: str) -> None:
        connection.execute(
            "INSERT INTO audit (actor_id,target_id,event,created) VALUES (?,?,?,?)",
            (actor, target, event, self.clock()),
        )


class AccountTOTPStore:
    """Shares the account DB; activation/removal revokes all previous sessions."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self._login: ContextVar[Login | None] = ContextVar("totp_actor", default=None)

    @contextmanager
    def authorized(self, login: Login) -> Iterator[None]:
        token = self._login.set(login)
        try:
            yield
        finally:
            self._login.reset(token)

    @contextmanager
    def transaction(self, user_id: str) -> Iterator[TwoFactorState]:
        with self.database.write() as connection:
            self.database.user(connection, user_id)
            login = self._login.get()
            if login is not None:
                self.database.assert_login(connection, login)
                if login.user.id != user_id:
                    raise AccountError("Account mismatch.")
            row = connection.execute(
                "SELECT state FROM two_factor WHERE user_id=?", (user_id,)
            ).fetchone()
            state = TwoFactorState(**json.loads(row["state"])) if row else TwoFactorState()
            previous = state.secret
            yield state
            connection.execute(
                "INSERT INTO two_factor VALUES (?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET state=excluded.state",
                (user_id, json.dumps(asdict(state))),
            )
            if state.secret != previous:
                if state.secret:
                    connection.execute(
                        "UPDATE users SET enrollment_allowed=0 WHERE id=?", (user_id,)
                    )
                self.database.bump(connection, user_id)
