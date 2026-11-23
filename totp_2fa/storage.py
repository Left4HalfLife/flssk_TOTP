"""Adapters must serialize each user's read/check/write as one transaction."""

import json
import sqlite3
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Protocol


@dataclass
class TwoFactorState:
    secret: str | None = None
    pending_secret: str | None = None
    pending_expires_at: float | None = None
    last_used_timecode: int = -1
    backup_hashes: list[str] = field(default_factory=list)
    session_tokens: dict[str, float] = field(default_factory=dict)


class TwoFactorStore(Protocol):
    def transaction(self, user_id: str) -> AbstractContextManager[TwoFactorState]:
        """Yield mutable state; commit on success, roll back on exception.

        Lock the user row (or use equivalent compare-and-swap semantics) until
        commit. Concurrent requests must never consume the same factor twice.
        Missing users' 2FA records start with TwoFactorState().
        """
        ...


class SQLiteStore:
    """Persistent reference adapter. BEGIN IMMEDIATE serializes writers."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("Use a file-backed SQLite database, not :memory:.")
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS two_factor "
                "(user_id TEXT PRIMARY KEY, state TEXT NOT NULL)"
            )

    @contextmanager
    def transaction(self, user_id: str) -> Iterator[TwoFactorState]:
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM two_factor WHERE user_id = ?", (user_id,)
            ).fetchone()
            state = TwoFactorState(**json.loads(row[0])) if row else TwoFactorState()
            yield state
            connection.execute(
                "INSERT INTO two_factor (user_id, state) VALUES (?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET state = excluded.state",
                (user_id, json.dumps(asdict(state))),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
