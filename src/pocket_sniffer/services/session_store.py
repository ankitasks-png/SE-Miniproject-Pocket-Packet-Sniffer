
"""SQLite-backed index of saved packet-capture sessions."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class SessionStoreError(ValueError):
    """Raised for invalid or unavailable capture sessions."""


@dataclass(frozen=True)
class Session:
    id: int
    name: str
    path: str
    created_at: str


class SessionStore:
    """Store and retrieve references to local capture-session folders."""

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database).expanduser().resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _has_session_artifacts(directory: Path) -> bool:
        if not directory.is_dir():
            return False

        return any(
            path.is_file()
            and (
                path.suffix.lower() in {".pcap", ".pcapng"}
                or path.name in {
                    "conn.log",
                    "notice.log",
                    "dns.log",
                    "http.log",
                }
            )
            for path in directory.iterdir()
        )

    def index_session(self, directory: str | Path) -> Session:
        """Add or update a session folder containing capture artifacts."""
        path = Path(directory).expanduser().resolve()

        if not path.is_dir():
            raise SessionStoreError(f"Session directory does not exist: {path}")
        if not self._has_session_artifacts(path):
            raise SessionStoreError(
                f"No supported PCAP or Zeek log files found in: {path}"
            )

        created_at = datetime.fromtimestamp(
            path.stat().st_mtime, tz=timezone.utc
        ).isoformat()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sessions (name, path, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    name = excluded.name,
                    created_at = excluded.created_at
                """,
                (path.name, str(path), created_at),
            )
            row = connection.execute(
                "SELECT * FROM sessions WHERE path = ?", (str(path),)
            ).fetchone()

        return self._to_session(row)

    def list_sessions(self) -> list[Session]:
        """Return indexed sessions, newest first."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC, id DESC"
            ).fetchall()
        return [self._to_session(row) for row in rows]

    def get_session(self, session_id: int) -> Session:
        """Retrieve one session by its index ID."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()

        if row is None:
            raise SessionStoreError(f"No session found with ID {session_id}")
        return self._to_session(row)

    @staticmethod
    def _to_session(row: sqlite3.Row) -> Session:
        return Session(
            id=row["id"],
            name=row["name"],
            path=row["path"],
            created_at=row["created_at"],
        )
