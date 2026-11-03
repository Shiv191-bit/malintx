"""SQLite storage with an explicit, ordered migration list (no ORM; the schema is small)."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "initial schema",
        """
        CREATE TABLE samples (
            sha256 TEXT PRIMARY KEY, sha1 TEXT NOT NULL, md5 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            display_name TEXT NOT NULL, first_seen TEXT NOT NULL, stored_path TEXT NOT NULL,
            package_name TEXT
        );
        CREATE TABLE jobs (
            id TEXT PRIMARY KEY, sample_sha256 TEXT REFERENCES samples(sha256), display_name TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            enrich_requested INTEGER NOT NULL DEFAULT 0, ai_requested INTEGER NOT NULL DEFAULT 0,
            error_code TEXT, error_message TEXT, stages_json TEXT NOT NULL DEFAULT '[]',
            duplicate_of_job TEXT
        );
        CREATE INDEX idx_jobs_created ON jobs(created_at DESC);
        CREATE INDEX idx_jobs_sample ON jobs(sample_sha256);
        CREATE TABLE results (
            job_id TEXT PRIMARY KEY REFERENCES jobs(id), schema_version TEXT NOT NULL, json TEXT NOT NULL,
            classification TEXT, score INTEGER, package_name TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE reports (
            job_id TEXT PRIMARY KEY REFERENCES jobs(id), path TEXT NOT NULL, sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE intel_cache (
            cache_key TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL, json TEXT NOT NULL,
            retrieved_at TEXT NOT NULL, expires_at TEXT NOT NULL
        );
        """,
    ),
]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    @contextlib.contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def migrate(self) -> None:
        with self.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT)"
            )
            done = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
            for version, name, sql in MIGRATIONS:
                if version in done:
                    continue
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT INTO schema_migrations VALUES (?,?,?)", (version, name, utcnow())
                    )
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise

    def schema_version(self) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        return int(row["v"] or 0)
