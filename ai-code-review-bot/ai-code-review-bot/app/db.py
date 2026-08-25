import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    pr_title TEXT,
    author TEXT,
    created_at REAL NOT NULL,
    files_reviewed INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id INTEGER NOT NULL REFERENCES reviews(id),
    file_path TEXT NOT NULL,
    line INTEGER,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    message TEXT NOT NULL,
    source TEXT NOT NULL,
    posted INTEGER NOT NULL DEFAULT 0
);
"""


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(settings.database_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def create_review(repo: str, pr_number: int, pr_title: str, author: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO reviews (repo, pr_number, pr_title, author, created_at) VALUES (?, ?, ?, ?, ?)",
            (repo, pr_number, pr_title, author, time.time()),
        )
        return cur.lastrowid


def add_finding(review_id: int, file_path: str, line: int | None, severity: str,
                 category: str, message: str, source: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO findings (review_id, file_path, line, severity, category, message, source)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (review_id, file_path, line, severity, category, message, source),
        )


def finalize_review(review_id: int, files_reviewed: int, counts: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """UPDATE reviews SET files_reviewed = ?, findings_count = ?,
               critical_count = ?, high_count = ?, medium_count = ?, low_count = ?
               WHERE id = ?""",
            (
                files_reviewed,
                sum(counts.values()),
                counts.get("critical", 0),
                counts.get("high", 0),
                counts.get("medium", 0),
                counts.get("low", 0),
                review_id,
            ),
        )


def get_stats() -> dict:
    with get_conn() as conn:
        totals = conn.execute(
            """SELECT COUNT(*) AS reviews,
                      COALESCE(SUM(findings_count), 0) AS findings,
                      COALESCE(SUM(critical_count), 0) AS critical,
                      COALESCE(SUM(high_count), 0) AS high,
                      COALESCE(SUM(medium_count), 0) AS medium,
                      COALESCE(SUM(low_count), 0) AS low
               FROM reviews"""
        ).fetchone()
        recent = conn.execute(
            """SELECT id, repo, pr_number, pr_title, author, created_at,
                      files_reviewed, findings_count, critical_count, high_count,
                      medium_count, low_count
               FROM reviews ORDER BY created_at DESC LIMIT 50"""
        ).fetchall()
        return {
            "totals": dict(totals),
            "recent": [dict(r) for r in recent],
        }


def get_findings_for_review(review_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE review_id = ? ORDER BY severity", (review_id,)
        ).fetchall()
        return [dict(r) for r in rows]
