"""Evidence Store — SQLite-backed raw tool output isolation.

The #1 context management rule: raw tool output (nmap XML, nuclei JSON,
curl headers) is NEVER inlined into agent context. It's stored here keyed
by an evidence_id, and agents exchange only the ID + a summary.

This prevents context bloat, reduces hallucination (the LLM can't
misquote a tool result it can't see), and lets the Verifier agent
re-fetch raw evidence to independently verify findings.
"""

from __future__ import annotations

import json
import sqlite3
import hashlib
import threading
from pathlib import Path
from datetime import datetime


_db_lock = threading.Lock()
_db_path: str | None = None


def init_db(db_path: str = "results/evidence.db") -> None:
    """Initialize the evidence database. Call once at scan start."""
    global _db_path
    _db_path = db_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _db_lock, _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                raw_output TEXT NOT NULL,
                output_type TEXT DEFAULT 'text',
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id)
            )
        """)
        conn.commit()


def _get_conn() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("Evidence DB not initialized. Call init_db() first.")
    return sqlite3.connect(_db_path)


def store(tool: str, target: str, command: str, raw_output: str, output_type: str = "text") -> str:
    """Store raw tool output, return evidence_id (ev_XXXXXX)."""
    h = hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest()[:12]
    eid = f"ev_{h}"
    with _db_lock, _get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO evidence (id, tool, target, command, raw_output, output_type, timestamp, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (eid, tool, target, " ".join(command) if isinstance(command, list) else str(command),
             raw_output, output_type, datetime.now().isoformat(), h),
        )
        conn.commit()
    return eid


def fetch(evidence_id: str) -> dict | None:
    """Fetch raw evidence by ID. Returns dict with all fields or None."""
    with _db_lock, _get_conn() as conn:
        row = conn.execute(
            "SELECT id, tool, target, command, raw_output, output_type, timestamp, hash "
            "FROM evidence WHERE id = ?", (evidence_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "id": row[0], "tool": row[1], "target": row[2], "command": row[3],
        "raw_output": row[4], "output_type": row[5], "timestamp": row[6], "hash": row[7],
    }


def search(query: str, limit: int = 10) -> list[dict]:
    """Search evidence by tool name or target (simple LIKE)."""
    with _db_lock, _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, tool, target, command, substr(raw_output, 1, 200) as preview "
            "FROM evidence WHERE tool LIKE ? OR target LIKE ? OR command LIKE ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (f"%{query}%", f"%{query}%", f"%{query}%", limit)
        ).fetchall()
    return [{"id": r[0], "tool": r[1], "target": r[2], "command": r[3], "preview": r[4]} for r in rows]


def summary() -> dict:
    """Return summary stats of stored evidence."""
    with _db_lock, _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        by_tool = conn.execute(
            "SELECT tool, COUNT(*) FROM evidence GROUP BY tool ORDER BY COUNT(*) DESC"
        ).fetchall()
    return {"total_evidence": total, "by_tool": dict(by_tool)}


def link_finding(finding_id: str, evidence_id: str) -> None:
    """Link a finding to its supporting evidence."""
    with _db_lock, _get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO findings (finding_id, evidence_id, verified) VALUES (?, ?, 0)",
            (finding_id, evidence_id),
        )
        conn.commit()


def mark_verified(finding_id: str, verified: bool = True) -> None:
    """Mark a finding as verified by the Verifier agent."""
    with _db_lock, _get_conn() as conn:
        conn.execute(
            "UPDATE findings SET verified = ? WHERE finding_id = ?",
            (1 if verified else 0, finding_id),
        )
        conn.commit()
