"""
PREVAIL - Audit Log
Records admin actions with timestamps. In-memory + SQLite persistence.
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "prevail.db"
_buffer: List[Dict[str, Any]] = []


def _ensure_table():
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                source TEXT DEFAULT 'admin',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        conn.close()


def log_action(action: str, details: Optional[Dict[str, Any]] = None, source: str = "admin"):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "details": details or {},
        "source": source,
    }
    _buffer.append(entry)
    if len(_buffer) > 100:
        _flush()
    try:
        _ensure_table()
        conn = sqlite3.connect(str(DB_PATH))
        try:
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, details, source) VALUES (?, ?, ?, ?)",
                (entry["timestamp"], action, json.dumps(details or {}), source)
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def _flush():
    if not _buffer:
        return
    try:
        _ensure_table()
        conn = sqlite3.connect(str(DB_PATH))
        try:
            for entry in _buffer:
                conn.execute(
                    "INSERT INTO audit_log (timestamp, action, details, source) VALUES (?, ?, ?, ?)",
                    (entry["timestamp"], entry["action"], json.dumps(entry["details"]), entry["source"])
                )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
    _buffer.clear()


def get_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        _ensure_table()
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except Exception:
        return list(reversed(_buffer[-limit:]))
