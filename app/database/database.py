"""
PREVAIL - SQLite Database Layer
Stores events, predictions, risk history, simulation runs.
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "prevail.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            event_type TEXT,
            login_success INTEGER,
            failed_login_count INTEGER DEFAULT 0,
            privilege_level TEXT,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            is_attack INTEGER,
            attack_stage TEXT,
            raw_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            risk_score REAL,
            risk_level TEXT,
            attack_probability REAL,
            anomaly_score REAL,
            temporal_score REAL,
            predicted_stage TEXT,
            explanation_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            risk_score REAL,
            risk_level TEXT,
            source TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS simulation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT,
            started_at TEXT,
            completed_at TEXT,
            total_events INTEGER,
            peak_risk_score REAL,
            peak_risk_level TEXT,
            events_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS model_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_type TEXT,
            model_name TEXT,
            trained_at TEXT,
            metrics_json TEXT,
            file_path TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
        CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON predictions(timestamp);
        CREATE INDEX IF NOT EXISTS idx_risk_history_timestamp ON risk_history(timestamp);
    """)
    conn.close()


def store_event(event_dict: Dict[str, Any]):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO events (event_id, timestamp, user_id, source_ip, destination_ip,
                event_type, login_success, failed_login_count, privilege_level, bytes_sent, bytes_received,
                is_attack, attack_stage, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_dict.get("event_id"), event_dict.get("timestamp"),
            event_dict.get("user_id"), event_dict.get("source_ip"),
            event_dict.get("destination_ip"), str(event_dict.get("event_type", "")),
            1 if event_dict.get("login_success") else 0,
            event_dict.get("failed_login_count", 0),
            str(event_dict.get("privilege_level", "")),
            event_dict.get("bytes_sent", 0), event_dict.get("bytes_received", 0),
            1 if event_dict.get("is_attack") else 0,
            event_dict.get("attack_stage"),
            json.dumps(event_dict),
        ))
        conn.commit()
    finally:
        conn.close()


def store_prediction(prediction: Dict[str, Any]):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO predictions (timestamp, risk_score, risk_level, attack_probability,
                anomaly_score, temporal_score, predicted_stage, explanation_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            prediction.get("risk_score", 0),
            prediction.get("risk_level", "LOW"),
            prediction.get("attack_probability", 0),
            prediction.get("anomaly_score", 0),
            prediction.get("temporal_score", 0),
            prediction.get("predicted_stage", "normal"),
            json.dumps(prediction.get("explanation", {})),
        ))
        conn.commit()
    finally:
        conn.close()


def store_risk_history(risk_score: float, risk_level: str, source: str = "live"):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO risk_history (timestamp, risk_score, risk_level, source)
            VALUES (?, ?, ?, ?)
        """, (datetime.utcnow().isoformat(), risk_score, risk_level, source))
        conn.commit()
    finally:
        conn.close()


def store_simulation_run(scenario: str, events: List[Dict], peak_risk: float, peak_level: str):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO simulation_runs (scenario, started_at, completed_at, total_events,
                peak_risk_score, peak_risk_level, events_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scenario,
            events[0].get("timestamp") if events else datetime.utcnow().isoformat(),
            events[-1].get("timestamp") if events else datetime.utcnow().isoformat(),
            len(events), peak_risk, peak_level,
            json.dumps(events[:50]),
        ))
        conn.commit()
    finally:
        conn.close()


def store_model_metadata(model_type: str, model_name: str, metrics: Dict, file_path: str):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO model_metadata (model_type, model_name, trained_at, metrics_json, file_path)
            VALUES (?, ?, ?, ?, ?)
        """, (model_type, model_name, datetime.utcnow().isoformat(), json.dumps(metrics), file_path))
        conn.commit()
    finally:
        conn.close()


def get_recent_events(limit: int = 50) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_risk_history(limit: int = 100) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM risk_history ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_predictions(limit: int = 50) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM predictions ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_simulation_runs(limit: int = 10) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM simulation_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_model_metadata() -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM model_metadata ORDER BY trained_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_event_count() -> int:
    conn = get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


def store_events_batch(events: List[Dict[str, Any]]):
    for ev in events:
        store_event(ev)


def get_table_stats() -> Dict[str, int]:
    conn = get_connection()
    try:
        stats = {}
        for table in ["events", "predictions", "risk_history", "simulation_runs", "model_metadata"]:
            try:
                stats[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except Exception:
                stats[table] = 0
        return stats
    finally:
        conn.close()


def reset_all_data():
    conn = get_connection()
    try:
        for table in ["events", "predictions", "risk_history", "simulation_runs", "model_metadata"]:
            try:
                conn.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def reset_table(table_name: str) -> bool:
    allowed = {"events", "predictions", "risk_history", "simulation_runs", "model_metadata"}
    if table_name not in allowed:
        return False
    conn = get_connection()
    try:
        conn.execute(f"DELETE FROM {table_name}")
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()
