"""
PREVAIL - Data Inspector
Wireshark-style data viewer: filter parser, event detail, pipeline trace, statistics.
"""
import re
import json
from typing import Dict, Any, List, Optional, Tuple
from app.database.database import get_connection


class FilterParser:
    OPERATORS = {
        "=": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        ">": lambda a, b: float(a) > float(b),
        "<": lambda a, b: float(a) < float(b),
        ">=": lambda a, b: float(a) >= float(b),
        "<=": lambda a, b: float(a) <= float(b),
    }

    @classmethod
    def parse(cls, query: str) -> List[Dict[str, Any]]:
        if not query or not query.strip():
            return []
        filters = []
        parts = re.split(r'\s+AND\s+', query, flags=re.IGNORECASE)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            neg = part.upper().startswith("NOT ")
            if neg:
                part = part[4:].strip()
            for op in [">=", "<=", "!=", "=", ">", "<"]:
                if op in part:
                    field, value = part.split(op, 1)
                    field = field.strip().lower()
                    value = value.strip().strip('"').strip("'")
                    filters.append({"field": field, "op": op, "value": value, "neg": neg})
                    break
            else:
                if ":" in part:
                    field, value = part.split(":", 1)
                    filters.append({"field": field.strip().lower(), "op": "=", "value": value.strip(), "neg": neg})
        return filters

    @classmethod
    def apply(cls, events: List[Dict], filters: List[Dict[str, Any]]) -> List[Dict]:
        result = events
        for f in filters:
            field = f["field"]
            op = f["op"]
            value = f["value"]
            neg = f["neg"]
            filtered = []
            for ev in result:
                ev_val = _get_nested(ev, field)
                match = cls._match(ev_val, op, value)
                if neg:
                    match = not match
                if match:
                    filtered.append(ev)
            result = filtered
        return result

    @classmethod
    def _match(cls, ev_val, op: str, filter_val: str) -> bool:
        if ev_val is None:
            return False
        if op in (">", "<", ">=", "<="):
            try:
                return cls.OPERATORS[op](float(ev_val), float(filter_val))
            except (ValueError, TypeError):
                return False
        if op == "!=":
            return str(ev_val).lower() != filter_val.lower()
        if "*" in filter_val:
            pattern = re.escape(filter_val).replace(r"\*", ".*")
            return bool(re.match(f"^{pattern}$", str(ev_val), re.IGNORECASE))
        return str(ev_val).lower() == filter_val.lower()


def _get_nested(d: dict, key: str):
    if key in d:
        return d[key]
    key_map = {
        "user": "user_id", "type": "event_type", "src": "source_ip",
        "dest": "destination_ip", "time": "timestamp",
    }
    mapped = key_map.get(key)
    if mapped and mapped in d:
        return d[mapped]
    return None


def get_filtered_events(filters: List[Dict[str, Any]], limit: int = 200, offset: int = 0) -> Dict[str, Any]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()
        events = [dict(r) for r in rows]
        total = len(events)
        filtered = FilterParser.apply(events, filters) if filters else events
        paginated = filtered[offset:offset + limit]
        for ev in paginated:
            if ev.get("raw_json"):
                try:
                    ev["raw_data"] = json.loads(ev["raw_json"])
                except Exception:
                    ev["raw_data"] = None
        return {
            "events": paginated,
            "total": total,
            "filtered_count": len(filtered),
            "offset": offset,
            "limit": limit,
        }
    finally:
        conn.close()


def get_event_trace(event_id: int) -> Dict[str, Any]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not row:
            return {"error": "Event not found"}
        event = dict(row)
        raw = None
        if event.get("raw_json"):
            try:
                raw = json.loads(event["raw_json"])
            except Exception:
                pass
        ts = event.get("timestamp", "")
        trace = [
            {"stage": "INGESTED", "timestamp": ts, "detail": "Raw event stored to database"},
            {"stage": "FEATURES_EXTRACTED", "timestamp": ts, "detail": "48 features computed across 3 time windows"},
            {"stage": "ANOMALY_SCORED", "timestamp": ts, "detail": "Isolation Forest prediction applied"},
            {"stage": "TEMPORAL_SCORED", "timestamp": ts, "detail": "Sequence engine pattern matching"},
            {"stage": "RISK_COMPUTED", "timestamp": ts, "detail": "Weighted risk score calculated"},
            {"stage": "EXPLAINED", "timestamp": ts, "detail": "Human-readable explanation generated"},
            {"stage": "STORED", "timestamp": ts, "detail": "Predictions and risk history saved"},
        ]
        pred_row = conn.execute(
            "SELECT * FROM predictions WHERE timestamp >= ? ORDER BY timestamp ASC LIMIT 1",
            (ts,)
        ).fetchone()
        if pred_row:
            pred = dict(pred_row)
            trace[2]["detail"] = f"Anomaly score: {pred.get('anomaly_score', 0):.1f}"
            trace[3]["detail"] = f"Temporal score: {pred.get('temporal_score', 0):.1f}"
            trace[4]["detail"] = f"Risk: {pred.get('risk_score', 0):.1f} ({pred.get('risk_level', 'LOW')})"
            if pred.get("explanation_json"):
                try:
                    explanation = json.loads(pred["explanation_json"])
                    trace[5]["detail"] = explanation.get("summary", "Explanation generated")[:120]
                except Exception:
                    pass
        return {"event": event, "raw_data": raw, "trace": trace}
    finally:
        conn.close()


def get_statistics() -> Dict[str, Any]:
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        type_rows = conn.execute(
            "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC"
        ).fetchall()
        event_types = [{"type": r["event_type"], "count": r["cnt"]} for r in type_rows]

        ip_rows = conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM events WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_source_ips = [{"ip": r["source_ip"], "count": r["cnt"]} for r in ip_rows]

        user_rows = conn.execute(
            "SELECT user_id, COUNT(*) as cnt FROM events WHERE user_id IS NOT NULL GROUP BY user_id ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_users = [{"user": r["user_id"], "count": r["cnt"]} for r in user_rows]

        attack_count = conn.execute("SELECT COUNT(*) FROM events WHERE is_attack = 1").fetchone()[0]

        risk_rows = conn.execute("SELECT risk_score, risk_level FROM risk_history").fetchall()
        risk_scores = [r["risk_score"] for r in risk_rows]
        risk_distribution = {"LOW": 0, "MODERATE": 0, "HIGH": 0, "CRITICAL": 0}
        for r in risk_rows:
            level = r["risk_level"]
            if level in risk_distribution:
                risk_distribution[level] += 1

        return {
            "total_events": total,
            "attack_events": attack_count,
            "normal_events": total - attack_count,
            "event_types": event_types,
            "top_source_ips": top_source_ips,
            "top_users": top_users,
            "risk_distribution": risk_distribution,
            "avg_risk_score": round(sum(risk_scores) / max(len(risk_scores), 1), 1),
            "max_risk_score": round(max(risk_scores), 1) if risk_scores else 0,
        }
    finally:
        conn.close()
