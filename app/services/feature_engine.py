"""
PREVAIL - Feature Engine
Converts raw telemetry events into time-windowed behavioral features.
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.services.telemetry import TelemetryEvent


def events_to_dataframe(events: List[TelemetryEvent]) -> pd.DataFrame:
    rows = [e.to_dict() for e in events]
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.sort_values("timestamp", inplace=True)
    return df


def compute_window_features(df: pd.DataFrame, window_seconds: int, prefix: str) -> Dict[str, Any]:
    if df.empty:
        return {}
    features = {}
    cutoff = df["timestamp"].max() - timedelta(seconds=window_seconds)
    window = df[df["timestamp"] >= cutoff]

    features[f"failed_logins_{prefix}"] = int((window.get("event_type", pd.Series()) == "auth_failure").sum())
    features[f"total_events_{prefix}"] = len(window)
    features[f"unique_ips_{prefix}"] = window["source_ip"].nunique() if "source_ip" in window else 0
    features[f"unique_destinations_{prefix}"] = window["destination_ip"].nunique() if "destination_ip" in window else 0
    features[f"unique_ports_{prefix}"] = window["destination_port"].nunique() if "destination_port" in window else 0
    features[f"bytes_sent_{prefix}"] = int(window.get("bytes_sent", pd.Series(dtype=float)).sum())
    features[f"bytes_received_{prefix}"] = int(window.get("bytes_received", pd.Series(dtype=float)).sum())
    features[f"login_successes_{prefix}"] = int((window.get("login_success", pd.Series(dtype=bool)) == True).sum())
    features[f"login_failures_{prefix}"] = int((window.get("login_success", pd.Series(dtype=bool)) == False).sum())

    if "event_type" in window:
        for etype in ["host_discovery", "port_scan", "data_transfer", "privilege_change", "command_execution", "config_change"]:
            features[f"{etype}_count_{prefix}"] = int((window["event_type"] == etype).sum())
    return features


def extract_features(events: List[TelemetryEvent], windows: Optional[List[int]] = None) -> Dict[str, Any]:
    if not events:
        return {}
    windows = windows or [300, 900, 3600]
    df = events_to_dataframe(events)
    if df.empty:
        return {}

    features = {}
    labels = {300: "5m", 900: "15m", 3600: "1h"}
    for w in windows:
        features.update(compute_window_features(df, w, labels.get(w, f"{w}s")))

    if not df.empty:
        latest = df.iloc[-1]
        hour = df["timestamp"].iloc[-1].hour
        features["unusual_login_time"] = 1 if hour < 6 or hour > 22 else 0
        features["is_weekend"] = 1 if df["timestamp"].iloc[-1].weekday() >= 5 else 0
        features["privilege_change"] = 1 if (df.get("event_type", pd.Series()) == "privilege_change").any() else 0

        if "destination_ip" in df:
            internal = df["destination_ip"].str.startswith("10.0.").sum()
            external = len(df) - internal
            features["internal_connections"] = int(internal)
            features["external_connections"] = int(external)
            features["external_ratio"] = external / max(len(df), 1)
        else:
            features["internal_connections"] = 0
            features["external_connections"] = 0
            features["external_ratio"] = 0.0

        if "failed_login_count" in df:
            max_fails = df["failed_login_count"].max()
            features["max_failed_logins"] = int(max_fails) if pd.notna(max_fails) else 0
        else:
            features["max_failed_logins"] = 0

        total_bytes_out = df.get("bytes_sent", pd.Series(dtype=float)).sum()
        features["high_data_volume"] = 1 if total_bytes_out > 10_000_000 else 0

    features["event_count"] = len(events)
    return features


def extract_labeled_features(events: List[TelemetryEvent], prediction_horizon_minutes: int = 30) -> Dict[str, Any]:
    features = extract_features(events)
    if not events:
        features["label"] = 0
        return features

    df = events_to_dataframe(events)
    has_future_attack = False
    if "is_attack" in df.columns:
        attack_events = df[df["is_attack"] == True]
        if not attack_events.empty:
            attack_time = attack_events["timestamp"].min()
            last_event_time = df["timestamp"].max()
            time_diff = (attack_time - last_event_time).total_seconds() / 60
            if time_diff <= prediction_horizon_minutes:
                has_future_attack = True

    features["label"] = 1 if has_future_attack else 0
    return features


def build_feature_matrix(event_groups: List[List[TelemetryEvent]], prediction_horizon_minutes: int = 30) -> pd.DataFrame:
    feature_list = []
    for group in event_groups:
        feat = extract_labeled_features(group, prediction_horizon_minutes)
        feature_list.append(feat)
    if not feature_list:
        return pd.DataFrame()
    return pd.DataFrame(feature_list).fillna(0)
