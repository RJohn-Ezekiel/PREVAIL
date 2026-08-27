"""
PREVAIL - AI19 FastAPI Application
Predictive cybersecurity platform.
"""
import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.database import (
    init_db, store_event, store_prediction, store_risk_history,
    store_simulation_run, store_events_batch, get_recent_events,
    get_risk_history, get_predictions, get_simulation_runs,
    get_model_metadata, get_event_count, store_model_metadata,
    get_table_stats, reset_all_data, reset_table,
)
from app.services.feature_engine import extract_features, events_to_dataframe
from app.services.anomaly_detector import get_detector, train_anomaly_detector
from app.services.risk_engine import compute_risk
from app.services.sequence_engine import get_engine, SequenceEngine
from app.services.explanation_engine import explain_risk
from app.services.telemetry import TelemetryEvent
from app.services.data_inspector import get_filtered_events, get_event_trace, get_statistics, FilterParser
from simulation.event_generator import load_scenario, generate_baseline_data, generate_training_data
from simulation.attack_scenarios import get_scenario, list_scenarios, SCENARIOS

@asynccontextmanager
async def lifespan(app):
    global _main_loop, _event_queue
    _main_loop = asyncio.get_event_loop()
    _event_queue = asyncio.Queue()
    # Start background task to drain queue and broadcast to WebSockets
    asyncio.ensure_future(_broadcast_worker())
    init_db()
    detector = get_detector()
    if not detector.is_trained:
        _train_models_background()
    yield


async def _broadcast_worker():
    """Drain event queue and broadcast to all connected WebSockets."""
    while True:
        event_data = await _event_queue.get()
        if not connected_websockets:
            continue
        dead = []
        payload = json.dumps(event_data)
        for ws in connected_websockets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in connected_websockets:
                connected_websockets.remove(ws)

app = FastAPI(title="PREVAIL - AI19", version="1.0.0", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

# Global state
simulation_state = {
    "running": False,
    "scenario": None,
    "current_step": 0,
    "events": [],
    "risk_history": [],
    "current_risk": {"risk_score": 8, "risk_level": "LOW", "predicted_stage": "normal", "key_signals": ["System operational"], "components": {}, "explanation": {}},
    "thread": None,
    "stop_event": False,
}
sequence_engine = SequenceEngine(window_size=15)
connected_websockets: list = []
_main_loop = None
_event_queue = None  # asyncio.Queue for thread-safe broadcast


def _train_models_background():
    def _train():
        try:
            import traceback
            import shutil
            from app.services.feature_engine import extract_features, extract_labeled_features

            training_data = generate_training_data(n_scenarios=15, seed=42)
            feature_groups = []
            group = []
            for ev in training_data:
                group.append(ev)
                if len(group) >= 20:
                    feature_groups.append(group)
                    group = []
            if group:
                feature_groups.append(group)

            all_features = []
            all_labeled = []
            for grp in feature_groups:
                feat = extract_features(grp)
                if feat:
                    all_features.append(feat)
                labeled = extract_labeled_features(grp)
                if labeled:
                    all_labeled.append(labeled)

            if not all_features:
                print("No features extracted during training")
                return

            import pandas as pd
            import numpy as np

            # --- Model 1: Isolation Forest (Anomaly Detector) ---
            df = pd.DataFrame(all_features).fillna(0)
            feature_names = list(df.columns)
            X = df.values.astype(float)
            detector = get_detector()
            metrics = detector.train(X, feature_names)
            detector.save()
            store_model_metadata("anomaly", "isolation_forest", metrics, "models/anomaly/isolation_forest.joblib")
            print(f"[1/3] Isolation Forest trained: {metrics}")

            # --- Model 2: Random Forest (Attack Classifier) ---
            if all_labeled:
                lf_df = pd.DataFrame(all_labeled).fillna(0)
                if "label" in lf_df.columns:
                    X_clf = lf_df.drop(columns=["label"]).values.astype(float)
                    y_clf = lf_df["label"].values.astype(int)
                    if len(np.unique(y_clf)) >= 2:
                        from sklearn.ensemble import RandomForestClassifier
                        from sklearn.model_selection import cross_val_score
                        clf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
                        scores = cross_val_score(clf, X_clf, y_clf, cv=min(3, len(y_clf)), scoring="f1")
                        clf.fit(X_clf, y_clf)
                        clf_metrics = {
                            "f1_mean": round(float(scores.mean()), 4),
                            "f1_std": round(float(scores.std()), 4),
                            "n_estimators": 200,
                            "n_samples": len(X_clf),
                            "n_features": X_clf.shape[1],
                        }
                        Path("models/classifier").mkdir(parents=True, exist_ok=True)
                        import joblib
                        joblib.dump({"model": clf, "feature_names": list(lf_df.columns), "metrics": clf_metrics}, "models/classifier/random_forest.joblib")
                        store_model_metadata("classifier", "random_forest", clf_metrics, "models/classifier/random_forest.joblib")
                        print(f"[2/3] Random Forest trained: {clf_metrics}")

            # --- Model 3: Logistic Regression (Baseline) ---
            if all_labeled:
                lf_df = pd.DataFrame(all_labeled).fillna(0)
                if "label" in lf_df.columns:
                    X_lr = lf_df.drop(columns=["label"]).values.astype(float)
                    y_lr = lf_df["label"].values.astype(int)
                    if len(np.unique(y_lr)) >= 2:
                        from sklearn.linear_model import LogisticRegression
                        from sklearn.preprocessing import StandardScaler
                        scaler = StandardScaler()
                        X_lr_scaled = scaler.fit_transform(X_lr)
                        lr = LogisticRegression(max_iter=500, random_state=42)
                        lr.fit(X_lr_scaled, y_lr)
                        lr_acc = round(float(lr.score(X_lr_scaled, y_lr)), 4)
                        lr_metrics = {"accuracy": lr_acc, "n_samples": len(X_lr)}
                        Path("models/classifier").mkdir(parents=True, exist_ok=True)
                        import joblib
                        joblib.dump({"model": lr, "scaler": scaler, "feature_names": list(lf_df.columns), "metrics": lr_metrics}, "models/classifier/logistic_regression.joblib")
                        store_model_metadata("classifier", "logistic_regression", lr_metrics, "models/classifier/logistic_regression.joblib")
                        print(f"[3/3] Logistic Regression trained: {lr_metrics}")

            print("All models trained successfully.")
        except Exception as e:
            print(f"Training error: {e}")
            traceback.print_exc()
    t = threading.Thread(target=_train, daemon=True)
    t.start()


@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse(str(Path(__file__).parent / "static" / "index.html"))


@app.get("/api/status")
async def status():
    detector = get_detector()
    return {
        "app": "PREVAIL - AI19",
        "version": "1.0.0",
        "status": "running",
        "models_loaded": detector.is_trained,
        "events_stored": get_event_count(),
        "simulation_running": simulation_state["running"],
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/risk")
async def get_risk():
    return simulation_state["current_risk"]


@app.get("/api/events")
async def get_events(limit: int = 50):
    return get_recent_events(limit)


@app.get("/api/timeline")
async def get_timeline(limit: int = 100):
    history = get_risk_history(limit)
    return {"timeline": list(reversed(history))}


@app.get("/api/models")
async def get_models():
    return {
        "models": get_model_metadata(),
        "available_scenarios": list_scenarios(),
    }


@app.get("/api/evaluation")
async def get_evaluation():
    return {
        "accuracy": None,
        "precision": None,
        "recall": None,
        "f1": None,
        "note": "Train models first to see evaluation metrics.",
        "model_metadata": get_model_metadata(),
    }


@app.get("/api/simulation/status")
async def simulation_status():
    return {
        "running": simulation_state["running"],
        "scenario": simulation_state["scenario"],
        "current_step": simulation_state["current_step"],
        "total_events": len(simulation_state["events"]),
        "risk_history": simulation_state["risk_history"][-20:],
    }


class SimulationRequest(BaseModel):
    scenario: str = "multi_stage_attack"
    speed: float = 1.0


@app.post("/api/simulation/start")
async def start_simulation(req: SimulationRequest = SimulationRequest()):
    if simulation_state["running"]:
        return {"status": "already_running", "scenario": simulation_state["scenario"]}

    simulation_state["running"] = True
    simulation_state["scenario"] = req.scenario
    simulation_state["current_step"] = 0
    simulation_state["events"] = []
    simulation_state["risk_history"] = []
    simulation_state["current_risk"] = {
        "risk_score": 8, "risk_level": "LOW", "predicted_stage": "normal",
        "key_signals": ["Simulation initialized"], "components": {}, "explanation": {}
    }
    sequence_engine.reset()

    def _run_simulation():
        try:
            import traceback
            scenario_def = get_scenario(req.scenario)
            base_time = datetime.utcnow()
            all_events = load_scenario(req.scenario, base_time)
            if not all_events:
                simulation_state["running"] = False
                return

            accumulated_events = []
            event_idx = 0
            for stage in scenario_def.get("stages", []):
                if not simulation_state["running"]:
                    break
                stage_count = stage.get("event_count", 1)
                stage_events = all_events[event_idx:event_idx + stage_count]
                event_idx += stage_count

                for ev in stage_events:
                    if not simulation_state["running"]:
                        break
                    ev_dict = ev.to_dict()
                    ev_dict["is_attack"] = ev.is_attack
                    ev_dict["attack_stage"] = ev.attack_stage
                    simulation_state["events"].append(ev_dict)
                    accumulated_events.append(ev)
                    store_event(ev_dict)

                    seq_result = sequence_engine.add_event(ev)
                    features = extract_features(accumulated_events[-25:])

                    detector = get_detector()
                    if detector.is_trained and features:
                        feature_vals = [float(v) for v in features.values() if isinstance(v, (int, float, bool))]
                        anomaly_result = detector.predict(feature_vals)
                    else:
                        anomaly_result = {"anomaly_score": 0.0, "is_anomalous": False, "top_features": [], "confidence": 0.0}

                    temporal_score = seq_result.get("temporal_score", 0)
                    if temporal_score > 50:
                        attack_prob = min(70 + temporal_score * 0.3, 95)
                    elif temporal_score > 20:
                        attack_prob = temporal_score * 1.2
                    else:
                        attack_prob = max(0, temporal_score * 0.3)

                    risk_result = compute_risk(
                        anomaly_score=anomaly_result.get("anomaly_score", 0),
                        attack_probability=attack_prob,
                        temporal_score=temporal_score,
                        behavioral_signals=features,
                    )

                    explanation = explain_risk(risk_result, anomaly_result, features)

                    current = {
                        "risk_score": risk_result["risk_score"],
                        "risk_level": risk_result["risk_level"],
                        "predicted_stage": risk_result["predicted_stage"],
                        "key_signals": risk_result["key_signals"],
                        "components": risk_result["components"],
                        "anomaly_score": anomaly_result.get("anomaly_score", 0),
                        "temporal_score": temporal_score,
                        "attack_probability": attack_prob,
                        "explanation": explanation,
                        "stage_label": stage.get("label", ""),
                        "event_type": ev.event_type.value if ev.event_type else "",
                        "timestamp": ev.timestamp.isoformat(),
                    }

                    simulation_state["current_risk"] = current
                    simulation_state["risk_history"].append({
                        "timestamp": ev.timestamp.isoformat(),
                        "risk_score": risk_result["risk_score"],
                        "risk_level": risk_result["risk_level"],
                        "stage": stage.get("label", ""),
                    })
                    store_risk_history(risk_result["risk_score"], risk_result["risk_level"], "simulation")
                    store_prediction(current)

                    # Broadcast event via WebSocket for real-time visibility
                    event_payload = {
                        "type": "event",
                        "event_id": ev.event_id,
                        "timestamp": ev.timestamp.isoformat(),
                        "event_type": ev.event_type.value if ev.event_type else "",
                        "user_id": ev.user_id or "",
                        "source_ip": ev.source_ip or "",
                        "destination_ip": ev.destination_ip or "",
                        "risk_score": risk_result["risk_score"],
                        "risk_level": risk_result["risk_level"],
                        "anomaly_score": anomaly_result.get("anomaly_score", 0),
                        "temporal_score": temporal_score,
                        "attack_probability": attack_prob,
                        "attack_stage": ev.attack_stage or stage.get("label", ""),
                        "stage_label": stage.get("label", ""),
                    }
                    try:
                        _push_event(event_payload)
                    except Exception:
                        pass

                    # Sleep in small chunks so stop is responsive
                    sleep_time = max(0.3, 1.5 / req.speed)
                    elapsed = 0
                    while elapsed < sleep_time:
                        if not simulation_state["running"]:
                            break
                        time.sleep(min(0.1, sleep_time - elapsed))
                        elapsed += 0.1

            peak = max((r["risk_score"] for r in simulation_state["risk_history"]), default=0)
            peak_level = "LOW"
            for r in simulation_state["risk_history"]:
                if r["risk_score"] == peak:
                    peak_level = r["risk_level"]
                    break
            store_simulation_run(req.scenario, simulation_state["events"], peak, peak_level)
            simulation_state["running"] = False
        except Exception as e:
            print(f"Simulation error: {e}")
            traceback.print_exc()
            simulation_state["running"] = False

    t = threading.Thread(target=_run_simulation, daemon=True)
    simulation_state["thread"] = t
    t.start()
    return {"status": "started", "scenario": req.scenario}


@app.post("/api/simulation/stop")
async def stop_simulation():
    simulation_state["running"] = False
    simulation_state["stop_event"] = True
    return {"status": "stopped"}


class InjectEventRequest(BaseModel):
    event_type: str = "login"
    user_id: str = "admin_user"
    source_ip: str = "10.0.2.99"
    destination_ip: str = "10.0.1.10"
    severity: str = "medium"


@app.post("/api/admin/inject-event")
async def inject_event(req: InjectEventRequest):
    from app.services.telemetry import EventType, PrivilegeLevel
    type_map = {
        "login": EventType.LOGIN, "auth_failure": EventType.AUTH_FAILURE,
        "host_discovery": EventType.HOST_DISCOVERY, "port_scan": EventType.PORT_SCAN,
        "privilege_change": EventType.PRIVILEGE_CHANGE, "command_execution": EventType.COMMAND_EXECUTION,
        "data_transfer": EventType.DATA_TRANSFER, "file_access": EventType.FILE_ACCESS,
        "config_change": EventType.CONFIG_CHANGE,
    }
    severity_risk = {"low": 5, "medium": 15, "high": 30, "critical": 50}
    ev_type = type_map.get(req.event_type, EventType.LOGIN)

    ev = TelemetryEvent(
        timestamp=datetime.utcnow(), user_id=req.user_id,
        source_ip=req.source_ip, destination_ip=req.destination_ip,
        event_type=ev_type, login_success=req.event_type == "login",
        privilege_level=PrivilegeLevel.ADMIN if req.severity in ("high", "critical") else PrivilegeLevel.USER,
        bytes_sent=50000 if req.event_type == "data_transfer" else 0,
        bytes_received=0, is_attack=req.severity in ("high", "critical"),
        attack_stage=f"admin_injected_{req.event_type}",
    )

    ev_dict = ev.to_dict()
    ev_dict["is_attack"] = ev.is_attack
    ev_dict["attack_stage"] = ev.attack_stage
    store_event(ev_dict)
    simulation_state["events"].append(ev_dict)

    seq_result = sequence_engine.add_event(ev)
    accumulated = [TelemetryEvent(**{k: v for k, v in e.items() if k in TelemetryEvent.model_fields})
                   for e in simulation_state["events"][-25:]]
    features = extract_features(accumulated) if accumulated else {}

    detector = get_detector()
    if detector.is_trained and features:
        feature_vals = [float(v) for v in features.values() if isinstance(v, (int, float, bool))]
        anomaly_result = detector.predict(feature_vals)
    else:
        anomaly_result = {"anomaly_score": 0.0, "is_anomalous": False, "top_features": [], "confidence": 0.0}

    temporal_score = seq_result.get("temporal_score", 0)
    attack_prob = min(70 + temporal_score * 0.3, 95) if temporal_score > 50 else temporal_score * 1.2 if temporal_score > 20 else max(0, temporal_score * 0.3)

    risk_result = compute_risk(
        anomaly_score=anomaly_result.get("anomaly_score", 0),
        attack_probability=attack_prob, temporal_score=temporal_score,
        behavioral_signals=features,
    )

    current = {
        "risk_score": risk_result["risk_score"], "risk_level": risk_result["risk_level"],
        "predicted_stage": risk_result["predicted_stage"],
        "key_signals": risk_result["key_signals"], "components": risk_result["components"],
        "anomaly_score": anomaly_result.get("anomaly_score", 0),
        "temporal_score": temporal_score, "attack_probability": attack_prob,
        "explanation": explain_risk(risk_result, anomaly_result, features),
        "stage_label": f"Admin Inject: {req.event_type}", "event_type": req.event_type,
        "timestamp": ev.timestamp.isoformat(),
    }
    simulation_state["current_risk"] = current
    store_risk_history(risk_result["risk_score"], risk_result["risk_level"], "admin_inject")
    store_prediction(current)

    event_payload = {
        "type": "event",
        "event_id": ev.event_id,
        "timestamp": ev.timestamp.isoformat(),
        "event_type": req.event_type,
        "user_id": req.user_id,
        "source_ip": req.source_ip,
        "destination_ip": req.destination_ip,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "anomaly_score": anomaly_result.get("anomaly_score", 0),
        "temporal_score": temporal_score,
        "attack_probability": attack_prob,
        "attack_stage": ev.attack_stage or f"admin_injected_{req.event_type}",
        "stage_label": f"Admin Inject: {req.event_type}",
    }
    try:
        _push_event(event_payload)
    except Exception:
        pass

    return {"status": "injected", "risk_score": risk_result["risk_score"], "risk_level": risk_result["risk_level"]}


class AttackChainRequest(BaseModel):
    chain_type: str = "credential_theft"


ATTACK_CHAINS = {
    "credential_theft": [
        ("auth_failure", "low"), ("auth_failure", "low"), ("auth_failure", "medium"),
        ("login", "high"), ("host_discovery", "high"), ("port_scan", "critical"),
    ],
    "data_breach": [
        ("login", "low"), ("file_access", "medium"), ("command_execution", "high"),
        ("data_transfer", "critical"), ("data_transfer", "critical"),
    ],
    "insider_threat": [
        ("login", "low"), ("file_access", "medium"), ("privilege_change", "high"),
        ("command_execution", "high"), ("data_transfer", "critical"),
    ],
    "apt_recon": [
        ("host_discovery", "medium"), ("port_scan", "medium"), ("port_scan", "high"),
        ("command_execution", "high"), ("privilege_change", "critical"), ("data_transfer", "critical"),
    ],
    "ransomware_prep": [
        ("login", "low"), ("command_execution", "medium"), ("file_access", "high"),
        ("config_change", "high"), ("command_execution", "critical"), ("data_transfer", "critical"),
    ],
}


@app.post("/api/admin/inject-attack-chain")
async def inject_attack_chain(req: AttackChainRequest):
    chain = ATTACK_CHAINS.get(req.chain_type, ATTACK_CHAINS["credential_theft"])

    def _run_chain():
        try:
            from app.services.telemetry import EventType, PrivilegeLevel
            type_map = {
                "login": EventType.LOGIN, "auth_failure": EventType.AUTH_FAILURE,
                "host_discovery": EventType.HOST_DISCOVERY, "port_scan": EventType.PORT_SCAN,
                "privilege_change": EventType.PRIVILEGE_CHANGE, "command_execution": EventType.COMMAND_EXECUTION,
                "data_transfer": EventType.DATA_TRANSFER, "file_access": EventType.FILE_ACCESS,
                "config_change": EventType.CONFIG_CHANGE,
            }
            accumulated = list(simulation_state["events"][-25:])
            accumulated_events = []
            for ed in accumulated:
                try:
                    accumulated_events.append(TelemetryEvent(**{k: v for k, v in ed.items() if k in TelemetryEvent.model_fields and v is not None}))
                except Exception:
                    pass

            for i, (event_type, severity) in enumerate(chain):
                ev = TelemetryEvent(
                    timestamp=datetime.utcnow(), user_id="admin_user",
                    source_ip="10.0.2.99", destination_ip="10.0.1.20",
                    event_type=type_map.get(event_type, EventType.LOGIN),
                    login_success=event_type == "login",
                    privilege_level=PrivilegeLevel.ADMIN if severity in ("high", "critical") else PrivilegeLevel.USER,
                    bytes_sent=50000 if event_type == "data_transfer" else 0,
                    is_attack=severity in ("high", "critical"),
                    attack_stage=f"chain_{req.chain_type}_{event_type}",
                )
                ev_dict = ev.to_dict()
                ev_dict["is_attack"] = ev.is_attack
                ev_dict["attack_stage"] = ev.attack_stage
                store_event(ev_dict)
                simulation_state["events"].append(ev_dict)
                accumulated_events.append(ev)
                if len(accumulated_events) > 25:
                    accumulated_events = accumulated_events[-25:]

                # Run through full pipeline
                seq_result = sequence_engine.add_event(ev)
                features = extract_features(accumulated_events) if accumulated_events else {}

                detector = get_detector()
                if detector.is_trained and features:
                    feature_vals = [float(v) for v in features.values() if isinstance(v, (int, float, bool))]
                    anomaly_result = detector.predict(feature_vals)
                else:
                    anomaly_result = {"anomaly_score": 0.0, "is_anomalous": False, "top_features": [], "confidence": 0.0}

                temporal_score = seq_result.get("temporal_score", 0)
                if temporal_score > 50:
                    attack_prob = min(70 + temporal_score * 0.3, 95)
                elif temporal_score > 20:
                    attack_prob = temporal_score * 1.2
                else:
                    attack_prob = max(0, temporal_score * 0.3)

                risk_result = compute_risk(
                    anomaly_score=anomaly_result.get("anomaly_score", 0),
                    attack_probability=attack_prob, temporal_score=temporal_score,
                    behavioral_signals=features,
                )
                explanation = explain_risk(risk_result, anomaly_result, features)

                current = {
                    "risk_score": risk_result["risk_score"],
                    "risk_level": risk_result["risk_level"],
                    "predicted_stage": risk_result["predicted_stage"],
                    "key_signals": risk_result["key_signals"],
                    "components": risk_result["components"],
                    "anomaly_score": anomaly_result.get("anomaly_score", 0),
                    "temporal_score": temporal_score,
                    "attack_probability": attack_prob,
                    "explanation": explanation,
                    "stage_label": f"Chain: {req.chain_type} [{i+1}/{len(chain)}] {event_type}",
                    "event_type": event_type,
                    "timestamp": ev.timestamp.isoformat(),
                }
                simulation_state["current_risk"] = current
                simulation_state["risk_history"].append({
                    "timestamp": ev.timestamp.isoformat(),
                    "risk_score": risk_result["risk_score"],
                    "risk_level": risk_result["risk_level"],
                    "stage": f"chain_{req.chain_type}",
                })
                store_risk_history(risk_result["risk_score"], risk_result["risk_level"], "admin_chain")
                store_prediction(current)

                # Broadcast event via WebSocket
                event_payload = {
                    "type": "event",
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp.isoformat(),
                    "event_type": event_type,
                    "user_id": "admin_user",
                    "source_ip": "10.0.2.99",
                    "destination_ip": "10.0.1.20",
                    "risk_score": risk_result["risk_score"],
                    "risk_level": risk_result["risk_level"],
                    "anomaly_score": anomaly_result.get("anomaly_score", 0),
                    "temporal_score": temporal_score,
                    "attack_probability": attack_prob,
                    "attack_stage": ev.attack_stage,
                    "stage_label": f"Chain: {req.chain_type} [{i+1}/{len(chain)}] {event_type}",
                }
                _push_event(event_payload)

                # Slow enough to watch: 2 seconds between events
                time.sleep(2)

        except Exception as e:
            print(f"Chain error: {e}")
            import traceback
            traceback.print_exc()

    t = threading.Thread(target=_run_chain, daemon=True)
    t.start()
    return {"status": "chain_started", "chain_type": req.chain_type, "events_count": len(chain)}


@app.post("/api/models/train")
async def train_models():
    def _train():
        _train_all_models()
    t = threading.Thread(target=_train, daemon=True)
    t.start()
    return {"status": "training_started", "message": "Model training initiated in background."}


@app.get("/api/admin/system-info")
async def system_info():
    detector = get_detector()
    stats = get_table_stats()
    import os
    db_size = os.path.getsize(str(Path("data/prevail.db"))) if Path("data/prevail.db").exists() else 0
    return {
        "app_name": "PREVAIL - AI19",
        "version": "1.0.0",
        "uptime": datetime.utcnow().isoformat(),
        "models_loaded": detector.is_trained,
        "model_features": len(detector.feature_names) if detector.is_trained else 0,
        "model_trained": detector.is_trained,
        "simulation_running": simulation_state["running"],
        "current_scenario": simulation_state["scenario"],
        "events_in_memory": len(simulation_state["events"]),
        "database": {
            "path": str(Path("data/prevail.db").resolve()),
            "size_bytes": db_size,
            "size_mb": round(db_size / 1024 / 1024, 2),
            "tables": stats,
        },
        "pipeline": {
            "event_ingestion": "active",
            "feature_extraction": "active",
            "anomaly_detection": "active" if detector.is_trained else "no_model",
            "temporal_analysis": "active",
            "risk_engine": "active",
            "explanation_engine": "active",
        },
    }


@app.post("/api/admin/reset")
async def reset_data():
    simulation_state["running"] = False
    simulation_state["events"] = []
    simulation_state["risk_history"] = []
    simulation_state["current_risk"] = {
        "risk_score": 8, "risk_level": "LOW", "predicted_stage": "normal",
        "key_signals": ["System reset — monitoring active"], "components": {}, "explanation": {}
    }
    sequence_engine.reset()
    reset_all_data()
    # Remove trained models
    import shutil
    model_dirs = [Path("models/anomaly"), Path("models/classifier"), Path("models/sequence")]
    for d in model_dirs:
        if d.exists():
            shutil.rmtree(d)
            d.mkdir(parents=True, exist_ok=True)
    return {"status": "reset_complete", "message": "All data, models, and history cleared."}


@app.post("/api/admin/reset/{table}")
async def reset_table_endpoint(table: str):
    if table == "all":
        return await reset_data()
    ok = reset_table(table)
    if ok:
        return {"status": "reset", "table": table}
    raise HTTPException(status_code=400, detail=f"Cannot reset table: {table}")


class InspectorFilterRequest(BaseModel):
    query: str = ""
    limit: int = 200
    offset: int = 0


@app.post("/api/inspector/events")
async def inspector_events(req: InspectorFilterRequest = InspectorFilterRequest()):
    filters = FilterParser.parse(req.query) if req.query else []
    return get_filtered_events(filters, req.limit, req.offset)


@app.get("/api/inspector/events/{event_id}/trace")
async def inspector_event_trace(event_id: int):
    return get_event_trace(event_id)


@app.get("/api/inspector/stats")
async def inspector_stats():
    return get_statistics()


def _push_event(event_data: dict):
    """Thread-safe: push event to queue for broadcast. Called from any thread."""
    if _event_queue is not None and _main_loop is not None and _main_loop.is_running():
        asyncio.run_coroutine_threadsafe(_event_queue.put(event_data), _main_loop)


async def broadcast_event(event_data: dict):
    """Async version: push event to queue."""
    if _event_queue is not None:
        await _event_queue.put(event_data)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            data = json.dumps(simulation_state["current_risk"])
            await websocket.send_text(data)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
    except Exception:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
