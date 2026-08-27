# PREVAIL - AI19: Predictive Early-warning & Vulnerability Intelligence Layer

> **The Attack Before It Happens**

A hackathon-ready predictive cybersecurity platform that analyzes behavioral telemetry to estimate attack probability before attacks materialize. Features real-time attack visualization, Wireshark-style data inspector, and production admin controls.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run (models auto-train on first start)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# 3. Open http://localhost:8000
```

No database setup needed. SQLite initializes automatically. Models train in background on first run.

## Architecture

```
Telemetry Events
      |
      v
[1] Event Ingestion -----> SQLite (raw events)
      |
[2] Feature Engine -------> 48 features (5m/15m/1h windows)
      |
[3] Anomaly Detector ----> Isolation Forest (behavioral anomaly)
      |
[4] Sequence Engine -----> Temporal pattern matching (6 attack patterns)
      |
[5] Risk Engine ---------> Weighted score (0-100) with 4 risk levels
      |
[6] Explanation Engine --> Human-readable summaries + recommendations
      |
      v
  Dashboard + Inspector + WebSocket (real-time push)
```

## ML Models

| Model | Purpose | Library |
|-------|---------|---------|
| Isolation Forest | Behavioral anomaly detection | scikit-learn |
| Random Forest | Attack probability classification | scikit-learn |
| XGBoost | Gradient boosting classifier | xgboost |
| Logistic Regression | Baseline classifier | scikit-learn |

Models auto-train on startup. Retrain from admin panel at any time.

## Dashboard

Real-time threat monitoring with:

- **Risk Gauge** - 0-100 score with LOW/MODERATE/HIGH/CRITICAL levels
- **Attack Probability** - 30-minute prediction window
- **Anomaly Score** - Behavioral deviation from baseline
- **Temporal Pattern** - Multi-stage attack correlation
- **Risk Timeline** - Interactive canvas graph with hover tooltips
- **Risk Components** - Breakdown of all 4 scoring factors
- **Key Signals** - Human-readable threat indicators
- **Recent Events** - Live event table

## Inspector (Wireshark-style)

Three-pane data viewer for inspecting raw events:

**Filter syntax:**
```
event_type:port_scan              # exact match
source_ip:10.0.2.*                # wildcard
risk:>50                          # comparison
user:admin AND event_type:login   # AND logic
NOT event_type:login              # negation
```

**Features:**
- Live event list (auto-scrolls, color-coded by risk)
- Event detail pane (all TelemetryEvent fields)
- Pipeline trace (7 processing stages with timestamps)
- Statistics panel (event types, IPs, risk distribution)
- Export as CSV or JSON
- Pause/resume live feed

## Admin Panel

### Attack Chain Simulation
Execute realistic multi-stage attacks that flow through the full ML pipeline:
- Credential Theft (auth failure -> login -> recon -> port scan)
- Data Breach (login -> file access -> command exec -> exfiltration)
- Insider Threat (login -> privilege change -> data transfer)
- APT Recon (host discovery -> port scan -> exploit -> exfiltration)
- Ransomware Prep (login -> command exec -> config change -> exfiltration)

Each event: feature extraction -> anomaly detection -> temporal correlation -> risk scoring -> explanation generation. 2-second delay between events for real-time visibility.

### Custom Event Injection
Inject individual events with full pipeline processing:
- Event type, user ID, source/destination IP, severity level
- Dashboard risk updates immediately
- Event appears in inspector in real-time

### System Metrics (Self-contained)
- Event throughput (events/min)
- Processing latency (ms avg)
- Buffer size (events in memory)
- Database size and record counts
- Pipeline component health
- Uptime

## Project Structure

```
AI19/
├── app/
│   ├── main.py                      # FastAPI app, endpoints, simulation
│   ├── services/
│   │   ├── telemetry.py             # TelemetryEvent data model
│   │   ├── feature_engine.py        # 48-feature extraction (3 time windows)
│   │   ├── anomaly_detector.py      # Isolation Forest wrapper
│   │   ├── risk_engine.py           # Weighted risk scoring (0-100)
│   │   ├── sequence_engine.py       # Temporal pattern matching
│   │   ├── explanation_engine.py    # Human-readable explanations
│   │   ├── xgboost_classifier.py    # XGBoost classifier
│   │   ├── lightgbm_classifier.py   # LightGBM classifier
│   │   ├── explainability.py        # SHAP integration
│   │   ├── model_evaluator.py       # Confusion matrix, ROC, feature importance
│   │   ├── concept_drift.py         # Performance drift detection
│   │   ├── alert_manager.py         # Threat alert system
│   │   ├── config_manager.py        # Live config singleton
│   │   ├── detection_rules.py       # 8 toggleable detection rules
│   │   ├── audit_log.py             # Admin action audit trail
│   │   └── data_inspector.py        # Wireshark-style data viewer
│   ├── database/
│   │   └── database.py              # SQLite (events, predictions, risk_history, etc.)
│   └── static/
│       ├── index.html               # Dashboard + Inspector + Admin
│       ├── app.js                   # All frontend logic
│       └── style.css                # Dark theme, production styling
├── simulation/
│   ├── event_generator.py           # 30+ synthetic event generators
│   └── attack_scenarios.py          # 3 scenario definitions
├── data/
│   └── scenarios/                   # 6 JSON attack scenario files
├── config/
│   └── config.json                  # All tunable parameters
├── models/
│   ├── anomaly/                     # Isolation Forest model files
│   └── classifier/                  # RF, XGBoost, LR, LightGBM model files
├── tests/
│   └── test_core.py                 # 16 tests
├── requirements.txt
└── README.md
```

## API Endpoints

### Core
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | App status, model loaded, event count |
| `/api/risk` | GET | Current risk state |
| `/api/events` | GET | Recent events (limit param) |
| `/api/timeline` | GET | Risk history |
| `/api/models` | GET | Model metadata + scenarios |

### Simulation
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/simulation/start` | POST | Start scenario (scenario + speed) |
| `/api/simulation/stop` | POST | Stop simulation |
| `/api/simulation/status` | GET | Running state, step, risk history |

### Admin
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/inject-event` | POST | Inject single event (full pipeline) |
| `/api/admin/inject-attack-chain` | POST | Execute multi-stage attack chain |
| `/api/admin/system-info` | GET | System status, DB size, table counts |
| `/api/admin/reset` | POST | Reset all data + models |
| `/api/admin/reset/{table}` | POST | Reset specific table |
| `/api/models/train` | POST | Retrain all ML models |

### Inspector
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/inspector/events` | POST | Filtered event query |
| `/api/inspector/events/{id}/trace` | GET | Pipeline trace for event |
| `/api/inspector/stats` | GET | Aggregated statistics |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `/ws` | Real-time risk + event broadcasts |

## Configuration

All parameters in `config/config.json`:

```json
{
  "risk_engine": {
    "weights": {
      "anomaly_score": 0.25,
      "attack_probability": 0.30,
      "temporal_score": 0.25,
      "behavioral_signals": 0.20
    },
    "thresholds": { "low": 24, "moderate": 49, "high": 74, "critical": 100 }
  },
  "model": {
    "anomaly": { "type": "isolation_forest", "contamination": 0.1 },
    "classifier": { "type": "random_forest", "n_estimators": 200 }
  }
}
```

## Dependencies

```
fastapi, uvicorn, pydantic, pandas, numpy, scikit-learn, joblib
xgboost, lightgbm, shap, imbalanced-learn
websockets, aiofiles, python-multipart
pytest, pytest-asyncio
```

All cross-platform (Windows + Linux). No OS-level dependencies.

## Testing

```bash
pytest tests/test_core.py -v
```

16 tests covering: TelemetryEvent, FeatureEngine, RiskEngine, SequenceEngine, ExplanationEngine, Scenarios.

## Security Note

Defensive cybersecurity research prototype. Generates synthetic telemetry representing suspicious behavior. Does NOT perform actual attacks, network scanning, exploitation, credential theft, or data exfiltration.

## License

MIT License - Built for hackathon demonstration and research purposes.

---

**PREVAIL - AI19** | *Predictive Early-warning & Vulnerability Intelligence Layer*
