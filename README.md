# PREVAIL — AI19: Predictive Early-warning & Vulnerability Intelligence Layer

> **The Attack Before It Happens**

A hackathon-ready predictive cybersecurity platform that analyzes behavioral telemetry to estimate attack probability before attacks materialize.

## Core Objective

PREVAIL analyzes user, system, authentication, and network behavioral telemetry to answer:

> **"Does the current sequence of behavior indicate an elevated probability of an upcoming attack?"**

The system does NOT simply classify whether an event is malicious — it predicts attack likelihood within a configurable prediction horizon (default: 30 minutes).

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PREVAIL - AI19 Architecture                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────────┐    ┌────────────────────┐   │
│  │   Synthetic  │───▶│   Feature        │───▶│  Anomaly Detector  │   │
│  │  Telemetry   │    │   Engineering    │    │  (Isolation Forest)│   │
│  │  Generator   │    │                  │    │                    │   │
│  └──────────────┘    └──────────────────┘    └─────────┬──────────┘   │
│                                                         │              │
│  ┌──────────────┐    ┌──────────────────┐             │              │
│  │   SQLite     │◀───│   Risk Engine    │◀────────────┤              │
│  │  Database    │    │                  │             │              │
│  └──────────────┘    └────────┬─────────┘             │              │
│                               │                       │              │
│                    ┌──────────┼──────────┐            │              │
│                    ▼          ▼          ▼            ▼              │
│             ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│             │ Attack   │ │ Temporal │ │Behavioral│ │Explain-  │     │
│             │Probability│ │Correlation│ │ Signals  │ │ability   │     │
│             │  Model   │ │ Engine   │ │          │ │ Engine   │     │
│             │(RF/XGB)  │ │          │ │          │ │          │     │
│             └──────────┘ └──────────┘ └──────────┘ └──────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize database and generate baseline data
python -m training.train_anomaly
python -m training.train_classifier

# 4. Run the application
python -m app.main

# 5. Open dashboard
# Navigate to http://localhost:8000
```

## 📁 Project Structure

```
AI19/
├── app/
│   ├── main.py                 # FastAPI application entry point
│   ├── api/                    # API route handlers
│   │   ├── risk.py             # Risk scoring endpoints
│   │   ├── events.py           # Event endpoints
│   │   ├── models.py           # Model management endpoints
│   │   ├── simulation.py       # Simulation control endpoints
│   │   └── evaluation.py       # Evaluation endpoints
│   ├── services/
│   │   ├── feature_engine.py   # Feature extraction from events
│   │   ├── anomaly_detector.py # Isolation Forest anomaly detection
│   │   ├── risk_engine.py      # Unified risk scoring
│   │   ├── sequence_engine.py  # Temporal correlation analysis
│   │   └── explanation_engine.py # Explainable AI
│   ├── database/
│   │   └── database.py         # SQLite operations
│   └── static/
│       ├── index.html          # Main dashboard
│       ├── admin.html          # Admin/Evaluation dashboard
│       ├── style.css           # Dark theme styling
│       └── app.js              # Dashboard JavaScript
├── models/
│   ├── anomaly/                # Trained anomaly models
│   ├── classifier/             # Trained attack probability models
│   └── sequence/               # Sequence models
├── data/
│   ├── raw/                    # Raw event data
│   ├── processed/              # Processed features
│   └── scenarios/              # Attack scenario definitions
├── training/
│   ├── train_anomaly.py        # Train anomaly detector
│   ├── train_classifier.py     # Train attack probability model
│   ├── train_sequence.py       # Train sequence model (optional)
│   └── evaluate.py             # Model evaluation
├── simulation/
│   ├── event_generator.py      # Synthetic telemetry generator
│   └── attack_scenarios.py     # Attack scenario definitions
├── config/
│   └── config.json             # Configuration
├── tests/
└── requirements.txt
```

## 🔑 Key Features

### 1. **Synthetic Telemetry Generation**
- Normal behavior patterns
- Authentication anomalies (brute force, unusual logins)
- Reconnaissance (port scanning, host discovery)
- Privilege escalation attempts
- Data exfiltration patterns
- Multi-stage attack progressions

### 2. **Behavioral Feature Engineering**
- Time-windowed aggregations (5m, 15m, 1h)
- Failed login tracking
- Network behavior profiling
- Privilege usage analysis
- Resource access deviation detection

### 3. **Anomaly Detection**
- Isolation Forest for unsupervised anomaly detection
- Configurable contamination threshold
- Top contributing feature identification

### 4. **Attack Probability Model**
- Random Forest classifier (primary)
- XGBoost support (optional)
- Logistic Regression fallback
- Temporal labeling: "attack within prediction horizon"

### 5. **Risk Engine**
- Weighted combination of multiple signals
- Configurable risk thresholds
- 4-level risk classification: LOW → MODERATE → HIGH → CRITICAL

### 6. **Temporal Correlation**
- Deterministic pattern matching
- Authentication → Reconnaissance → Privilege → Network progression
- Extensible for LSTM/GRU integration

### 7. **Explainability**
- Human-readable risk explanations
- Feature-attribution based reasoning
- No hallucinated explanations

### 8. **Live Dashboard**
- Real-time risk visualization
- Progressive attack simulation
- Professional dark theme with cyan accents
- WebSocket-ready polling architecture

### 9. **Admin/Evaluation Interface**
- Model training from UI
- Metrics: accuracy, precision, recall, F1, ROC-AUC
- Confusion matrix visualization
- False positive rate tracking
- Prediction lead time analysis

## ⚙️ Configuration

All settings in `config/config.json`:

- Model hyperparameters
- Risk engine weights and thresholds
- Feature engineering windows
- Simulation scenarios and timing
- Dashboard theme and polling

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov=simulation --cov=training
```

## 🎮 Live Demo

1. Start the application: `python -m app.main`
2. Open http://localhost:8000
3. Click **"START ATTACK SIMULATION"**
3. Watch risk progression:
   ```
   NORMAL          → Risk: 8%
   Unusual login   → Risk: 17%
   Auth failures   → Risk: 31%
   Recon           → Risk: 54%
   Privilege anom  → Risk: 72%
   Network anom    → Risk: 89%
   PREDICTED ATTACK → Risk: 89%
   ```

## 🔒 Security Note

This is a **defensive cybersecurity research prototype**. The simulator generates synthetic telemetry representing suspicious behavior — it does NOT perform actual attacks, network scanning, exploitation, credential theft, or data exfiltration.

## 📊 Model Training Labels

The attack probability model uses temporal labeling:
- **Label 0**: No attack within prediction horizon (default 30 min)
- **Label 1**: Attack begins within prediction horizon

This enables the model to answer: *"Based on current behavior, is an attack likely within the next 30 minutes?"*

## 🛠️ Development Order

1. Project skeleton & config
2. Synthetic telemetry generator
3. SQLite storage
4. Feature engine
5. Anomaly detector (Isolation Forest)
6. Risk engine
7. Temporal correlation
8. Attack probability model (RF/XGBoost)
9. Explanation engine
10. FastAPI backend
11. Dashboard
12. Live simulation
13. Evaluation dashboard
14. Tests
15. Documentation

## 📄 License

MIT License - Built for hackathon demonstration and research purposes.

---

**PREVAIL — AI19** | *Predictive Early-warning & Vulnerability Intelligence Layer* | The Attack Before It Happens