# PhishGuard – Phishing URL Detection & Security Analyzer

A full-stack web application that analyzes URLs for phishing indicators using a combination of machine learning (Random Forest) and security rules. Built with React.js, Bootstrap 5, FastAPI, and SQLite.

## Features

- **ML-Based Detection** — Random Forest model (SivakumarP/PhishingURLDetection) on TF-IDF URL features for phishing URL classification
- **URL Security Analysis** — Real-time phishing URL detection using security rules
- **Feature Extraction** — Extracts 15+ URL features (length, entropy, subdomains, etc.)
- **Security Rules Engine** — 8 explainable security rules with severity levels
- **Risk Assessment** — Deterministic weighted ML, URL-rule, TLS, and HTTP-header scoring (SAFE / SUSPICIOUS / PHISHING)
- **Explainable Results** — Separate ML probability, phishing evidence, connection security, and top contributing factors
- **Scan History** — Persistent scan history stored in SQLite with search, filtering, and pagination
- **Dashboard** — Real-time statistics and visualizations
- **Responsive Design** — Works on desktop, tablet, and mobile devices
- **Dark Theme** — Cybersecurity-inspired dark navy UI

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React.js, Vite, Bootstrap 5, Bootstrap Icons |
| HTTP Client | Axios |
| Charts | Chart.js, react-chartjs-2 |
| Backend | Python, FastAPI, Uvicorn |
| Database | SQLite + SQLAlchemy |
| ML | scikit-learn Random Forest (SivakumarP/PhishingURLDetection), joblib, scipy, tldextract |

## System Architecture

```
React + Bootstrap
        ↓
Axios
        ↓
FastAPI
        ↓
URL Validation
        ↓
URL Feature Extraction
        ↓
┌──────────────────────┐
│                      │
│ Security Rules       │
│        +             │
│ RandomForest ML Model│
│                      │
└──────────┬───────────┘
           ↓
      Risk Engine
           ↓
    Final Classification
           ↓
        Response
           ↓
      React Result UI
```

## Project Structure

```
phishguard/
├── .gitignore
├── README.md
├── frontend/
│   ├── .env                          # API base URL config
│   ├── .env.example
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx                  # App entry point
│       ├── App.jsx                   # React Router setup
│       ├── index.css                 # Global theme styles
│       ├── dashboard.css             # Dashboard styles
│       ├── scanhistory.css           # Scan History styles
│       ├── about.css                 # About page styles
│       ├── components/
│       │   ├── Navbar.jsx
│       │   ├── Footer.jsx
│       │   ├── Layout.jsx
│       │   ├── BrandLogo.jsx
│       │   ├── UrlScanner.jsx        # URL input + validation
│       │   ├── HeroSection.jsx
│       │   ├── FeaturesSection.jsx
│       │   ├── HowItWorksSection.jsx
│       │   ├── EmptyState.jsx
│       │   ├── DashboardStats.jsx
│       │   ├── RecentScansTable.jsx
│       │   ├── RiskDistributionChart.jsx
│       │   ├── RiskScoreTrendChart.jsx
│       │   ├── ScanHistoryFilters.jsx
│       │   └── ScanHistoryTable.jsx
│       ├── pages/
│       │   ├── HomePage.jsx
│       │   ├── AnalysisResultPage.jsx
│       │   ├── DashboardPage.jsx
│       │   ├── ScanHistoryPage.jsx
│       │   └── AboutPage.jsx
│       ├── services/
│       │   └── api.js                # Centralized API client
│       ├── data/
│       │   ├── siteContent.js
│       │   └── aboutContent.js
│       └── utils/
│           └── historyFilters.js
└── backend/
    ├── .env.example
    ├── main.py                       # FastAPI app setup
    ├── requirements.txt
    ├── phishguard.db                 # SQLite database (auto-created)
    ├── database/
    │   ├── __init__.py
    │   ├── database.py               # SQLAlchemy config
    │   ├── models.py                 # ScanRecord model
    │   └── schemas.py                # Pydantic schemas
    ├── routes/
    │   ├── __init__.py
    │   ├── scanner.py                # POST /analyze
    │   ├── history.py                # GET /history, DELETE /history/{id}
    │   └── dashboard.py              # GET /dashboard
    ├── services/
    │   ├── __init__.py
    │   ├── feature_extractor.py      # URL feature extraction (rules engine)
    │   ├── security_rules.py         # Security rules engine
    │   ├── risk_engine.py            # Risk scoring + classification
    │   └── ml_predictor.py           # Cached ML predictor (SivakumarP RF, legacy ONNX fallback)
    └── ml/
        ├── sivakumar/                # SivakumarP Random Forest artifacts (production)
        │   ├── model.pkl             # RandomForestClassifier (100 trees, gini, depth 32)
        │   ├── dataencoder_url.pkl   # char TF-IDF of full URL (96 features)
        │   ├── dataencoder_dom.pkl   # char TF-IDF of registered domain (57 features)
        │   ├── dataencoder_tld.pkl   # char TF-IDF of public suffix / TLD (32 features)
        │   └── datascaler.pkl        # StandardScaler(digit_cnt, is_https) (2 features)
        └── model.onnx                # Legacy pirocheto ONNX model (rollback only)
```

## Setup

### Prerequisites

- **Node.js** 18+ (for frontend)
- **Python** 3.10+ (for backend)

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at `http://localhost:5173`.

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload --port 8000
```

The backend runs at `http://127.0.0.1:8000`.

### Detection and Risk Model

The production ML model is **SivakumarP/PhishingURLDetection**, a
scikit-learn Random Forest (100 trees, gini, depth 32) trained on a
feature-engineered URL dataset. It does **not** accept a raw URL string alone;
`ml_predictor.py` builds its exact 187-feature input internally:

```
TF-IDF(char, full URL)            # dataencoder_url.pkl   -> 96 features
+ TF-IDF(char, registered domain) # dataencoder_dom.pkl   -> 57 features
+ TF-IDF(char, public suffix)     # dataencoder_tld.pkl   -> 32 features
+ scaled(digit_cnt, is_https)     # datascaler.pkl        ->  2 features
= 187 features
```

Registered domain and public suffix are extracted with `tldextract` (IP hosts
yield `dom` = IP string and an empty TLD, matching the training dataset). The
model loads the five pickle artifacts once per Python process (module-level
cache) and returns the phishing probability as `predict_proba()[1]`
(class 0 = benign, class 1 = phishing). No probability post-processing is
applied.

The legacy `pirocheto/phishing-url-detection` ONNX model is preserved at
`backend/ml/model.onnx` for rollback; set `MODEL_BACKEND=pirocheto` to
restore it. URL features for the explainable rules engine are computed
independently and never substituted for the model's TF-IDF input.

The final risk score is a documented heuristic, not a calibrated probability:

```
final phishing risk = ML phishing probability * 70%   (heuristic weight)
                    + URL phishing-rule risk * 30%    (heuristic weight)
```

TLS connection security and HTTP hardening are separate dimensions and never
enter this phishing-risk formula. Unavailable network checks do not become
phishing evidence. Missing HTTPS remains visible as a transport warning but
does not inflate the URL phishing-rule score. The API returns each phishing
component, weight, and weighted contribution so the final integer is
reproducible, along with separate `connection_security` and `http_security`
objects.

Both ML models are loaded once per Python process from trusted repository
files under `backend/ml/`; there is no uploaded-model endpoint and no model
download on each request. The SivakumarP artifacts total ~29.8 MB; with
scikit-learn/scipy/joblib/tldextract the full deployment bundle is ~247 MB,
which fits Vercel's 500 MB uncompressed Python function limit (verified live,
see `backend/benchmark/vercel_live_report.md`). Cold start is ~1.8 s with
model load cached per warm instance.

## Environment Variables

### Frontend (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Backend API URL |

### Backend (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | (empty) | Comma-separated allowed origins |
| `MODEL_BACKEND` | `sivakumar` | ML backend: `sivakumar` (Random Forest, default) or `pirocheto` (legacy ONNX, rollback) |

## API Endpoints

### Health Check

```
GET /
```

Response:
```json
{
  "status": "ok",
  "service": "PhishGuard API"
}
```

### Analyze URL

```
POST /analyze
```

Request:
```json
{
  "url": "https://example.com"
}
```

Response:
```json
{
  "url": "https://example.com",
  "classification": "SAFE",
  "risk_score": 12,
  "confidence": 82,
  "message": "URL analysis completed. No significant phishing indicators detected.",
  "detected_indicators": [...],
  "summary": "No major phishing indicators were detected...",
  "features": {...},
  "rules": [...],
  "ml_analysis": {...},
  "rule_analysis": {"score": 0, "findings": [...]},
  "connection_security": {"https": true, "tls_available": true, "headers_available": true},
  "risk_breakdown": {...},
  "top_factors": [...],
  "model_info": {...}
}
```

### Get Scan History

```
GET /history?search=&classification=All&risk=All&date=All%20Time&page=1&page_size=10
```

Response:
```json
{
  "records": [...],
  "total": 25,
  "page": 1,
  "page_size": 10,
  "total_pages": 3
}
```

### Retrieve a Scan Record

```
GET /history/{id}
```

Returns the exact stored scan record (the ML model is NOT re-run). The
`detected_indicators` field is a JSON string of the indicators that were
flagged at scan time.

Response:
```json
{
  "id": 1,
  "url": "https://example.com",
  "classification": "SAFE",
  "risk_score": 0,
  "confidence": 1,
  "message": "URL analysis completed. ...",
  "detected_indicators": "[]",
  "summary": "No major phishing indicators were detected. ...",
  "scanned_at": "2026-09-05T11:28:14.718806"
}
```

### Delete Scan Record

```
DELETE /history/{id}
```

### Get Dashboard Statistics

```
GET /dashboard
```

Response:
```json
{
  "total_scans": 1250,
  "safe_count": 820,
  "suspicious_count": 275,
  "phishing_count": 155,
  "average_risk_score": 46.2,
  "recent_scans": [...]
}
```

### Get Dashboard Trends

```
GET /dashboard/trends
```

Returns the real average risk score per calendar day for the last 7 days,
derived from SQLite scan records. Days with no scans are reported as `null`
(rendered as a gap in the chart) — no values are fabricated.

Response:
```json
{
  "labels": ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
  "average_risk_scores": [null, null, null, null, null, null, 54.3],
  "total_scans": 19
}
```

## ML Model Information

**Status**: Active

**Model**: [SivakumarP/PhishingURLDetection](https://huggingface.co/SivakumarP/PhishingURLDetection)

**Inference**: scikit-learn (`predict_proba`)

**Model type**: Random Forest classifier (100 trees, gini, max depth 32)

**Purpose**: Binary classification of URLs as phishing or safe

**Artifacts** (in `backend/ml/sivakumar/`): `model.pkl` + three TF-IDF
vectorizers (`dataencoder_url.pkl`, `dataencoder_dom.pkl`,
`dataencoder_tld.pkl`) + `datascaler.pkl`

**How it works**:
- `ml_predictor.py` preprocesses each URL into the exact 187-feature vector: char TF-IDF of the full URL, the registered domain, and the public suffix, concatenated with scaled digit count and HTTPS flag (see "Detection and Risk Model" above)
- Feature order is fixed; nothing is normalized or re-scaled after the model
- The ML prediction is combined with the security rules engine in a weighted formula:
  - ML component: 70% weight (heuristic) — phishing probability
  - Rule component: 30% weight (heuristic) — normalized rule risk score

**Input/Output** (verified by inspection and live testing):
- Input: preprocessed 187-dim feature vector (built internally from a raw URL string)
- `predict_proba()` shape [n, 2] — column 0 = benign (class 0), column 1 = phishing (class 1)
- `phishing_probability = predict_proba(features)[1]`; the mapping is **not** reversed

**Benchmark results** (internal 210-URL benchmark only — not universal
real-world accuracy): accuracy 85.71%, precision 93.42%, recall 73.96%, F1
0.8256, ROC-AUC 0.9471, FPR 4.39%, FNR 26.04%. Full methodology and
per-URL predictions in `backend/benchmark/`.

**Verified live predictions** (local vs Vercel, bit-identical):
- `learnova-ai-8.vercel.app` → 54.0% phishing
- `www.google.com` → 13.0% phishing
- `example.com` → 30.0% phishing
- `github.com` → 32.0% phishing
- `paypal.com` → 45.0% phishing

**Limitations**:
- The model may not detect all phishing techniques; URL-only analysis cannot verify actual website content
- The ML signal is combined with rule-based analysis and must not be treated as ground truth or a guarantee
- Reported metrics are benchmark-only and should not be claimed as universal real-world accuracy

**Fallback / rollback**: If the SivakumarP artifacts fail to load, the
predictor falls back to rule-based analysis only. Set `MODEL_BACKEND=pirocheto`
to restore the legacy ONNX model (kept at `backend/ml/model.onnx`).

## Database

**Engine**: SQLite (file: `backend/phishguard.db`)

**Table**: `scan_records`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| url | VARCHAR(2048) | Analyzed URL |
| classification | VARCHAR(20) | SAFE / SUSPICIOUS / PHISHING |
| risk_score | INTEGER | 0-100 risk score |
| confidence | INTEGER | 0-100 confidence |
| message | TEXT | Analysis message |
| detected_indicators | TEXT | JSON string of indicators |
| summary | TEXT | Analysis summary |
| scanned_at | DATETIME | Timestamp (UTC) |

The database is auto-created on first startup.

## Security Limitations

- **URL-only analysis**: The backend analyzes URL strings only; it never fetches or visits URLs
- **ML limitations**: The model may not detect all phishing techniques; URL-only analysis cannot verify actual website content
- **Single-user**: SQLite is suitable for development/testing, not production multi-user
- **No authentication**: The API is open; add auth for production use
- **Deterministic scoring**: Risk scores are deterministic but should not be treated as guarantees

## How It Works

1. **User enters a URL** in the scanner form
2. **Frontend validates** the URL format and sends it to the backend
3. **Feature extraction** analyzes 15+ URL characteristics
4. **Parallel analysis**: ML model (SivakumarP Random Forest on TF-IDF features) predicts phishing probability + Security rules evaluate explainable rules
5. **Risk engine** combines ML prediction (70%) and rule results (30%) into a final score and classification
6. **Result stored** in SQLite database
7. **Response returned** with classification, risk score, ML analysis, indicators, and summary
8. **Frontend displays** the result with ML analysis, detected indicators, and visual gauges

## Future Enhancements

- [ ] Add user authentication and API keys
- [ ] Implement URL reputation checking (external APIs)
- [ ] Add batch URL analysis
- [ ] Export scan history to CSV/PDF
- [ ] Real-time threat intelligence feeds
- [ ] Browser extension for live URL checking
- [ ] Rate limiting and abuse prevention
- [ ] Docker containerization
- [ ] Production deployment with PostgreSQL

## Commands to Run

```bash
# Frontend
cd frontend
npm install
npm run dev

# Backend
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## License

Educational project for cybersecurity and machine learning learning.
