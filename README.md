# PhishGuard – Phishing URL Detection & Security Analyzer

A full-stack web application that analyzes URLs for phishing indicators using a combination of machine learning (ONNX) and security rules. Built with React.js, Bootstrap 5, FastAPI, and SQLite.

## Features

- **ML-Based Detection** — ONNX model from pirocheto/phishing-url-detection for phishing URL classification
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
| ML | ONNX Runtime, pirocheto/phishing-url-detection |

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
│ ONNX ML Model        │
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
    │   ├── feature_extractor.py      # URL feature extraction
    │   ├── security_rules.py         # Security rules engine
    │   ├── risk_engine.py            # Risk scoring + classification
    │   └── ml_predictor.py           # Cached ONNX model interface
    └── ml/
        └── model.onnx                # ONNX model (pirocheto/phishing-url-detection)
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

PhishGuard keeps two analysis layers separate. The shipped
`pirocheto/phishing-url-detection` ONNX artifact accepts a raw URL string and
returns a class label plus `[safe_probability, phishing_probability]`. URL
features are sent only to the explainable rules engine; they are not passed to
the ML model.

The final risk score is a documented heuristic, not a calibrated probability:

```
final risk = ML probability * 45%
           + URL phishing-rule risk * 25%
           + TLS connection risk * 15%
           + HTTP header risk * 15%
```

TLS and header risk are the inverse of their respective security scores.
Unavailable network checks contribute zero rather than being treated as
phishing evidence. Missing HTTPS remains visible as a transport warning but
does not inflate the URL phishing-rule score. The API returns each component,
weight, and weighted contribution so the final integer is reproducible.

The model is loaded once per Python process from the trusted repository file
`backend/ml/model.onnx`; there is no uploaded-model endpoint and no model
download on each request. The current artifact is approximately 23.5 MB, so
Vercel's configured 50 MB Python Lambda limit remains relevant together with
ONNX Runtime cold-start and package-size constraints.

## Environment Variables

### Frontend (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Backend API URL |

### Backend (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | (empty) | Comma-separated allowed origins |

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

**Model**: [pirocheto/phishing-url-detection](https://huggingface.co/pirocheto/phishing-url-detection)

**Inference**: ONNX Runtime

**Model type**: LinearSVM (exported to ONNX format)

**Purpose**: Binary classification of URLs as phishing or safe

**How it works**:
- The model accepts raw URL strings directly (no manual preprocessing required)
- It outputs a phishing probability and safe probability for each URL
- The ML prediction is combined with the security rules engine in a weighted formula:
  - ML component: 70% weight (phishing probability)
  - Rule component: 30% weight (normalized rule risk score)

**Model performance** (from HuggingFace):
- ROC AUC: 0.987
- Accuracy: 94.9%
- F1 Score: 94.9%

**Input/Output** (verified by inspection):
- Input: URL strings (tensor(string), shape [None])
- Output 0: Class labels (tensor(int64)) — 0 = SAFE, 1 = PHISHING
- Output 1: Probabilities (tensor(float), shape [None, 2]) — [safe_prob, phishing_prob]

**Limitations**:
- The model may not detect all phishing techniques
- URL-only analysis cannot verify actual website content
- Risk scores are deterministic but should not be treated as guarantees

**Fallback**: If the ONNX model is unavailable, the system falls back to rule-based analysis only.

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
4. **Parallel analysis**: ML model (ONNX) predicts phishing probability + Security rules evaluate 8 explainable rules
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
