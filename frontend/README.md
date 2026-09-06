# PhishGuard – Frontend

Phishing URL detection & security analyzer. This is the React + Vite
frontend with five pages — Home, URL Security Analysis, Security
Dashboard, Scan History and About — backed by the FastAPI + SQLite backend.

## Stack

- React 19 + Vite (JavaScript)
- Bootstrap 5 (dark navy theme via `data-bs-theme="dark"`)
- Bootstrap Icons
- Chart.js + react-chartjs-2 (dashboard charts, animations disabled)
- Axios (wired to the FastAPI backend)

## Getting started

```bash
npm install
npm run dev      # start the dev server
npm run lint     # run ESLint
npm run build    # production build
```

## Project structure

```
src/
├── main.jsx                 # entry point (Bootstrap CSS/JS + theme imported here)
├── App.jsx                  # routes: Home, /analyze, /dashboard, /history
├── index.css                # PhishGuard theme + custom component styles
├── dashboard.css            # dashboard-specific styles
├── scanhistory.css          # scan-history-specific styles
├── about.css                # about-page-specific styles
├── pages/
│   ├── HomePage.jsx         # landing page
│   ├── AnalysisResultPage.jsx # URL security report (backend-driven)
│   ├── DashboardPage.jsx    # security dashboard (backend-driven)
│   ├── ScanHistoryPage.jsx  # scan history (client-side filters + pagination)
│   └── AboutPage.jsx        # about / how-it-works / architecture
├── components/
│   ├── Layout.jsx           # shared navbar + <main> + footer frame
│   ├── Navbar.jsx
│   ├── BrandLogo.jsx        # logo used by Navbar and Footer
│   ├── HeroSection.jsx      # headline + URL analysis form (navigates to /analyze)
│   ├── FeaturesSection.jsx  # 3 feature cards
│   ├── HowItWorksSection.jsx# 3-step process
│   ├── Footer.jsx
│   ├── DashboardStats.jsx   # summary statistic cards
│   ├── RiskDistributionChart.jsx # Safe/Suspicious/Phishing doughnut
│   ├── RiskScoreTrendChart.jsx   # 7-day risk-score line chart
│   ├── RecentScansTable.jsx # recent URL scans table
│   ├── ScanHistoryFilters.jsx # search + classification/risk/date filters
│   ├── ScanHistoryTable.jsx # scan history rows + pagination
│   └── EmptyState.jsx       # reusable empty-state block
├── data/
│   ├── siteContent.js       # static copy (nav, features, steps, …)
│   └── aboutContent.js      # static about-page copy
├── utils/
│   └── historyFilters.js    # date formatting + scan filtering helpers
└── services/
    └── api.js               # axios client — communicates with the FastAPI backend
```

## Backend connection

The URL scanner (`src/components/UrlScanner.jsx`) POSTs the entered URL to
`/analyze` through `src/services/api.js` (Axios). The Result page renders
the normalized backend response directly. It also supports a historical
view: when opened with `?id=<scanId>` (e.g. from the Scan History "View"
action) it loads the stored record via `GET /history/{id}` instead of
re-running the analysis. Override the backend URL with the
`VITE_API_BASE_URL` environment variable.

### Running the FastAPI backend

```bash
cd backend
python -m venv venv          # one-time setup (if not present)
./venv/Scripts/pip install -r requirements.txt   # Windows
# ./venv/bin/pip install -r requirements.txt     # macOS/Linux
./venv/Scripts/python main.py                    # starts http://127.0.0.1:8000
```

CORS allows `http://localhost:5173` and `http://127.0.0.1:5173`. The
`/analyze` endpoint is structured so the ML model (SivakumarP Random
Forest; see the root README) and the
SQLite database can be swapped without changing the API contract.
