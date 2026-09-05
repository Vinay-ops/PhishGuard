// ---------------------------------------------------------------------------
// API service for PhishGuard.
//
// Single source of truth for all backend communication. The backend returns
// snake_case fields; the helper below converts them to camelCase for React.
//
// To run the backend locally (from the backend/ folder):
//     python main.py        # serves http://127.0.0.1:8000
// ---------------------------------------------------------------------------

import axios from 'axios'

// Centralized API base URL: read from .env (VITE_API_BASE_URL) with a
// development fallback so the app works out of the box.
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

/** Shared Axios instance with a default timeout. */
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

// ---------------------------------------------------------------------------
// Normalizers — convert snake_case backend fields to camelCase.
// ---------------------------------------------------------------------------

function normalizeAnalysisResult(data) {
  return {
    url: data.url,
    classification: data.classification,
    riskScore: data.risk_score,
    confidence: data.confidence,
    message: data.message,
    detectedIndicators: data.detected_indicators ?? [],
    rules: data.rules ?? [],
    summary: data.summary ?? '',
    features: data.features ?? {},
    mlAnalysis: data.ml_analysis ?? {
      available: false,
      prediction: null,
      phishing_probability: null,
      safe_probability: null,
      error: null,
    },
  }
}

function normalizeScanRecord(record) {
  return {
    id: record.id,
    url: record.url,
    classification: record.classification,
    tone: record.classification.toLowerCase(),
    riskScore: record.risk_score,
    mlConfidence: record.confidence,
    message: record.message ?? '',
    scannedAt: record.scanned_at ? new Date(record.scanned_at) : new Date(),
  }
}

function normalizeHistoricalRecord(record) {
  let detectedIndicators = []
  const raw = record.detected_indicators
  if (raw) {
    try {
      const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
      if (Array.isArray(parsed)) detectedIndicators = parsed
    } catch {
      detectedIndicators = []
    }
  }
  return {
    url: record.url,
    classification: record.classification,
    riskScore: record.risk_score,
    confidence: record.confidence,
    message: record.message ?? '',
    detectedIndicators,
    summary: record.summary ?? record.message ?? '',
    features: {},
    mlAnalysis: {
      available: false,
      prediction: null,
      phishing_probability: null,
      safe_probability: null,
      error: 'ML details were not stored with this historical record.',
    },
    rules: [],
    scannedAt: record.scanned_at ? new Date(record.scanned_at) : null,
    isHistorical: true,
  }
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/**
 * Analyze a URL for phishing indicators.
 * @param {string} url
 * @returns {Promise<object>} Normalized analysis result.
 */
export async function analyzeUrl(url) {
  const response = await api.post('/analyze', { url })
  return normalizeAnalysisResult(response.data)
}

/**
 * Fetch scan history with optional filters and pagination.
 * @param {object} params - { search, classification, risk, date, page, pageSize }
 * @returns {Promise<object>} Paginated history response.
 */
export async function fetchHistory(params = {}) {
  const response = await api.get('/history', { params })
  const data = response.data
  return {
    records: data.records.map(normalizeScanRecord),
    total: data.total,
    page: data.page,
    pageSize: data.page_size,
    totalPages: data.total_pages,
  }
}

/**
 * Delete a scan record by ID.
 * @param {number} id
 * @returns {Promise<object>}
 */
export async function deleteScanRecord(id) {
  const response = await api.delete(`/history/${id}`)
  return response.data
}

/**
 * Fetch dashboard summary statistics.
 * @returns {Promise<object>}
 */
export async function fetchDashboard() {
  const response = await api.get('/dashboard')
  const data = response.data
  return {
    totalScans: data.total_scans,
    safeCount: data.safe_count,
    suspiciousCount: data.suspicious_count,
    phishingCount: data.phishing_count,
    averageRiskScore: data.average_risk_score,
    recentScans: data.recent_scans.map(normalizeScanRecord),
  }
}

/**
 * Check if the backend is reachable.
 * @returns {Promise<boolean>}
 */
export async function checkApiHealth() {
  try {
    await api.get('/')
    return true
  } catch {
    return false
  }
}

/**
 * Fetch daily trend data for the dashboard chart.
 * @returns {Promise<object>} { labels, averageRiskScores, totalScans }
 */
export async function fetchDashboardTrends() {
  const response = await api.get('/dashboard/trends')
  const data = response.data
  return {
    labels: data.labels,
    averageRiskScores: data.average_risk_scores,
    totalScans: data.total_scans,
  }
}

/**
 * Fetch a single stored scan record by ID.
 * Returns the originally persisted result (no re-analysis).
 * @param {number|string} id
 * @returns {Promise<object>} Normalized historical result object.
 */
export async function fetchScanRecord(id) {
  const response = await api.get(`/history/${id}`)
  return normalizeHistoricalRecord(response.data)
}

export { API_BASE_URL }
