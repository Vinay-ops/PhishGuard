import { useState, useEffect } from 'react'
import { Link, useLocation, useSearchParams, useNavigate } from 'react-router-dom'
import { analyzeUrl, fetchScanRecord, API_BASE_URL } from '../services/api.js'
import { formatScanDateTime } from '../utils/historyFilters.js'

// Map a backend classification to the display tone.
const CLASS_TONES = { SAFE: 'success', SUSPICIOUS: 'warning', PHISHING: 'danger' }

// Map severity to Bootstrap tone classes.
const SEVERITY_TONE = { high: 'danger', medium: 'warning', low: 'info' }

// Feature display labels (user-friendly names for each feature key).
const FEATURE_LABELS = {
  url_length: 'URL Length',
  hostname_length: 'Hostname Length',
  path_length: 'Path Length',
  query_length: 'Query Length',
  fragment_length: 'Fragment Length',
  number_of_dots: 'Dots',
  number_of_hyphens: 'Hyphens',
  number_of_underscores: 'Underscores',
  number_of_digits: 'Digits',
  number_of_special_characters: 'Special Characters',
  number_of_subdomains: 'Subdomains',
  has_at_symbol: 'Has @ Symbol',
  has_ip_address: 'Uses IP Address',
  uses_https: 'Uses HTTPS',
  suspicious_keyword_count: 'Suspicious Keywords',
  url_entropy: 'URL Entropy',
}

// Keys to skip in the features display (internal/not useful to show).
const FEATURE_SKIP = new Set(['hostname', 'path', 'query_present'])

const RISK_COMPONENTS = [
  ['ml', 'Machine learning'],
  ['url_rules', 'URL rules'],
]

const HEADER_LABELS = {
  'Strict-Transport-Security': 'Strict-Transport-Security',
  'Content-Security-Policy': 'Content-Security-Policy',
  'X-Frame-Options': 'X-Frame-Options',
  'X-Content-Type-Options': 'X-Content-Type-Options',
  'Referrer-Policy': 'Referrer-Policy',
  'Permissions-Policy': 'Permissions-Policy',
}

function AnalysisResultPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const liveResult = location.state?.analysisResult
  const paramUrl = searchParams.get('url')?.trim()
  const paramId = searchParams.get('id')

  const [result, setResult] = useState(liveResult || null)
  const [loading, setLoading] = useState(() => !liveResult && Boolean(paramUrl || paramId))
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)
  const [featuresOpen, setFeaturesOpen] = useState(false)
  const [whyOpen, setWhyOpen] = useState(true)

  // Resolve the page content:
  //  1. A live result passed via navigation state (fresh analysis).
  //  2. A stored record id (?id=) -> fetch the persisted result, no re-analysis.
  //  3. A url (?url=) -> re-analyze (refresh/reload case).
  useEffect(() => {
    if (result) return

    // Historical record: load the stored result without re-running analysis.
    if (paramId) {
      let cancelled = false

      fetchScanRecord(paramId)
        .then((data) => {
          if (!cancelled) setResult(data)
        })
        .catch(() => {
          if (!cancelled) {
            setError('Could not load the stored scan result.')
          }
        })
        .finally(() => {
          if (!cancelled) setLoading(false)
        })

      return () => { cancelled = true }
    }

    if (!paramUrl) {
      navigate('/', { replace: true })
      return
    }

    let cancelled = false

    analyzeUrl(paramUrl)
      .then((data) => {
        if (!cancelled) setResult(data)
      })
      .catch(() => {
        if (!cancelled) {
          setError(
            'Could not reach the analysis service. ' +
            'Is the FastAPI backend running at ' + API_BASE_URL + '?'
          )
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => { cancelled = true }
  }, [paramId, paramUrl, result, navigate])

  // --- Loading state ---
  if (loading) {
    return (
      <section className="result-header">
        <div className="container text-center py-5">
          <div className="spinner-border text-primary mb-3" role="status">
            <span className="visually-hidden">Loading…</span>
          </div>
          <h2 className="h4 fw-semibold mb-2">
            {paramId ? 'Loading Scan Record' : 'Analyzing URL'}
          </h2>
          <p className="text-secondary mb-0">
            {paramId
              ? 'Retrieving the stored analysis result…'
              : `Running security analysis on ${paramUrl}…`}
          </p>
        </div>
      </section>
    )
  }

  // --- Error state ---
  if (error) {
    return (
      <section className="result-header">
        <div className="container text-center py-5">
          <div className="mb-3">
            <i className="bi bi-exclamation-octagon-fill text-danger" style={{ fontSize: '3rem' }} aria-hidden="true"></i>
          </div>
          <h2 className="h4 fw-semibold mb-2">Analysis Failed</h2>
          <p className="text-secondary mb-4">{error}</p>
          <div className="d-flex flex-wrap justify-content-center gap-3">
            <Link to="/" className="btn btn-brand rounded-pill px-4">
              <i className="bi bi-arrow-left me-2" aria-hidden="true"></i>
              Back to Home
            </Link>
            <Link to="/history" className="btn btn-ghost rounded-pill px-4">
              <i className="bi bi-clock-history me-2" aria-hidden="true"></i>
              View History
            </Link>
          </div>
        </div>
      </section>
    )
  }

  // --- No result ---
  if (!result) {
    return (
      <section className="result-header">
        <div className="container text-center py-5">
          <p className="text-secondary">No analysis result available.</p>
          <Link to="/" className="btn btn-brand rounded-pill px-4">Go to Home</Link>
        </div>
      </section>
    )
  }

  // --- Render result ---
  const classification = result.classification
  const tone = CLASS_TONES[classification] || 'danger'
  const scannedUrl = result.url || paramUrl || ''
  const riskScore = result.riskScore ?? 0
  const mlPct = result.mlPhishingProbabilityPct ?? result.confidence ?? 0
  const modelRuleStatus = result.modelRuleStatus ?? result.phishingAnalysis?.model_rule_status ?? null
  const indicators = result.detectedIndicators ?? []
  const rules = result.rules ?? []
  const features = result.features ?? {}
  const summary = result.summary || result.message || ''
  const mlAnalysis = result.mlAnalysis ?? {}
  const tlsAnalysis = result.tlsAnalysis ?? {}
  const headerAnalysis = result.headerAnalysis ?? {}
  const riskBreakdown = result.riskBreakdown ?? {}
  const topFactors = result.topFactors ?? []
  const whyFlagged = result.whyFlagged ?? null
  const modelInfo = result.modelInfo ?? {}
  const phishingAnalysis = result.phishingAnalysis ?? {}
  const httpSecurity = result.httpSecurity ?? {}

  // Determine if this is a model-rule disagreement display.
  const isDisagreement = modelRuleStatus === 'MODEL-RULE DISAGREEMENT'
  const displayClassification = isDisagreement
    ? `${classification} — MODEL WARNING`
    : classification

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(scannedUrl)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      // Clipboard unavailable
    }
  }

  // Determine risk bar color class based on score range.
  const riskBarClass = riskScore >= 70
    ? 'bg-danger'
    : riskScore >= 30
      ? 'bg-warning'
      : 'bg-success'

  return (
    <>
      {/* ---- Page header ------------------------------------------------- */}
      <section className="result-header">
        <div className="container">
          <nav className="result-breadcrumb mb-3" aria-label="Breadcrumb">
            <Link to="/">Home</Link>
            <span aria-hidden="true">/</span>
            <span>URL Security Analysis</span>
          </nav>
          <h1 className="section-title text-center mb-2">URL Security Analysis</h1>
          <p className="section-subtitle text-center mx-auto">
            Detailed security analysis of the submitted URL.
          </p>

          {result.scannedAt && (
            <p className="text-center text-secondary small mb-0 mt-2">
              <i className="bi bi-clock-history me-1" aria-hidden="true"></i>
              Originally scanned on{' '}
              <time dateTime={result.scannedAt.toISOString()}>
                {formatScanDateTime(result.scannedAt)}
              </time>
              {' '}
              <span aria-hidden="true">·</span>
              <span className="ms-1 fst-italic">
                historical record — no new analysis was run
              </span>
            </p>
          )}

          {/* Scanned URL card */}
          <div className="d-flex justify-content-center mt-4">
            <div className="scanned-url-card">
              <i className="bi bi-link-45deg scanned-url-icon" aria-hidden="true"></i>
              <span className="scanned-url-text" title={scannedUrl}>
                {scannedUrl}
              </span>
              <button
                type="button"
                className="btn-copy"
                onClick={handleCopy}
                aria-label="Copy scanned URL"
              >
                <i className={`bi ${copied ? 'bi-check2' : 'bi-clipboard'}`} aria-hidden="true"></i>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Main verdict card ------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="verdict-card card p-4 p-md-5" data-tone={tone}>
            <div className="row g-4 g-lg-5 align-items-center">
              {/* Circular risk gauge */}
              <div className="col-12 col-md-5 d-flex flex-column align-items-center text-center">
                <div
                  className="gauge"
                  role="progressbar"
                  aria-valuenow={riskScore}
                  aria-valuemin="0"
                  aria-valuemax="100"
                  aria-label="Risk score"
                >
                  <div className="gauge-fill" style={{ '--score': riskScore }}>
                    <div className="gauge-core">
                      <span className="gauge-value">{riskScore}%</span>
                      <span className="gauge-label">Risk Score</span>
                    </div>
                  </div>
                </div>
                <span className="gauge-caption mt-3">
                  {riskScore >= 70
                    ? 'High-risk URL detected'
                    : riskScore >= 30
                      ? 'Medium-risk URL — caution advised'
                      : 'Low-risk URL — looks safe'}
                </span>
              </div>

              {/* Status + metrics */}
              <div className="col-12 col-md-7">
                <span className="kv-label">Security Status</span>
                <div className="verdict-pill d-inline-flex align-items-center gap-2 mt-2">
                  <i className="bi bi-shield-check" aria-hidden="true"></i>
                  <span className="text-uppercase">{displayClassification}</span>
                </div>

                <div className="row g-4 mt-1">
                  <div className="col-12 col-sm-6">
                    <div className="d-flex justify-content-between align-items-baseline">
                      <span className="kv-label">Risk Score</span>
                      <span className={`metric-value tone-${tone}`}>
                        {riskScore}/100
                      </span>
                    </div>
                    <div className="progress pg-progress mt-2" role="presentation">
                      <div
                        className={`progress-bar ${riskBarClass}`}
                        style={{ width: `${riskScore}%` }}
                      ></div>
                    </div>
                  </div>
                  <div className="col-12 col-sm-6">
                    <div className="d-flex justify-content-between align-items-baseline">
                      <span className="kv-label">ML Phishing Probability</span>
                      <span className="metric-value text-primary">
                        {mlPct}%
                      </span>
                    </div>
                    <div className="progress pg-progress mt-2" role="presentation">
                      <div
                        className="progress-bar bar-ml"
                        style={{ width: `${mlPct}%` }}
                      ></div>
                    </div>
                  </div>
                </div>

                <p className="verdict-note mt-4 mb-0">
                  <i className="bi bi-shield-exclamation me-2" aria-hidden="true"></i>
                  {isDisagreement
                    ? 'The ML model assigns a high phishing probability, but no phishing-specific URL indicators were detected. This model-rule disagreement should be independently verified.'
                    : tone === 'success'
                      ? 'No obvious threats detected — always verify unfamiliar sites before sharing information.'
                      : tone === 'warning'
                        ? 'Exercise caution: treat this URL as unverified until you confirm its source.'
                        : 'Do not enter personal information or credentials on this URL.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Machine Learning Analysis ----------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center text-center mb-4">
            <div className="col-12 col-lg-8">
              <span className="section-eyebrow">ML Analysis</span>
              <h2 className="result-section-title mt-2">Machine Learning Analysis</h2>
              <p className="result-section-sub mx-auto">
                {mlAnalysis.available
                  ? 'Model prediction — an estimated phishing probability, not independent confirmation.'
                  : 'ML model is currently unavailable. Rule-based analysis is still active.'}
              </p>
            </div>
          </div>

          <div className="row g-4 justify-content-center">
            <div className="col-12 col-lg-8">
              <div className="card pg-card p-4">
                {mlAnalysis.available ? (
                  <ul className="list-unstyled mb-0">
                    {/* Model Status */}
                    <li className="rule-row">
                      <i className="bi bi-check-circle-fill tone-success" aria-hidden="true"></i>
                      <span className="flex-grow-1">
                        <strong>Model Status</strong>
                        <br />
                        <small className="text-secondary">ONNX model loaded and ready</small>
                      </span>
                      <span className="status-badge tone-success">AVAILABLE</span>
                    </li>

                    {/* Prediction */}
                    <li className="rule-row">
                      <i
                        className={`bi ${
                          mlAnalysis.prediction === 'PHISHING'
                            ? 'bi-exclamation-octagon-fill tone-danger'
                            : 'bi-check-circle-fill tone-success'
                        }`}
                        aria-hidden="true"
                      ></i>
                      <span className="flex-grow-1">
                        <strong>Prediction</strong>
                        <br />
                        <small className="text-secondary">
                          {mlAnalysis.prediction === 'PHISHING'
                            ? 'Model prediction: estimated phishing'
                            : 'Model prediction: estimated safe'}
                        </small>
                      </span>
                      <span
                        className={`status-badge ${
                          mlAnalysis.prediction === 'PHISHING' ? 'tone-danger' : 'tone-success'
                        }`}
                      >
                        {mlAnalysis.prediction}
                      </span>
                    </li>

                    {/* Phishing Probability */}
                    <li className="rule-row">
                      <i
                        className={`bi ${
                          (mlAnalysis.phishing_probability ?? 0) > 0.5
                            ? 'bi-exclamation-triangle-fill tone-danger'
                            : 'bi-info-circle-fill tone-info'
                        }`}
                        aria-hidden="true"
                      ></i>
                      <span className="flex-grow-1">
                        <strong>Phishing Probability</strong>
                        <br />
                        <small className="text-secondary">
                          Estimated probability that this URL is phishing (model prediction)
                        </small>
                      </span>
                      <span
                        className={`metric-value ${
                          (mlAnalysis.phishing_probability ?? 0) > 0.5
                            ? 'tone-danger'
                            : 'text-primary'
                        }`}
                      >
                        {((mlAnalysis.phishing_probability ?? 0) * 100).toFixed(1)}%
                      </span>
                    </li>

                    {/* Safe Probability */}
                    <li className="rule-row">
                      <i
                        className={`bi ${
                          (mlAnalysis.safe_probability ?? 0) > 0.5
                            ? 'bi-check-circle-fill tone-success'
                            : 'bi-info-circle-fill tone-info'
                        }`}
                        aria-hidden="true"
                      ></i>
                      <span className="flex-grow-1">
                        <strong>Safe Probability</strong>
                        <br />
                        <small className="text-secondary">
                          Estimated probability that this URL is safe (model prediction)
                        </small>
                      </span>
                      <span
                        className={`metric-value ${
                          (mlAnalysis.safe_probability ?? 0) > 0.5
                            ? 'tone-success'
                            : 'text-primary'
                        }`}
                      >
                        {((mlAnalysis.safe_probability ?? 0) * 100).toFixed(1)}%
                      </span>
                    </li>
                  </ul>
                ) : (
                  <div className="text-center py-3">
                    <i className="bi bi-info-circle text-secondary" style={{ fontSize: '2rem' }} aria-hidden="true"></i>
                    <p className="text-secondary mt-2 mb-0">
                      Machine learning analysis is currently unavailable.
                      Rule-based security analysis is still active.
                    </p>
                    {mlAnalysis.error && (
                      <small className="text-muted d-block mt-2">{mlAnalysis.error}</small>
                    )}
                  </div>
                )}
                {modelInfo.model_name && (
                  <div className="model-info mt-4 pt-3">
                    <span className="kv-label d-block mb-2">Detection Engine</span>
                    <small className="text-secondary d-block">{modelInfo.model_name}</small>
                    <small className="text-secondary d-block">Input: {modelInfo.input || 'Raw URL string'}</small>
                    <small className="text-secondary d-block">Output: {modelInfo.output || 'Model prediction and probabilities'}</small>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Explainability --------------------------------------------- */}
      {(topFactors.length > 0 || whyFlagged) && (
        <section className="pb-5">
          <div className="container">
            <div className="row justify-content-center text-center mb-4">
              <div className="col-12 col-lg-8">
              <span className="section-eyebrow">Explainability</span>
              <h2 className="result-section-title mt-2">Why Was This Flagged?</h2>
              <p className="result-section-sub mx-auto">
                Evidence-based analysis separated into phishing evidence, model warnings, and security hardening findings.
              </p>
              </div>
            </div>
            <div className="row justify-content-center">
              <div className="col-12 col-lg-8">
                <div className="card pg-card p-4">
                  {/* --- Model / Rule Status Header --- */}
                  {modelRuleStatus && (
                    <div className="d-flex align-items-center gap-2 mb-3 pb-3 border-bottom">
                      <i className="bi bi-diagram-3-fill tone-info" aria-hidden="true"></i>
                      <span>
                        <strong>Assessment:</strong>{' '}
                        <span className={isDisagreement ? 'tone-danger' : 'tone-success'}>
                          {modelRuleStatus}
                        </span>
                      </span>
                    </div>
                  )}

                  {/* --- DIRECT PHISHING EVIDENCE --- */}
                  <div className="mb-3">
                    <h3 className="h6 fw-semibold mb-2">
                      <i className="bi bi-exclamation-octagon-fill tone-danger me-2" aria-hidden="true"></i>
                      Direct Phishing Evidence
                    </h3>
                    {whyFlagged?.phishing_evidence?.length > 0 ? (
                      <ul className="list-unstyled mb-0">
                        {whyFlagged.phishing_evidence.map((ev) => (
                          <li className="rule-row" key={ev.rule}>
                            <span className={`status-badge tone-${SEVERITY_TONE[ev.severity] || 'secondary'}`}>
                              {ev.severity?.toUpperCase()}
                            </span>
                            <span className="flex-grow-1">
                              <strong>{ev.rule}</strong>
                              <br />
                              <small className="text-secondary">{ev.description}</small>
                            </span>
                            {ev.value && <small className="text-secondary">{ev.value}</small>}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-secondary mb-0">
                        <i className="bi bi-check-circle-fill tone-success me-1" aria-hidden="true"></i>
                        0 phishing-specific indicators detected.
                      </p>
                    )}
                  </div>

                  {/* --- MODEL WARNING --- */}
                  {whyFlagged?.model_warning && (
                    <div className="mb-3">
                      <h3 className="h6 fw-semibold mb-2">
                        <i className="bi bi-exclamation-triangle-fill tone-warning me-2" aria-hidden="true"></i>
                        Model Warning
                      </h3>
                      <div className="d-flex align-items-start gap-2">
                        <span className="status-badge tone-danger">ML MODEL</span>
                        <span className="flex-grow-1">
                          <small className="text-secondary">
                            {whyFlagged.model_warning.message}
                          </small>
                        </span>
                      </div>
                    </div>
                  )}

                  {/* --- SECURITY HARDENING FINDINGS --- */}
                  {whyFlagged?.hardening_findings?.length > 0 && (
                    <div className="mb-0">
                      <h3 className="h6 fw-semibold mb-2">
                        <i className="bi bi-info-circle-fill tone-info me-2" aria-hidden="true"></i>
                        Security Hardening Findings
                      </h3>
                      <ul className="list-unstyled mb-0">
                        {whyFlagged.hardening_findings.map((finding) => (
                          <li className="rule-row" key={finding.category}>
                            <span className={`status-badge ${finding.status === 'VERIFIED' ? 'tone-success' : finding.status === 'PRESENT' ? 'tone-success' : 'tone-warning'}`}>
                              {finding.status}
                            </span>
                            <span className="flex-grow-1">
                              <strong>{finding.category}</strong>
                              <br />
                              <small className="text-secondary">{finding.message}</small>
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <small className="text-secondary d-block mt-3">
                    TLS and HTTP hardening describe connection and transport security. They do not prove that a site is legitimate or illegitimate.
                  </small>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ---- Security risk breakdown ------------------------------------ */}
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center text-center mb-4">
            <div className="col-12 col-lg-8">
              <span className="section-eyebrow">Heuristic Weights</span>
              <h2 className="result-section-title mt-2">Security Risk Breakdown</h2>
              <p className="result-section-sub mx-auto">
                Final phishing risk uses heuristic weights: ML probability (70%) + URL rule risk (30%). These weights are not statistically validated. TLS and HTTP hardening are reported as separate security dimensions.
              </p>
            </div>
          </div>
          <div className="row g-3 justify-content-center">
            {RISK_COMPONENTS.map(([key, label]) => {
              const component = riskBreakdown[key] ?? {}
              const score = component.score ?? 0
              return (
                <div className="col-12 col-sm-6 col-lg-3" key={key}>
                  <div className="card pg-card p-3 risk-component-card h-100">
                    <div className="d-flex justify-content-between align-items-start gap-2">
                      <span className="kv-label">{label}</span>
                      <span className="risk-weight">{component.weight ?? 0}%</span>
                    </div>
                    <strong className="risk-component-score mt-2">{score}/100</strong>
                    <div className="progress pg-progress mt-2" role="presentation">
                      <div className="progress-bar bg-warning" style={{ width: `${score}%` }}></div>
                    </div>
                    {!component.available && <small className="text-secondary mt-2">Unavailable</small>}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ---- TLS and HTTP security -------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row g-4 justify-content-center">
            <div className="col-12 col-lg-6">
              <div className="card pg-card p-4 h-100">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <div>
                    <span className="section-eyebrow">Transport</span>
                    <h2 className="result-section-title mt-2 mb-0">Connection Security</h2>
                  </div>
                  <span className={`status-badge ${tlsAnalysis.available ? 'tone-success' : 'tone-warning'}`}>
                    {tlsAnalysis.available ? `${tlsAnalysis.score}/100` : 'UNAVAILABLE'}
                  </span>
                </div>
                {tlsAnalysis.certificate ? (
                  <div className="security-detail-grid">
                    <span>Protocol</span><strong>{tlsAnalysis.version || 'Unknown'}</strong>
                    <span>Issuer</span><strong>{tlsAnalysis.certificate.issuer}</strong>
                    <span>Subject</span><strong>{tlsAnalysis.certificate.subject}</strong>
                    <span>Valid until</span><strong>{tlsAnalysis.certificate.not_after || 'Unknown'}</strong>
                  </div>
                ) : (
                  <p className="text-secondary mb-0">{tlsAnalysis.error || 'No certificate details were returned.'}</p>
                )}
                <small className="text-secondary d-block mt-3">
                  Phishing risk contribution: 0/100. TLS describes connection security, not website legitimacy.
                </small>
              </div>
            </div>
            <div className="col-12 col-lg-6">
              <div className="card pg-card p-4 h-100">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <div>
                    <span className="section-eyebrow">Application</span>
                    <h2 className="result-section-title mt-2 mb-0">HTTP Security Hardening</h2>
                  </div>
                  <span className={`status-badge ${headerAnalysis.available ? 'tone-success' : 'tone-warning'}`}>
                    {headerAnalysis.available ? `${headerAnalysis.score}/100` : 'UNAVAILABLE'}
                  </span>
                </div>
                <ul className="list-unstyled mb-0 security-header-list">
                  {Object.entries(HEADER_LABELS).map(([key, label]) => {
                    const present = Boolean(headerAnalysis.headers?.[key])
                    return (
                      <li key={key}>
                        <span>{label}</span>
                        <span className={`status-badge ${present ? 'tone-success' : 'tone-danger'}`}>
                          {present ? 'PRESENT' : 'MISSING'}
                        </span>
                      </li>
                    )
                  })}
                </ul>
                {!headerAnalysis.available && <small className="text-secondary d-block mt-3">{headerAnalysis.error || 'Header request was unavailable.'}</small>}
                {headerAnalysis.available && (
                  <>
                    <small className="text-secondary d-block mt-3">
                      Phishing risk contribution: 0/100. Missing headers indicate weaker HTTP hardening, not phishing evidence.
                    </small>
                    {httpSecurity.missing_headers?.length > 0 && (
                      <small className="text-secondary d-block mt-2">
                        Missing: {httpSecurity.missing_headers.join(', ')}
                      </small>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Detected Indicators ----------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center text-center mb-4">
            <div className="col-12 col-lg-8">
              <span className="section-eyebrow">Security Analysis</span>
              <h2 className="result-section-title mt-2">Detected Indicators</h2>
              <p className="result-section-sub mx-auto">
                {indicators.length > 0
                  ? `${indicators.length} phishing-specific indicator(s) flagged by the security rules engine.`
                  : '0 phishing-specific indicators detected.'}
              </p>
            </div>
          </div>

          {indicators.length > 0 ? (
            <div className="row g-4 justify-content-center">
              <div className="col-12 col-lg-8">
                <div className="card pg-card p-4">
                  <ul className="list-unstyled mb-0">
                    {indicators.map((ind) => {
                      const sevTone = SEVERITY_TONE[ind.severity] || 'secondary'
                      return (
                        <li
                          className="rule-row"
                          key={ind.rule}
                        >
                          <span className={`status-badge tone-${sevTone}`}>
                            {ind.severity.toUpperCase()}
                          </span>
                          <span className="flex-grow-1">
                            <strong>{ind.rule}</strong>
                            <br />
                            <small className="text-secondary">{ind.description}</small>
                          </span>
                          {ind.value && (
                            <small className="text-secondary">{ind.value}</small>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                </div>
              </div>
            </div>
          ) : (
            <div className="row justify-content-center">
              <div className="col-12 col-lg-8 text-center">
                <div className="card pg-card p-4">
                  <i className="bi bi-check-circle-fill text-success" style={{ fontSize: '2rem' }} aria-hidden="true"></i>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ---- Security Rules Analysis ------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center text-center mb-4">
            <div className="col-12 col-lg-8">
              <span className="section-eyebrow">Rule Analysis</span>
              <h2 className="result-section-title mt-2">Rules Checked</h2>
                <p className="result-section-sub mx-auto">
                Each rule was evaluated independently against the URL. Only phishing-specific URL findings affect phishing risk; transport warnings remain separate.
              </p>
            </div>
          </div>
          <div className="row g-4 justify-content-center">
            <div className="col-12 col-lg-8">
              <div className="card pg-card p-4">
                <ul className="list-unstyled mb-0">
                  {rules.length > 0 ? (
                    rules.map((rule) => {
                      const rTone = rule.status === 'WARNING' ? 'warning' : rule.detected ? 'danger' : 'success'
                      const rIcon = rule.detected
                        ? 'bi-exclamation-octagon-fill'
                        : 'bi-check-circle-fill'
                      return (
                        <li className="rule-row" key={rule.rule}>
                          <i className={`bi ${rIcon} tone-${rTone}`} aria-hidden="true"></i>
                          <span className="flex-grow-1">{rule.rule}</span>
                          <span className={`status-badge tone-${rTone}`} title={rule.description}>
                            {rule.status || (rule.detected ? rule.severity.toUpperCase() : 'PASS')}
                          </span>
                        </li>
                      )
                    })
                  ) : (
                    <li className="rule-row">
                      <i className="bi bi-info-circle-fill tone-secondary" aria-hidden="true"></i>
                      <span className="flex-grow-1">Security rules evaluation unavailable</span>
                    </li>
                  )}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Technical URL Features (collapsible) ------------------------- */}
      {features && Object.keys(features).length > 0 && (
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center">
            <div className="col-12 col-lg-8">
              <button
                type="button"
                className="btn btn-ghost w-100 d-flex align-items-center justify-content-between"
                onClick={() => setFeaturesOpen(!featuresOpen)}
                aria-expanded={featuresOpen}
              >
                <span>
                  <i className="bi bi-code-slash me-2" aria-hidden="true"></i>
                  Technical URL Features
                </span>
                <i className={`bi bi-chevron-${featuresOpen ? 'up' : 'down'}`} aria-hidden="true"></i>
              </button>
              {featuresOpen && (
                <div className="card pg-card p-4 mt-2">
                  <div className="row g-3">
                    {Object.entries(features)
                      .filter(([key]) => !FEATURE_SKIP.has(key))
                      .map(([key, value]) => (
                        <div className="col-6 col-md-4 col-lg-3" key={key}>
                          <span className="kv-label d-block mb-1">
                            {FEATURE_LABELS[key] || key}
                          </span>
                          <span className="indicator-value">
                            {typeof value === 'boolean'
                              ? value ? 'Yes' : 'No'
                              : String(value)}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>
      )}

      {/* ---- Summary ------------------------------------------------------ */}
      {summary && (
        <section className="pb-5">
          <div className="container">
            <div className="row justify-content-center text-center mb-4">
              <div className="col-12 col-lg-8">
                <span className="section-eyebrow">Conclusion</span>
                <h2 className="result-section-title mt-2">Analysis Summary</h2>
              </div>
            </div>
            <div className="row justify-content-center">
              <div className="col-12 col-lg-9">
                <div className="summary-card p-4 p-lg-5" data-tone={tone}>
                  <i className="bi bi-exclamation-octagon-fill summary-icon" aria-hidden="true"></i>
                  <p className="summary-text mb-0">{summary}</p>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ---- Actions ------------------------------------------------------ */}
      <section className="pb-5">
        <div className="container d-flex flex-wrap justify-content-center gap-3">
          <Link to="/" className="btn btn-brand rounded-pill px-4">
            <i className="bi bi-arrow-repeat me-2" aria-hidden="true"></i>
            Analyze Another URL
          </Link>
          <Link to="/dashboard" className="btn btn-ghost rounded-pill px-4">
            <i className="bi bi-speedometer2 me-2" aria-hidden="true"></i>
            Back to Dashboard
          </Link>
          <Link to="/history" className="btn btn-ghost rounded-pill px-4">
            <i className="bi bi-clock-history me-2" aria-hidden="true"></i>
            Back to History
          </Link>
        </div>
      </section>
    </>
  )
}

export default AnalysisResultPage
