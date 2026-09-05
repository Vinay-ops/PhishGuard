import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { fetchDashboard, fetchDashboardTrends } from '../services/api.js'
import DashboardStats from '../components/DashboardStats.jsx'
import RiskDistributionChart from '../components/RiskDistributionChart.jsx'
import RiskScoreTrendChart from '../components/RiskScoreTrendChart.jsx'
import RecentScansTable from '../components/RecentScansTable.jsx'

function DashboardPage() {
  const [data, setData] = useState(null)
  const [trends, setTrends] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    // Dashboard summary is the primary data; failures surface an error.
    fetchDashboard()
      .then((dashboardData) => {
        if (!cancelled) setData(dashboardData)
      })
      .catch(() => {
        if (!cancelled) setError('Could not load dashboard data. Is the backend running?')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    // Trend data is non-fatal: if it is unavailable the chart simply
    // renders an empty state instead of breaking the whole dashboard.
    fetchDashboardTrends()
      .then((trendsData) => {
        if (!cancelled) setTrends(trendsData)
      })
      .catch(() => {
        if (!cancelled) setTrends(null)
      })

    return () => { cancelled = true }
  }, [])

  // Loading state
  if (loading) {
    return (
      <>
        <section className="dashboard-header">
          <div className="container">
            <h1 className="section-title mb-2">Security Dashboard</h1>
            <p className="section-subtitle mb-0">Loading dashboard data…</p>
          </div>
        </section>
        <section className="pb-5">
          <div className="container text-center py-5">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading…</span>
            </div>
          </div>
        </section>
      </>
    )
  }

  // Error state
  if (error) {
    return (
      <>
        <section className="dashboard-header">
          <div className="container">
            <h1 className="section-title mb-2">Security Dashboard</h1>
          </div>
        </section>
        <section className="pb-5">
          <div className="container text-center py-5">
            <div className="mb-3">
              <i className="bi bi-exclamation-octagon-fill text-danger" style={{ fontSize: '3rem' }} aria-hidden="true"></i>
            </div>
            <h2 className="h4 fw-semibold mb-2">Dashboard Unavailable</h2>
            <p className="text-secondary mb-4">{error}</p>
            <Link to="/" className="btn btn-brand rounded-pill px-4">
              <i className="bi bi-arrow-left me-2" aria-hidden="true"></i>
              Back to Home
            </Link>
          </div>
        </section>
      </>
    )
  }

  // Empty state — no data yet
  if (!data || data.totalScans === 0) {
    return (
      <>
        <section className="dashboard-header">
          <div className="container">
            <h1 className="section-title mb-2">Security Dashboard</h1>
            <p className="section-subtitle mb-0">
              Monitor URL scans and phishing detection activity.
            </p>
          </div>
        </section>
        <section className="pb-5">
          <div className="container text-center py-5">
            <div className="mb-3">
              <i className="bi bi-bar-chart text-primary" style={{ fontSize: '3rem' }} aria-hidden="true"></i>
            </div>
            <h2 className="h4 fw-semibold mb-2">No Data Yet</h2>
            <p className="text-secondary mb-4">
              Start analyzing URLs to populate the dashboard with real data.
            </p>
            <Link to="/" className="btn btn-brand rounded-pill px-4">
              <i className="bi bi-shield-check me-2" aria-hidden="true"></i>
              Analyze Your First URL
            </Link>
          </div>
        </section>
      </>
    )
  }

  // Compute stats for the DashboardStats component.
  const statistics = [
    {
      icon: 'bi-link-45deg',
      tile: 'cyan',
      value: data.totalScans,
      label: 'Total URLs Scanned',
      trend: '',
      trendTone: 'success',
    },
    {
      icon: 'bi-shield-check',
      tile: 'emerald',
      value: data.safeCount,
      label: 'Safe URLs',
      trend: '',
      trendTone: 'success',
    },
    {
      icon: 'bi-exclamation-triangle',
      tile: 'amber',
      value: data.suspiciousCount,
      label: 'Suspicious URLs',
      trend: '',
      trendTone: 'warning',
    },
    {
      icon: 'bi-x-octagon-fill',
      tile: 'red',
      value: data.phishingCount,
      label: 'Phishing URLs',
      trend: '',
      trendTone: 'danger',
    },
  ]

  // Compute risk distribution percentages.
  const total = data.totalScans || 1
  const riskDistribution = {
    totalScanned: data.totalScans,
    labels: ['Safe', 'Suspicious', 'Phishing'],
    data: [
      Math.round((data.safeCount / total) * 100),
      Math.round((data.suspiciousCount / total) * 100),
      Math.round((data.phishingCount / total) * 100),
    ],
    colors: ['#22c55e', '#f59e0b', '#ef4444'],
  }

  // Recent scans for the table.
  const recentScans = data.recentScans.map((scan) => ({
    id: scan.id,
    url: scan.url,
    classification: scan.classification,
    tone: scan.tone,
    riskScore: scan.riskScore,
    date: scan.scannedAt.toLocaleDateString('en-US', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    }),
  }))

  // Weekly risk scores from backend trend endpoint. Each entry maps to a
  // real calendar day; days with no scans are `null` (rendered as a gap).
  const weeklyRiskScores = {
    labels: trends?.labels ?? [],
    data: trends?.averageRiskScores ?? [],
  }

  // Insights
  const insights = [
    {
      icon: 'bi-speedometer2',
      tile: 'amber',
      title: 'Average Risk Score',
      value: `${data.averageRiskScore}%`,
    },
    {
      icon: 'bi-flag-fill',
      tile: 'red',
      title: 'Phishing URLs Found',
      value: data.phishingCount,
    },
    {
      icon: 'bi-shield-check',
      tile: 'emerald',
      title: 'Safe URLs Detected',
      value: data.safeCount,
    },
  ]

  return (
    <>
      {/* ---- Page header ------------------------------------------------ */}
      <section className="dashboard-header">
        <div className="container">
          <div className="row align-items-center g-3">
            <div className="col-12 col-lg-7">
              <h1 className="section-title mb-2">Security Dashboard</h1>
              <p className="section-subtitle mb-0">
                Monitor URL scans and phishing detection activity.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Statistics --------------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <DashboardStats stats={statistics} />
        </div>
      </section>

      {/* ---- Charts -------------------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row g-4">
            <div className="col-12 col-xl-5 d-flex">
              <RiskDistributionChart distribution={riskDistribution} />
            </div>
            <div className="col-12 col-xl-7 d-flex">
              <RiskScoreTrendChart series={weeklyRiskScores} />
            </div>
          </div>
        </div>
      </section>

      {/* ---- Recent scans -------------------------------------------------- */}
      {recentScans.length > 0 && (
        <section className="pb-5">
          <div className="container">
            <RecentScansTable scans={recentScans} />
          </div>
        </section>
      )}

      {/* ---- Security insights --------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row g-4">
            {insights.map((insight) => (
              <div className="col-12 col-lg-4" key={insight.title}>
                <div className="card pg-card h-100 p-4 insight-card">
                  <div className="d-flex justify-content-between align-items-start gap-3">
                    <div className="min-w-0">
                      <span className="kv-label">{insight.title}</span>
                      <p className="insight-value mt-2 mb-0">{insight.value}</p>
                    </div>
                    <span
                      className={`icon-tile icon-tile-${insight.tile}`}
                      aria-hidden="true"
                    >
                      <i className={`bi ${insight.icon}`}></i>
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Quick actions -------------------------------------------------- */}
      <section className="pb-5">
        <div className="container d-flex flex-wrap justify-content-center gap-3">
          <Link to="/" className="btn btn-brand rounded-pill px-4">
            <i className="bi bi-shield-check me-2" aria-hidden="true"></i>
            Analyze New URL
          </Link>
          <Link to="/history" className="btn btn-ghost rounded-pill px-4">
            <i className="bi bi-clock-history me-2" aria-hidden="true"></i>
            View Scan History
          </Link>
        </div>
      </section>
    </>
  )
}

export default DashboardPage
