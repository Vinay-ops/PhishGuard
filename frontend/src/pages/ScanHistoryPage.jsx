import { useMemo, useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { fetchHistory, deleteScanRecord, API_BASE_URL } from '../services/api.js'

import ScanHistoryFilters from '../components/ScanHistoryFilters.jsx'
import ScanHistoryTable from '../components/ScanHistoryTable.jsx'
import EmptyState from '../components/EmptyState.jsx'

const PAGE_SIZE = 10

const EMPTY_FILTERS = {
  search: '',
  classification: 'All',
  risk: 'All',
  date: 'All Time',
}

const hasActiveFilters = (filters) =>
  filters.search.trim() !== '' ||
  filters.classification !== 'All' ||
  filters.risk !== 'All' ||
  filters.date !== 'All Time'

function ScanHistoryPage() {
  const [records, setRecords] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [draft, setDraft] = useState(EMPTY_FILTERS)
  const [applied, setApplied] = useState(EMPTY_FILTERS)
  const [page, setPage] = useState(1)

  // Fetch history from the API.
  const loadHistory = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchHistory({
        search: applied.search,
        classification: applied.classification,
        risk: applied.risk,
        date: applied.date,
        page,
        pageSize: PAGE_SIZE,
      })
      setRecords(data.records)
      setTotal(data.total)
    } catch {
      setError('Could not load scan history. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }, [applied, page])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleApply = () => {
    setApplied(draft)
    setPage(1)
  }

  const handleReset = () => {
    setDraft(EMPTY_FILTERS)
    setApplied(EMPTY_FILTERS)
    setPage(1)
  }

  const handleDelete = async (record) => {
    const confirmed = window.confirm(
      `Remove "${record.url}" from scan history?`,
    )
    if (!confirmed) return

    try {
      await deleteScanRecord(record.id)
      // Optimistic removal from local state.
      setRecords((current) => current.filter((item) => item.id !== record.id))
      setTotal((prev) => Math.max(0, prev - 1))
    } catch {
      // Silently handle — the record may already be deleted.
    }
  }

  // Compute summary stats from the total count (or show zeros if no data).
  const summaryCards = useMemo(() => {
    // We only have total from the API; classification counts require
    // separate queries or we derive from the current page.
    // For simplicity, show total and the records count.
    return [
      { icon: 'bi-clipboard-data', tile: 'cyan', label: 'Total Records', value: total },
      { icon: 'bi-clock-history', tile: 'amber', label: 'Current Page', value: records.length },
    ]
  }, [total, records.length])

  const start = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const end = total === 0 ? 0 : Math.min(start + records.length - 1, total)

  return (
    <>
      {/* ---- Page header ------------------------------------------------ */}
      <section className="history-header">
        <div className="container">
          <div className="row align-items-center g-3">
            <div className="col-12 col-lg-8">
              <h1 className="section-title mb-2">Scan History</h1>
              <p className="section-subtitle mb-0">
                View and manage previously analyzed URLs.
              </p>
            </div>
            <div className="col-12 col-lg-4 d-flex justify-content-lg-end">
              <Link to="/" className="btn btn-brand rounded-pill px-4">
                <i className="bi bi-plus-lg me-2" aria-hidden="true"></i>
                Analyze New URL
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Summary cards ---------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row g-4">
            {summaryCards.map((summary) => (
              <div className="col-12 col-sm-6" key={summary.label}>
                <div className="card pg-card p-4 h-100">
                  <div className="d-flex align-items-center gap-3">
                    <span
                      className={`icon-tile icon-tile-${summary.tile} flex-shrink-0`}
                      aria-hidden="true"
                    >
                      <i className={`bi ${summary.icon}`}></i>
                    </span>
                    <div className="min-w-0">
                      <p className="summary-number mb-0">
                        {typeof summary.value === 'number'
                          ? summary.value.toLocaleString('en-US')
                          : summary.value}
                      </p>
                      <p className="stat-label mb-0">{summary.label}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Search + filters -------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <ScanHistoryFilters
            filters={draft}
            onChange={setDraft}
            onApply={handleApply}
            onReset={handleReset}
          />
        </div>
      </section>

      {/* ---- Table / empty state ----------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="card pg-card p-4">
            <div className="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
              <div className="d-flex align-items-center gap-3">
                <span className="icon-tile icon-tile-cyan" aria-hidden="true">
                  <i className="bi bi-clock-history"></i>
                </span>
                <div>
                  <h2 className="h5 fw-semibold mb-0">Scan Records</h2>
                  <span className="kv-label">
                    {loading ? 'Loading…' : `${total} total records`}
                  </span>
                </div>
              </div>
              {hasActiveFilters(applied) && records.length > 0 && (
                <span className="status-badge tone-success">
                  Filters applied
                </span>
              )}
            </div>

            {/* Error state */}
            {error && (
              <div className="alert alert-danger d-flex align-items-center gap-2" role="alert">
                <i className="bi bi-exclamation-octagon-fill" aria-hidden="true"></i>
                <span>{error}</span>
              </div>
            )}

            {/* Loading state */}
            {loading && (
              <div className="text-center py-5">
                <div className="spinner-border text-primary" role="status">
                  <span className="visually-hidden">Loading…</span>
                </div>
              </div>
            )}

            {/* Empty state */}
            {!loading && !error && records.length === 0 && (
              <EmptyState
                icon={hasActiveFilters(applied) ? 'bi-search' : 'bi-inbox'}
                title={hasActiveFilters(applied) ? 'No Matches Found' : 'No Scan History'}
                text={
                  hasActiveFilters(applied)
                    ? 'No scans match your current filters. Try clearing them to see more records.'
                    : 'URLs that you analyze will appear here.'
                }
                action={
                  hasActiveFilters(applied) ? (
                    <button
                      type="button"
                      className="btn btn-ghost rounded-pill px-4"
                      onClick={handleReset}
                    >
                      <i className="bi bi-arrow-counterclockwise me-2" aria-hidden="true"></i>
                      Reset Filters
                    </button>
                  ) : (
                    <Link to="/" className="btn btn-brand rounded-pill px-4">
                      <i className="bi bi-shield-check me-2" aria-hidden="true"></i>
                      Analyze Your First URL
                    </Link>
                  )
                }
              />
            )}

            {/* Data table */}
            {!loading && !error && records.length > 0 && (
              <ScanHistoryTable
                rows={records}
                page={page}
                totalPages={totalPages}
                onPageChange={setPage}
                onDelete={handleDelete}
                rangeInfo={`Showing ${start}–${end} of ${total} scans`}
              />
            )}
          </div>
        </div>
      </section>
    </>
  )
}

export default ScanHistoryPage
