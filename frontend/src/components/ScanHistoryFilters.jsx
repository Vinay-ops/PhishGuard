// Filter bar for the Scan History page. Fully controlled: the parent owns
// the filter values (draft) and this component only reports changes.

const classificationOptions = ['All', 'Safe', 'Suspicious', 'Phishing']
const riskOptions = ['All', 'Low Risk', 'Medium Risk', 'High Risk']
const dateOptions = ['All Time', 'Today', 'Last 7 Days', 'Last 30 Days']

function ScanHistoryFilters({ filters, onChange, onApply, onReset }) {
  const handleChange = (key, value) => {
    onChange({ ...filters, [key]: value })
  }

  return (
    <div className="card pg-card p-4 filter-card">
      <form
        onSubmit={(event) => {
          event.preventDefault()
          onApply()
        }}
      >
        <div className="row g-3 align-items-end">
          {/* URL search */}
          <div className="col-12 col-lg-4">
            <label htmlFor="filterSearch" className="kv-label d-block mb-2">
              Search
            </label>
            <div className="input-group">
              <span className="input-group-text" aria-hidden="true">
                <i className="bi bi-search"></i>
              </span>
              <input
                id="filterSearch"
                type="search"
                className="form-control pg-input"
                placeholder="Search URL..."
                value={filters.search}
                onChange={(event) =>
                  handleChange('search', event.target.value)
                }
              />
            </div>
          </div>

          {/* Classification */}
          <div className="col-6 col-md-4 col-lg-2">
            <label
              htmlFor="filterClassification"
              className="kv-label d-block mb-2"
            >
              Classification
            </label>
            <select
              id="filterClassification"
              className="form-select pg-input"
              value={filters.classification}
              onChange={(event) =>
                handleChange('classification', event.target.value)
              }
            >
              {classificationOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>

          {/* Risk score */}
          <div className="col-6 col-md-4 col-lg-2">
            <label htmlFor="filterRisk" className="kv-label d-block mb-2">
              Risk Score
            </label>
            <select
              id="filterRisk"
              className="form-select pg-input"
              value={filters.risk}
              onChange={(event) => handleChange('risk', event.target.value)}
            >
              {riskOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>

          {/* Date range */}
          <div className="col-6 col-md-4 col-lg-2">
            <label htmlFor="filterDate" className="kv-label d-block mb-2">
              Date
            </label>
            <select
              id="filterDate"
              className="form-select pg-input"
              value={filters.date}
              onChange={(event) => handleChange('date', event.target.value)}
            >
              {dateOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>

          {/* Actions */}
          <div className="col-12 col-lg-2 d-flex gap-2 justify-content-lg-end">
            <button type="submit" className="btn btn-brand flex-grow-1 flex-lg-grow-0">
              <i className="bi bi-funnel me-2" aria-hidden="true"></i>
              Apply Filters
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={onReset}
              aria-label="Reset filters"
            >
              <i className="bi bi-arrow-counterclockwise" aria-hidden="true"></i>
              Reset
            </button>
          </div>
        </div>
      </form>
    </div>
  )
}

export default ScanHistoryFilters
