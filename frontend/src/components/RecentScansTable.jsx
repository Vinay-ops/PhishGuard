import { Link } from 'react-router-dom'

// Table of the most recent URL scans. Each row's "View" action loads the
// stored scan record (no re-analysis).
function RecentScansTable({ scans }) {
  if (!scans || scans.length === 0) {
    return (
      <div className="card pg-card p-4">
        <div className="text-center py-4">
          <p className="text-secondary mb-0">No recent scans available.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="card pg-card p-4">
      <div className="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
        <div className="d-flex align-items-center gap-3">
          <span className="icon-tile icon-tile-cyan" aria-hidden="true">
            <i className="bi bi-clock-history"></i>
          </span>
          <div>
            <h2 className="h5 fw-semibold mb-0">Recent URL Scans</h2>
            <span className="kv-label">Latest activity</span>
          </div>
        </div>
        <span className="status-badge tone-success">
          {scans.length} shown
        </span>
      </div>

      <div className="table-responsive recent-table-wrap">
        <table className="table table-hover align-middle mb-0 recent-table">
          <thead>
            <tr>
              <th scope="col">URL</th>
              <th scope="col">Classification</th>
              <th scope="col">Risk Score</th>
              <th scope="col">Date</th>
              <th scope="col" className="text-end">Action</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.url + scan.date}>
                <td>
                  <span className="url-cell" title={scan.url}>
                    <i className="bi bi-link-45deg" aria-hidden="true"></i>
                    {scan.url}
                  </span>
                </td>
                <td>
                  <span className={`status-badge tone-${scan.tone}`}>
                    {scan.classification}
                  </span>
                </td>
                <td>
                  <span className={`risk-cell tone-${scan.tone}`}>
                    {scan.riskScore}%
                  </span>
                </td>
                <td className="date-cell">{scan.date}</td>
                <td className="text-end">
                  <Link
                    to={`/analyze?id=${scan.id}`}
                    className="action-view"
                  >
                    <i className="bi bi-eye me-1" aria-hidden="true"></i>
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default RecentScansTable
