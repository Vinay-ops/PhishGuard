import { Link } from 'react-router-dom'
import { formatScanDateTime } from '../utils/historyFilters.js'

// Data table for the Scan History page. Receives only the rows that should
// be visible on the current page, plus pagination info and callbacks.
function ScanHistoryTable({
  rows,
  page,
  totalPages,
  onPageChange,
  onDelete,
  rangeInfo,
}) {
  const goTo = (target) => {
    if (target >= 1 && target <= totalPages) onPageChange(target)
  }

  return (
    <>
      <div className="table-responsive recent-table-wrap">
        <table className="table table-hover align-middle mb-0 recent-table history-table">
          <thead>
            <tr>
              <th scope="col" className="text-center col-index">#</th>
              <th scope="col">URL</th>
              <th scope="col">Classification</th>
              <th scope="col">Risk Score</th>
              <th scope="col">ML Confidence</th>
              <th scope="col">Date &amp; Time</th>
              <th scope="col" className="text-end">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((record) => (
              <tr key={record.id}>
                <td className="text-center date-cell">{record.id}</td>
                <td>
                  <span className="url-cell" title={record.url}>
                    <i className="bi bi-link-45deg" aria-hidden="true"></i>
                    {record.url}
                  </span>
                </td>
                <td>
                  <span className={`status-badge tone-${record.tone}`}>
                    {record.classification}
                  </span>
                </td>
                <td>
                  <span className={`risk-cell tone-${record.tone}`}>
                    {record.riskScore}%
                  </span>
                </td>
                <td>
                  <span className="ml-cell">{record.mlConfidence}%</span>
                </td>
                <td className="date-cell">
                  {formatScanDateTime(record.scannedAt)}
                </td>
                <td>
                  <div className="d-flex justify-content-end gap-2">
                    {/* View link loads the stored scan record (no re-analysis). */}
                    <Link
                      to={`/analyze?id=${record.id}`}
                      className="action-view"
                    >
                      <i className="bi bi-eye me-1" aria-hidden="true"></i>
                      View
                    </Link>
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => onDelete(record)}
                      aria-label={`Remove ${record.url} from history`}
                      title="Remove from history"
                    >
                      <i className="bi bi-trash3" aria-hidden="true"></i>
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination footer */}
      {totalPages > 1 && (
        <div className="d-flex flex-wrap align-items-center justify-content-between gap-3 mt-4">
          <p className="mb-0 small text-secondary">{rangeInfo}</p>
          <nav aria-label="Scan history pagination">
            <ul className="pagination pagination-custom justify-content-center mb-0">
              <li className={`page-item ${page === 1 ? 'disabled' : ''}`}>
                <button
                  type="button"
                  className="page-link"
                  onClick={() => goTo(page - 1)}
                  disabled={page === 1}
                >
                  <i className="bi bi-chevron-left me-1" aria-hidden="true"></i>
                  Previous
                </button>
              </li>
              {Array.from({ length: totalPages }, (_, index) => index + 1).map(
                (number) => (
                  <li
                    className={`page-item ${number === page ? 'active' : ''}`}
                    key={number}
                  >
                    <button
                      type="button"
                      className="page-link"
                      onClick={() => goTo(number)}
                      aria-current={number === page ? 'page' : undefined}
                    >
                      {number}
                    </button>
                  </li>
                ),
              )}
              <li className={`page-item ${page === totalPages ? 'disabled' : ''}`}>
                <button
                  type="button"
                  className="page-link"
                  onClick={() => goTo(page + 1)}
                  disabled={page === totalPages}
                >
                  Next
                  <i className="bi bi-chevron-right ms-1" aria-hidden="true"></i>
                </button>
              </li>
            </ul>
          </nav>
        </div>
      )}
    </>
  )
}

export default ScanHistoryTable
