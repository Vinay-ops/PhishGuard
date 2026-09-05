// Reusable empty-state block (used on Scan History and reusable on future
// pages whenever a list has no records to show).
function EmptyState({ icon = 'bi-inbox', title, text, action }) {
  return (
    <div className="empty-state text-center py-5">
      <span className="empty-icon" aria-hidden="true">
        <i className={`bi ${icon}`}></i>
      </span>
      <h3 className="h5 fw-bold empty-state-title">{title}</h3>
      <p className="text-secondary empty-state-text mb-4">{text}</p>
      {action}
    </div>
  )
}

export default EmptyState
