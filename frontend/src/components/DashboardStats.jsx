// Row of summary statistic cards (total / safe / suspicious / phishing).
// Renders any array of stat objects; optional trend badges are hidden
// when the trend string is empty.
function DashboardStats({ stats }) {
  return (
    <div className="row g-4">
      {stats.map((stat) => (
        <div className="col-12 col-sm-6 col-xl-3" key={stat.label}>
          <div className="card pg-card stat-card h-100 p-4">
            <div className="d-flex align-items-start justify-content-between gap-2">
              <span
                className={`icon-tile icon-tile-${stat.tile}`}
                aria-hidden="true"
              >
                <i className={`bi ${stat.icon}`}></i>
              </span>
              {stat.trend && (
                <span
                  className={`trend-badge tone-${stat.trendTone}`}
                  title="Compared to the previous period"
                >
                  <i className="bi bi-arrow-up-right" aria-hidden="true"></i>
                  {stat.trend}
                </span>
              )}
            </div>
            <p className="stat-value mt-3 mb-1">
              {typeof stat.value === 'number'
                ? stat.value.toLocaleString('en-US')
                : stat.value}
            </p>
            <p className="stat-label mb-0">{stat.label}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

export default DashboardStats
