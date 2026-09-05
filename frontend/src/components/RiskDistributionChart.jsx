import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
} from 'chart.js'
import { Doughnut } from 'react-chartjs-2'

// Register only the Chart.js pieces this chart needs (registered once).
ChartJS.register(ArcElement, Tooltip)

// Shared tooltip styling so chart tooltips match the dark theme.
const chartTooltip = {
  backgroundColor: '#101b31',
  borderColor: '#223153',
  borderWidth: 1,
  titleColor: '#eef3fc',
  bodyColor: '#cbd5e1',
  padding: 10,
  cornerRadius: 8,
  displayColors: false,
}

// Doughnut chart showing the Safe / Suspicious / Phishing distribution.
// Reusable: pass any { labels, data, colors } distribution object.
function RiskDistributionChart({ distribution }) {
  const { labels, data, colors, totalScanned } = distribution

  const chartData = {
    labels,
    datasets: [
      {
        data,
        backgroundColor: colors,
        borderWidth: 0,
        hoverOffset: 4,
      },
    ],
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    cutout: '74%',
    plugins: {
      tooltip: {
        ...chartTooltip,
        callbacks: {
          label: (context) => ` ${context.label}: ${context.parsed}%`,
        },
      },
    },
  }

  return (
    <div className="card pg-card h-100 p-4">
      <div className="pg-card-head">
        <span className="icon-tile icon-tile-cyan" aria-hidden="true">
          <i className="bi bi-pie-chart-fill"></i>
        </span>
        <div>
          <h2 className="h5 fw-semibold mb-0">URL Risk Distribution</h2>
          <span className="kv-label">Share of all scanned URLs</span>
        </div>
      </div>

      <div className="row g-4 align-items-center flex-grow-1">
        <div className="col-12 col-md-6 d-flex justify-content-center">
          <div className="chart-donut-wrap" role="img" aria-label="URL risk distribution doughnut chart">
            <Doughnut data={chartData} options={options} />
            <div className="chart-center" aria-hidden="true">
              <span className="chart-center-value">
                {totalScanned.toLocaleString('en-US')}
              </span>
              <span className="chart-center-label">URLs Scanned</span>
            </div>
          </div>
        </div>

        <div className="col-12 col-md-6">
          <ul className="legend-list list-unstyled mb-0">
            {labels.map((label, index) => (
              <li key={label} className="d-flex align-items-center gap-3">
                <span
                  className="legend-dot"
                  style={{ backgroundColor: colors[index] }}
                  aria-hidden="true"
                ></span>
                <span className="legend-label flex-grow-1">{label}</span>
                <span className="legend-value">{data[index]}%</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

export default RiskDistributionChart
