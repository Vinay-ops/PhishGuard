import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
} from 'chart.js'
import { Line } from 'react-chartjs-2'

// Register only the Chart.js pieces this chart needs (registered once).
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
)

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

// Line chart of average risk scores per day.
// Reusable: pass any { labels, data } series object.
function RiskScoreTrendChart({ series }) {
  const chartData = {
    labels: series.labels,
    datasets: [
      {
        label: 'Average risk score',
        data: series.data,
        borderColor: '#38bdf8',
        borderWidth: 2.5,
        tension: 0.35,
        fill: true,
        // Soft gradient fill under the line.
        backgroundColor: (context) => {
          const { chart } = context
          const { ctx, chartArea } = chart
          if (!chartArea) return 'rgba(56, 189, 248, 0)'
          const gradient = ctx.createLinearGradient(
            0,
            chartArea.top,
            0,
            chartArea.bottom,
          )
          gradient.addColorStop(0, 'rgba(56, 189, 248, 0.28)')
          gradient.addColorStop(1, 'rgba(56, 189, 248, 0)')
          return gradient
        },
        pointBackgroundColor: '#0ea5e9',
        pointBorderColor: '#0b1220',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
    ],
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      tooltip: {
        ...chartTooltip,
        callbacks: {
          label: (context) => {
            const y = context.parsed.y
            return y == null
              ? ' No scans recorded for this day'
              : ` Average risk: ${y}%`
          },
        },
      },
    },
    scales: {
      x: {
        grid: { display: false },
        border: { display: false },
        ticks: { color: '#8296b3', font: { size: 12 } },
      },
      y: {
        suggestedMin: 0,
        suggestedMax: 100,
        grid: { color: 'rgba(148, 163, 184, 0.1)' },
        border: { display: false },
        ticks: {
          color: '#8296b3',
          font: { size: 11 },
          callback: (value) => `${value}%`,
        },
      },
    },
  }

  return (
    <div className="card pg-card h-100 p-4">
      <div className="pg-card-head">
        <span className="icon-tile icon-tile-violet" aria-hidden="true">
          <i className="bi bi-graph-up-arrow"></i>
        </span>
        <div>
          <h2 className="h5 fw-semibold mb-0">Risk Score Overview</h2>
          <span className="kv-label">Average risk per day</span>
        </div>
      </div>

      <div
        className="chart-line-wrap flex-grow-1"
        role="img"
        aria-label="Line chart of average risk scores over the last 7 days"
      >
        <Line data={chartData} options={options} />
      </div>

      <div className="d-flex align-items-center gap-2 mt-3 chart-line-caption">
        <span
          className="legend-dot"
          style={{ backgroundColor: '#38bdf8' }}
          aria-hidden="true"
        ></span>
        <span className="small text-secondary">Average risk score per day</span>
      </div>
    </div>
  )
}

export default RiskScoreTrendChart
