// Pure helpers for the Scan History page.

/**
 * Format a Date like "05 Sep 2026, 11:32 AM".
 * Accepts both Date objects and ISO date strings.
 */
export function formatScanDateTime(date) {
  const d = date instanceof Date ? date : new Date(date)

  if (isNaN(d.getTime())) return '—'

  const dayNumber = String(d.getDate()).padStart(2, '0')
  const month = d.toLocaleDateString('en-US', { month: 'short' })
  const year = d.getFullYear()
  const time = d.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
  })
  return `${dayNumber} ${month} ${year}, ${time}`
}

/**
 * Map a numeric risk score to a bucket used by the dropdown.
 * Low < 30 · Medium 30–70 · High > 70.
 */
export function getRiskLevel(score) {
  if (score < 30) return 'Low'
  if (score <= 70) return 'Medium'
  return 'High'
}
