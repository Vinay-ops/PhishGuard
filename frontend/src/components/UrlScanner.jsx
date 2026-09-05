import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { hero } from '../data/siteContent.js'
import { analyzeUrl, API_BASE_URL } from '../services/api.js'

// Maximum URL length accepted by the frontend.
const MAX_URL_LENGTH = 2048

function UrlScanner() {
  const navigate = useNavigate()
  const [url, setUrl] = useState('')
  const [notice, setNotice] = useState(null)
  const [loading, setLoading] = useState(false)
  const inputRef = useRef(null)

  // Validate a URL string and return an error message, or null if valid.
  const validateUrl = (value) => {
    const trimmed = value.trim()

    if (!trimmed) {
      return 'Please enter a URL you would like to analyze.'
    }

    if (trimmed.length > MAX_URL_LENGTH) {
      return `URL exceeds maximum length of ${MAX_URL_LENGTH} characters.`
    }

    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return 'URL must start with http:// or https://.'
    }

    return null
  }

  const handleSubmit = async (event) => {
    event.preventDefault()

    const trimmed = url.trim()
    const validationError = validateUrl(trimmed)
    if (validationError) {
      setNotice({ kind: 'warn', text: validationError })
      return
    }

    // Clear previous results and errors.
    setNotice(null)
    setLoading(true)

    try {
      const result = await analyzeUrl(trimmed)
      navigate(`/analyze?url=${encodeURIComponent(trimmed)}`, {
        state: { analysisResult: result },
      })
    } catch (error) {
      const detail = error?.response?.data?.detail
      if (detail) {
        setNotice({ kind: 'error', text: `Analysis failed: ${detail}` })
      } else if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
        setNotice({ kind: 'error', text: 'Request timed out. The server may be overloaded.' })
      } else {
        setNotice({
          kind: 'error',
          text: `Could not reach the analysis service. Is the FastAPI backend running at ${API_BASE_URL}?`,
        })
      }
    } finally {
      setLoading(false)
    }
  }

  const trySample = (sample) => {
    setUrl(sample)
    setNotice(null)
    inputRef.current?.focus()
  }

  const noticeClass =
    notice?.kind === 'warn'
      ? 'hero-notice-warn'
      : notice?.kind === 'error'
        ? 'hero-notice-error'
        : ''

  return (
    <>
      <form
        id="analyze"
        onSubmit={handleSubmit}
        className="mx-auto mb-4"
        aria-label="URL analysis form"
      >
        <label htmlFor="urlInput" className="visually-hidden">
          URL to analyze
        </label>
        <div className="url-search d-flex align-items-center p-1 p-sm-2">
          <i className="bi bi-link-45deg url-search-icon" aria-hidden="true"></i>
          <input
            ref={inputRef}
            id="urlInput"
            type="text"
            className="url-input flex-grow-1"
            placeholder={hero.inputPlaceholder}
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            autoComplete="off"
            spellCheck="false"
            disabled={loading}
            maxLength={MAX_URL_LENGTH}
            aria-describedby={notice ? 'scanner-notice' : undefined}
          />
          <button
            type="submit"
            className="btn btn-brand rounded-pill"
            disabled={loading}
          >
            {loading ? (
              <>
                <span
                  className="spinner-border spinner-border-sm me-2"
                  role="status"
                  aria-hidden="true"
                ></span>
                Analyzing…
              </>
            ) : (
              <>
                <i className="bi bi-shield-check me-2" aria-hidden="true"></i>
                Analyze URL
              </>
            )}
          </button>
        </div>
      </form>

      {/* Feedback: validation warning or API error */}
      {notice && (
        <div
          id="scanner-notice"
          role="alert"
          className={`hero-notice d-inline-flex align-items-center gap-2 text-start ${noticeClass}`}
        >
          <i
            className={`bi ${
              notice.kind === 'warn'
                ? 'bi-exclamation-triangle-fill'
                : 'bi-exclamation-octagon-fill'
            } flex-shrink-0`}
            aria-hidden="true"
          ></i>
          <span>{notice.text}</span>
        </div>
      )}

      {/* One-click sample URLs */}
      <div className="d-flex flex-wrap justify-content-center align-items-center gap-2 mb-4 mt-4">
        <span className="sample-label">Try a sample:</span>
        {hero.samples.map((sample) => (
          <button
            key={sample.label}
            type="button"
            className="sample-chip"
            onClick={() => trySample(sample.label)}
            disabled={loading}
          >
            <span className="sample-chip-url">{sample.label}</span>
            <span
              className={`sample-chip-kind ${
                sample.kind === 'Looks suspicious'
                  ? 'text-warning'
                  : 'text-success'
              }`}
            >
              {sample.kind}
            </span>
          </button>
        ))}
      </div>
    </>
  )
}

export default UrlScanner
