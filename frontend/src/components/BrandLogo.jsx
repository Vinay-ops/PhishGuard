import { Link } from 'react-router-dom'
import { brand } from '../data/siteContent.js'

// The PhishGuard logo: a gradient shield icon next to the product name.
// Used in both the Navbar and the Footer. Clicking it goes to the Home page.
function BrandLogo({ size = 'md' }) {
  return (
    <Link
      to="/"
      className="d-inline-flex align-items-center gap-2 text-decoration-none"
      aria-label={`${brand.name} home`}
    >
      <span
        className={`brand-logo-icon d-inline-flex align-items-center justify-content-center ${
          size === 'lg' ? 'brand-logo-icon-lg' : ''
        }`}
      >
        <i className="bi bi-shield-fill-check" aria-hidden="true"></i>
      </span>
      <span
        className={`brand-logo-text fw-bold ${
          size === 'lg' ? 'fs-3' : 'fs-5'
        }`}
      >
        {brand.name}
      </span>
    </Link>
  )
}

export default BrandLogo
