import { Link } from 'react-router-dom'
import BrandLogo from './BrandLogo.jsx'
import { brand, footer } from '../data/siteContent.js'

function Footer() {
  const year = new Date().getFullYear()

  return (
    <footer className="pg-footer">
      <div className="container">
        <div className="row g-5 py-5">
          {/* Brand + description */}
          <div className="col-12 col-lg-5 pe-lg-4">
            <BrandLogo size="lg" />
            <p className="mt-3 mb-0 footer-description">
              {footer.description}
            </p>
            <p className="mt-3 mb-0 footer-tagline">{brand.tagline}</p>
          </div>

          {/* Link columns */}
          {footer.columns.map((column) => (
            <div className="col-6 col-md-4 col-lg-2" key={column.heading}>
              <h2 className="footer-heading">{column.heading}</h2>
              <ul className="list-unstyled mb-0 d-flex flex-column gap-2">
                {column.links.map((link) => (
                  <li key={link.label}>
                    {link.path ? (
                      <Link className="footer-link" to={link.path}>
                        {link.label}
                      </Link>
                    ) : (
                      <span
                        className="footer-link"
                        title={`${link.label} — coming soon`}
                      >
                        {link.label}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}

          <div className="col-12 col-lg-3" aria-hidden="true"></div>
        </div>

        {/* Bottom bar */}
        <div className="py-4 footer-bottom d-flex flex-column flex-md-row gap-2 gap-md-0 align-items-center justify-content-between">
          <p className="mb-0">
            © {year} {footer.copyright}
          </p>
          <p className="mb-0 d-flex align-items-center gap-2">
            <i className="bi bi-shield-check text-primary" aria-hidden="true"></i>
            Stay safe online — think before you click.
          </p>
        </div>
      </div>
    </footer>
  )
}

export default Footer
