import { Link, NavLink } from 'react-router-dom'
import BrandLogo from './BrandLogo.jsx'
import { navLinks } from '../data/siteContent.js'

// Sticky top navigation bar.
// Items with a route become <NavLink>s; the collapse button uses Bootstrap JS.
function Navbar() {
  return (
    <nav
      className="navbar navbar-expand-lg sticky-top pg-navbar"
      aria-label="Main navigation"
    >
      <div className="container">
        <BrandLogo />

        <button
          className="navbar-toggler border-0 shadow-none"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#mainNav"
          aria-controls="#mainNav"
          aria-expanded="false"
          aria-label="Toggle navigation"
        >
          <i className="bi bi-list fs-2 lh-1 text-white" aria-hidden="true"></i>
        </button>

        <div className="collapse navbar-collapse" id="mainNav">
          <ul className="navbar-nav mx-auto mb-2 mb-lg-0 gap-lg-1">
            {navLinks.map((link) => (
              <li className="nav-item" key={link.label}>
                <NavLink
                  to={link.path}
                  className={({ isActive }) =>
                    `nav-link pg-nav-link px-3${isActive ? ' active' : ''}`
                  }
                  end={link.path === '/'}
                >
                  {link.label}
                </NavLink>
              </li>
            ))}
          </ul>

          <div className="d-flex align-items-center gap-2">
            <Link
              to="/"
              className="btn btn-brand btn-sm px-3 rounded-pill d-none d-lg-inline-flex align-items-center gap-2"
            >
              <i className="bi bi-shield-check" aria-hidden="true"></i>
              Start Scanning
            </Link>
          </div>
        </div>
      </div>
    </nav>
  )
}

export default Navbar
