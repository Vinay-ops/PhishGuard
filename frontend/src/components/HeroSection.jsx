import { hero } from '../data/siteContent.js'
import UrlScanner from './UrlScanner.jsx'

// Hero (first) section of the Home page. The URL scanning form itself lives
// in UrlScanner, which talks to the FastAPI backend through services/api.js.
function HeroSection() {
  return (
    <section id="home" className="hero-section position-relative overflow-hidden">
      {/* Decorative, non-animated background layers */}
      <div className="hero-grid" aria-hidden="true"></div>
      <div className="hero-glow hero-glow-top" aria-hidden="true"></div>
      <div className="hero-glow hero-glow-bottom" aria-hidden="true"></div>

      <div className="container position-relative">
        <div className="row justify-content-center">
          <div className="col-12 col-xl-9 text-center">
            <span className="hero-badge d-inline-flex align-items-center gap-2">
              <i className="bi bi-shield-check" aria-hidden="true"></i>
              {hero.badge}
            </span>

            <h1 className="hero-title mt-4 mb-3">
              {hero.titleStart}{' '}
              <span className="text-gradient">{hero.titleAccent}</span>
            </h1>

            <p className="hero-subtitle mx-auto mb-4">{hero.description}</p>

            <UrlScanner />

            {/* Trust indicators */}
            <ul className="trust-row list-unstyled d-flex flex-wrap justify-content-center gap-4 gap-md-5 mb-0">
              {hero.trustPoints.map((point) => (
                <li
                  key={point.text}
                  className="d-flex align-items-center gap-2"
                >
                  <i
                    className={`bi ${point.icon} trust-row-icon`}
                    aria-hidden="true"
                  ></i>
                  {point.text}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}

export default HeroSection
