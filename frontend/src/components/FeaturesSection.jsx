import { features } from '../data/siteContent.js'

// Feature cards rendered from the static data in siteContent.js.
// The `accent` value maps to a CSS class controlling each icon's gradient.
function FeaturesSection() {
  return (
    <section id="features" className="pg-section features-section">
      <div className="container">
        <div className="row justify-content-center text-center">
          <div className="col-12 col-lg-8">
            <span className="section-eyebrow">{features.eyebrow}</span>
            <h2 className="section-title mt-2">{features.title}</h2>
            <p className="section-subtitle mx-auto">{features.subtitle}</p>
          </div>
        </div>

        <div className="row g-4 mt-2">
          {features.cards.map((feature) => (
            <div className="col-12 col-md-6 col-lg-4" key={feature.title}>
              <div className="card pg-card h-100 p-4 p-xl-4">
                <div className="card-body p-0 d-flex flex-column">
                  <span
                    className={`icon-tile mb-3 icon-tile-${feature.accent}`}
                    aria-hidden="true"
                  >
                    <i className={`bi ${feature.icon} fs-3`}></i>
                  </span>
                  <h3 className="h5 fw-semibold mb-2">{feature.title}</h3>
                  <p className="pg-card-text mb-4">{feature.description}</p>
                  <div className="mt-auto d-flex align-items-center gap-2 feature-link">
                    <i
                      className="bi bi-check-circle-fill text-success"
                      aria-hidden="true"
                    ></i>
                    <span>Built into every scan</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default FeaturesSection
