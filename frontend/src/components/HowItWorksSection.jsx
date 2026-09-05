import { Fragment } from 'react'
import { steps } from '../data/siteContent.js'

// "How it works" — three steps connected by arrow icons in one horizontal
// row (3 + 1 + 3 + 1 + 3 = 11 Bootstrap columns, centered by Bootstrap).
// On smaller screens the steps stack vertically and the arrows rotate 90°.
function HowItWorksSection() {
  return (
    <section id="how-it-works" className="pg-section how-section">
      <div className="container">
        <div className="row justify-content-center text-center">
          <div className="col-12 col-lg-8">
            <span className="section-eyebrow">{steps.eyebrow}</span>
            <h2 className="section-title mt-2">{steps.title}</h2>
            <p className="section-subtitle mx-auto">{steps.subtitle}</p>
          </div>
        </div>

        <div className="row justify-content-center align-items-stretch g-0 mt-2">
          {steps.items.map((step, index) => (
            <Fragment key={step.number}>
              {index > 0 && (
                <div className="col-12 col-lg-1 step-arrow-wrap">
                  <i
                    className="bi bi-arrow-right step-arrow"
                    aria-hidden="true"
                  ></i>
                </div>
              )}
              <div className="col-12 col-lg-3 d-flex">
                <div className="how-step text-center flex-fill px-2">
                  <div className="how-icon mx-auto" aria-hidden="true">
                    <i className={`bi ${step.icon}`}></i>
                    <span className="how-number">{step.number}</span>
                  </div>
                  <h3 className="h5 fw-semibold mt-4 mb-2">{step.title}</h3>
                  <p className="mb-0">{step.description}</p>
                </div>
              </div>
            </Fragment>
          ))}
        </div>
      </div>
    </section>
  )
}

export default HowItWorksSection
