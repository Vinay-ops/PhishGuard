import { Fragment } from 'react'
import { Link } from 'react-router-dom'
import {
  aboutHeader,
  whatIsPhishing,
  whatIsPhishGuard,
  analysisSteps,
  techStack,
  securityFeatures,
  securityNotice,
  architecture,
  projectInfo,
} from '../data/aboutContent.js'

// Centered section heading used across the page (matches Home sections).
function SectionHead({ eyebrow, title, sub }) {
  return (
    <div className="row justify-content-center text-center mb-4">
      <div className="col-12 col-lg-8">
        <span className="section-eyebrow">{eyebrow}</span>
        <h2 className="section-title mt-2">{title}</h2>
        {sub && <p className="section-subtitle mx-auto">{sub}</p>}
      </div>
    </div>
  )
}

// Horizontal 5-step flow: arrows between steps on desktop, stacked on mobile.
function StepsFlow({ steps }) {
  return (
    <div className="steps-flow">
      {steps.map((step, index) => (
        <Fragment key={step.number}>
          {index > 0 && (
            <div className="flow-arrow" aria-hidden="true">
              <i className="bi bi-arrow-right step-arrow"></i>
            </div>
          )}
          <div className="flow-step text-center">
            <div className="how-icon mx-auto">
              <i className={`bi ${step.icon}`} aria-hidden="true"></i>
              <span className="how-number">{step.number}</span>
            </div>
            <h3 className="h6 fw-semibold mt-3 mb-2">{step.title}</h3>
            <p className="flow-step-text mb-0">{step.text}</p>
          </div>
        </Fragment>
      ))}
    </div>
  )
}

// Vertical architecture diagram with a two-card branch (model + rules).
function ArchitectureFlow({ stages }) {
  return (
    <div className="d-flex flex-column align-items-center">
      {stages.map((stage, index) => (
        <Fragment key={stage.label ?? `stage-${index}`}>
          {stage.branch ? (
            <div className="row g-3 justify-content-center arch-branch w-100">
              {stage.boxes.map((box) => (
                <div className="col-12 col-sm-6" key={box.label}>
                  <div className="arch-node">
                    <i className={`bi ${box.icon}`} aria-hidden="true"></i>
                    <span>{box.label}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div
              className={`arch-node${
                stage.highlight ? ' arch-node-final' : ''
              }`}
            >
              <i className={`bi ${stage.icon}`} aria-hidden="true"></i>
              <span>{stage.label}</span>
            </div>
          )}
          {index < stages.length - 1 && (
            <i className="bi bi-arrow-down arch-arrow" aria-hidden="true"></i>
          )}
        </Fragment>
      ))}
    </div>
  )
}

// About PhishGuard — static content page (version 5).
function AboutPage() {
  return (
    <>
      {/* ---- Page header with shield emblem ------------------------------- */}
      <section className="about-header">
        <div className="container">
          <div className="text-center">
            <div className="about-emblem" aria-hidden="true">
              <span className="emblem-chip ec1">
                <i className="bi bi-cpu"></i>
              </span>
              <span className="emblem-chip ec2">
                <i className="bi bi-shield-exclamation"></i>
              </span>
              <span className="emblem-chip ec3">
                <i className="bi bi-speedometer2"></i>
              </span>
              <i className="bi bi-shield-fill-check emblem-shield"></i>
            </div>
            <h1 className="section-title mt-4 mb-2">{aboutHeader.heading}</h1>
            <p className="section-subtitle mx-auto mb-0">
              {aboutHeader.subtitle}
            </p>
          </div>
        </div>
      </section>

      {/* ---- What is Phishing / What is PhishGuard ------------------------ */}
      <section className="pb-5">
        <div className="container">
          <div className="row g-4">
            <div className="col-12 col-lg-6">
              <div className="card pg-card h-100 p-4">
                <div className="pg-card-head">
                  <span className="icon-tile icon-tile-red" aria-hidden="true">
                    <i className={`bi ${whatIsPhishing.icon}`}></i>
                  </span>
                  <h2 className="h5 fw-semibold mb-0">
                    {whatIsPhishing.title}
                  </h2>
                </div>
                <p className="mb-0 about-body-text">{whatIsPhishing.text}</p>
              </div>
            </div>

            <div className="col-12 col-lg-6">
              <div className="card pg-card h-100 p-4">
                <div className="pg-card-head">
                  <span className="icon-tile icon-tile-cyan" aria-hidden="true">
                    <i className={`bi ${whatIsPhishGuard.icon}`}></i>
                  </span>
                  <h2 className="h5 fw-semibold mb-0">
                    {whatIsPhishGuard.title}
                  </h2>
                </div>
                <p className="about-body-text">{whatIsPhishGuard.text}</p>
                <ul className="list-unstyled mb-0 mt-2 purpose-list">
                  {whatIsPhishGuard.purposes.map((purpose) => (
                    <li key={purpose} className="d-flex align-items-center gap-2">
                      <i
                        className="bi bi-check2-circle text-success"
                        aria-hidden="true"
                      ></i>
                      {purpose}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- How PhishGuard Works ---------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <SectionHead
            eyebrow="Process"
            title="How PhishGuard Works"
            sub="From a pasted link to a clear verdict — five simple steps behind every scan."
          />
          <StepsFlow steps={analysisSteps} />
        </div>
      </section>

      {/* ---- Technology stack --------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <SectionHead
            eyebrow="Built With"
            title="Technology Stack"
            sub="Modern, open and beginner-friendly technologies power PhishGuard."
          />
          <div className="row g-4 row-cols-1 row-cols-sm-2 row-cols-xl-5">
            {techStack.map((tech) => (
              <div className="col" key={tech.layer}>
                <div className="card pg-card h-100 p-4">
                  <span
                    className={`icon-tile icon-tile-${tech.tile} mb-3`}
                    aria-hidden="true"
                  >
                    <i className={`bi ${tech.icon}`}></i>
                  </span>
                  <span className="kv-label d-block mb-1">{tech.layer}</span>
                  <h3 className="h6 fw-semibold mb-2">{tech.tech}</h3>
                  <p className="small text-secondary mb-0">{tech.note}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Security features -------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <SectionHead
            eyebrow="Defense Layers"
            title="Security Features"
            sub="PhishGuard combines four complementary layers of protection."
          />
          <div className="row g-4">
            {securityFeatures.map((feature) => (
              <div className="col-12 col-md-6 col-lg-3" key={feature.title}>
                <div className="card pg-card h-100 p-4">
                  <span
                    className={`icon-tile icon-tile-${feature.tile} mb-3`}
                    aria-hidden="true"
                  >
                    <i className={`bi ${feature.icon}`}></i>
                  </span>
                  <h3 className="h6 fw-semibold mb-2">{feature.title}</h3>
                  <p className="small text-secondary mb-0 feature-text">
                    {feature.text}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Important limitation notice ---------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center">
            <div className="col-12 col-lg-10 col-xl-9">
              <div className="notice-card p-4 p-lg-5">
                <div className="d-flex align-items-start gap-3">
                  <span className="notice-icon" aria-hidden="true">
                    <i className={`bi ${securityNotice.icon}`}></i>
                  </span>
                  <div>
                    <h2 className="h5 fw-bold notice-title mb-2">
                      {securityNotice.title}
                    </h2>
                    <p className="notice-text mb-0">{securityNotice.text}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- System architecture ------------------------------------------ */}
      <section className="pb-5">
        <div className="container">
          <SectionHead
            eyebrow="Behind the Scenes"
            title="System Architecture"
            sub="How a URL travels from the user to the final risk assessment."
          />
          <div className="row justify-content-center">
            <div className="col-12 col-md-9 col-xl-7">
              <ArchitectureFlow stages={architecture} />
            </div>
          </div>
        </div>
      </section>

      {/* ---- Project info -------------------------------------------------- */}
      <section className="pb-5">
        <div className="container">
          <div className="row justify-content-center">
            <div className="col-12 col-xl-10">
              <div className="card pg-card p-4 p-lg-5">
                <div className="row g-4 align-items-center">
                  <div className="col-12 col-lg-8">
                    <ul className="list-unstyled mb-0 d-flex flex-column gap-3">
                      {projectInfo.map((info) => (
                        <li key={info.label}>
                          <span className="kv-label d-block mb-1">
                            {info.label}
                          </span>
                          <span className="info-value">{info.value}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="col-12 col-lg-4 text-lg-end">
                    <Link to="/" className="btn btn-brand rounded-pill px-4">
                      <i className="bi bi-shield-check me-2" aria-hidden="true"></i>
                      Analyze a URL
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  )
}

export default AboutPage
