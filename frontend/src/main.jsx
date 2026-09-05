import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

// Bootstrap 5 CSS + JS (dark mode is enabled via data-bs-theme="dark" on <html>).
import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap/dist/js/bootstrap.bundle.min.js'
// Bootstrap Icons (font + CSS).
import 'bootstrap-icons/font/bootstrap-icons.css'
// Custom PhishGuard theme + component styles. Imported last so they can
// override Bootstrap's default CSS variables.
import './index.css'
import './dashboard.css'
import './scanhistory.css'
import './about.css'

import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
