import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import HomePage from './pages/HomePage.jsx'
import AnalysisResultPage from './pages/AnalysisResultPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import ScanHistoryPage from './pages/ScanHistoryPage.jsx'
import AboutPage from './pages/AboutPage.jsx'

// Application routing. The Layout component wraps every page with the shared
// Navbar and Footer; each page only renders its own <main> content.
function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<HomePage />} />
          <Route path="/analyze" element={<AnalysisResultPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/history" element={<ScanHistoryPage />} />
          <Route path="/about" element={<AboutPage />} />
          {/* Unknown URLs fall back to the Home page. */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
