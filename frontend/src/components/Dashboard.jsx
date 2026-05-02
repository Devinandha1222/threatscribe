import React, { useState, useEffect } from 'react'
import StatsOverview from './StatsOverview'
import ThreatFeed from './ThreatFeed'
import MitreChart from './MitreChart'
import BobQAPanel from './BobQAPanel'
import Sidebar from './Sidebar'
import UploadPanel from './UploadPanel'

function Dashboard() {
  const [cves, setCves] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeView, setActiveView] = useState('overview')
  const [showUploadPanel, setShowUploadPanel] = useState(false)
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    parserAccuracy: 94,
    avgTriageTime: 7.2
  })

  useEffect(() => {
    fetchCVEs()
    const interval = setInterval(fetchCVEs, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const fetchCVEs = async () => {
    try {
      setLoading(true)
      const response = await fetch('http://localhost:3001/api/triage')
      if (!response.ok) {
        throw new Error('Failed to fetch CVEs')
      }
      const data = await response.json()
      const cveList = data.cves || []
      setCves(cveList)
      
      // Calculate stats
      const critical = cveList.filter(c => c.severity === 'CRITICAL').length
      const high = cveList.filter(c => c.severity === 'HIGH').length
      const medium = cveList.filter(c => c.severity === 'MEDIUM').length
      const low = cveList.filter(c => c.severity === 'LOW').length
      
      setStats({
        critical,
        high,
        medium,
        low,
        total: cveList.length,
        parserAccuracy: 94,
        avgTriageTime: 7.2
      })
      
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleUploadComplete = () => {
    // Refresh CVE list after upload
    fetchCVEs()
  }

  return (
    <div className="dashboard">
      <Sidebar activeView={activeView} setActiveView={setActiveView} />
      
      <div className="dashboard-main">
        <header className="dashboard-header">
          <div className="header-left">
            <h1 className="dashboard-title">
              <span className="title-icon">🛡️</span>
              THREATSCRIBE
            </h1>
            <p className="dashboard-subtitle">Intelligent threat analyst</p>
          </div>
          <div className="header-right">
            <button
              className="btn btn-primary upload-btn"
              onClick={() => setShowUploadPanel(true)}
            >
              📤 Upload CVE Data
            </button>
            <div className="status-badge">
              <span className="status-dot running"></span>
              <span className="status-text">watsonx.ai connected</span>
            </div>
          </div>
        </header>

        <div className="dashboard-content">
          {loading && cves.length === 0 ? (
            <div className="loading-state">
              <div className="spinner-large"></div>
              <p>Loading threat intelligence...</p>
            </div>
          ) : error ? (
            <div className="error-state">
              <div className="error-icon">⚠️</div>
              <h3>Connection Error</h3>
              <p>{error}</p>
              <button className="btn btn-primary" onClick={fetchCVEs}>
                Retry Connection
              </button>
            </div>
          ) : (
            <>
              <StatsOverview stats={stats} />
              
              <div className="dashboard-grid">
                <div className="dashboard-col-main">
                  <ThreatFeed cves={cves} loading={loading} />
                </div>
                
                <div className="dashboard-col-side">
                  <MitreChart cves={cves} />
                  <BobQAPanel />
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {showUploadPanel && (
        <UploadPanel
          onAnalyze={handleUploadComplete}
          onClose={() => setShowUploadPanel(false)}
        />
      )}
    </div>
  )
}

export default Dashboard

// Made with Bob
