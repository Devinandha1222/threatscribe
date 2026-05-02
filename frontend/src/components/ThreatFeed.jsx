import React, { useState } from 'react'

function ThreatFeed({ cves, loading }) {
  const [filter, setFilter] = useState('all')

  const getSeverityClass = (severity) => {
    const map = {
      'CRITICAL': 'badge-critical',
      'HIGH': 'badge-high',
      'MEDIUM': 'badge-medium',
      'LOW': 'badge-low'
    }
    return map[severity] || 'badge-medium'
  }

  const filteredCves = filter === 'all' 
    ? cves 
    : cves.filter(cve => cve.severity === filter)

  return (
    <div className="threat-feed">
      <div className="feed-header">
        <div className="feed-title">
          <h2>Threat overview — live feed</h2>
          <span className="feed-count">{filteredCves.length} threats</span>
        </div>
        <div className="feed-filters">
          <button 
            className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            All
          </button>
          <button 
            className={`filter-btn ${filter === 'CRITICAL' ? 'active' : ''}`}
            onClick={() => setFilter('CRITICAL')}
          >
            Critical
          </button>
          <button 
            className={`filter-btn ${filter === 'HIGH' ? 'active' : ''}`}
            onClick={() => setFilter('HIGH')}
          >
            High
          </button>
        </div>
      </div>

      <div className="feed-subtitle">
        INCOMING THREAT FEED — AUTO-CLASSIFIED BY WATSONX.AI
      </div>

      <div className="feed-list">
        {loading && filteredCves.length === 0 ? (
          <div className="feed-loading">
            <div className="spinner"></div>
            <span>Scanning for threats...</span>
          </div>
        ) : filteredCves.length === 0 ? (
          <div className="feed-empty">
            <div className="empty-icon">🔍</div>
            <p>No threats detected</p>
            <span className="empty-subtitle">System is monitoring for new CVEs</span>
          </div>
        ) : (
          filteredCves.map((cve, index) => (
            <div key={cve.cveId || index} className="feed-item">
              <div className="feed-item-badge">
                <span className={`badge ${getSeverityClass(cve.severity)}`}>
                  {cve.severity || 'UNKNOWN'}
                </span>
              </div>
              
              <div className="feed-item-content">
                <div className="feed-item-header">
                  <h3 className="feed-item-title">{cve.cveId}</h3>
                  <span className="feed-item-meta">
                    {cve.vendor || 'Unknown'} · {cve.product || 'Multiple products'}
                  </span>
                </div>
                
                <p className="feed-item-description">
                  {cve.description?.substring(0, 200) || 'No description available'}
                  {cve.description?.length > 200 && '...'}
                </p>

                {cve.aiAnalysis && (
                  <div className="feed-item-analysis">
                    <span className="analysis-label">AI Analysis:</span>
                    <span className="analysis-text">{cve.aiAnalysis.summary}</span>
                  </div>
                )}
              </div>

              <div className="feed-item-actions">
                <button className="action-btn" title="View details">
                  <span>→</span>
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default ThreatFeed

// Made with Bob
