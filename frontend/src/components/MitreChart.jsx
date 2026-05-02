import React from 'react'

function MitreChart({ cves }) {
  // Mock MITRE ATT&CK coverage data
  const mitreData = [
    { technique: 'Initial Access', count: 17, percentage: 85 },
    { technique: 'Execution', count: 14, percentage: 70 },
    { technique: 'Persistence', count: 11, percentage: 55 },
    { technique: 'Privilege Esc.', count: 8, percentage: 40 },
    { technique: 'Exfiltration', count: 5, percentage: 25 }
  ]

  const getBarColor = (percentage) => {
    if (percentage >= 70) return '#f87171' // red
    if (percentage >= 50) return '#fbbf24' // amber
    if (percentage >= 30) return '#60a5fa' // blue
    return '#a78bfa' // purple
  }

  return (
    <div className="mitre-chart card">
      <div className="card-header">
        <h3 className="card-title">MITRE ATT&CK COVERAGE — AUTO-MAPPED BY WATSONX.AI</h3>
      </div>
      
      <div className="mitre-bars">
        {mitreData.map((item, index) => (
          <div key={index} className="mitre-bar-row">
            <div className="mitre-label">{item.technique}</div>
            <div className="mitre-bar-container">
              <div 
                className="mitre-bar"
                style={{ 
                  width: `${item.percentage}%`,
                  backgroundColor: getBarColor(item.percentage)
                }}
              >
                <span className="mitre-bar-label">{item.count}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mitre-footer">
        <span className="mitre-footer-text">
          Coverage analysis based on {cves.length} active threats
        </span>
      </div>
    </div>
  )
}

export default MitreChart

// Made with Bob
