import React from 'react'

function Sidebar({ activeView, setActiveView }) {
  const menuItems = [
    { id: 'overview', icon: '◈', label: 'Threat overview' },
    { id: 'ingest', icon: '↓', label: 'CVE feed ingestion' },
    { id: 'mitre', icon: '◎', label: 'MITRE mapping' },
    { id: 'qa', icon: '★', label: 'IBM Bob QA suite' },
    { id: 'runbook', icon: '≡', label: 'Runbook generator' },
    { id: 'reports', icon: '⚡', label: 'Reports' }
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">THREATSCRIBE</span>
        </div>
        <div className="sidebar-subtitle">powered by watsonx.ai + IBM Bob</div>
      </div>

      <nav className="sidebar-nav">
        {menuItems.map((item) => (
          <button
            key={item.id}
            className={`sidebar-nav-item ${activeView === item.id ? 'active' : ''}`}
            onClick={() => setActiveView(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-status">
          <span className="status-dot running"></span>
          <span className="status-label">System operational</span>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar

// Made with Bob
