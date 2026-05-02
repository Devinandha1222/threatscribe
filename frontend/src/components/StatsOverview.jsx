import React from 'react'

function StatsOverview({ stats }) {
  return (
    <div className="stats-overview">
      <div className="stat-card stat-card-critical">
        <div className="stat-value">{stats.critical}</div>
        <div className="stat-label">CRITICAL CVES</div>
        <div className="stat-badge badge-critical">URGENT</div>
      </div>

      <div className="stat-card stat-card-high">
        <div className="stat-value">{stats.high}</div>
        <div className="stat-label">HIGH SEVERITY</div>
        <div className="stat-trend">↑ 12% this week</div>
      </div>

      <div className="stat-card stat-card-accuracy">
        <div className="stat-value">{stats.parserAccuracy}%</div>
        <div className="stat-label">PARSER ACCURACY</div>
        <div className="stat-progress">
          <div className="progress-bar" style={{ width: `${stats.parserAccuracy}%` }}></div>
        </div>
      </div>

      <div className="stat-card stat-card-time">
        <div className="stat-value">{stats.avgTriageTime}m</div>
        <div className="stat-label">AVG TRIAGE TIME</div>
        <div className="stat-icon">⚡</div>
      </div>
    </div>
  )
}

export default StatsOverview

// Made with Bob
