import React, { useState, useEffect } from 'react'

function BobQAPanel() {
  const [qaStatus, setQaStatus] = useState('running')
  const [testResults, setTestResults] = useState([
    { id: 1, name: 'Edge case validation', status: 'passed', confidence: 98.4 },
    { id: 2, name: 'NVD corpus accuracy', status: 'passed', confidence: 100 },
    { id: 3, name: 'Advisory PDF scan', status: 'running', confidence: null },
    { id: 4, name: 'Regression detection', status: 'failed', confidence: 87.2 }
  ])

  const getStatusIcon = (status) => {
    switch(status) {
      case 'passed': return '✓'
      case 'failed': return '✗'
      case 'running': return '~'
      default: return '○'
    }
  }

  const getStatusClass = (status) => {
    switch(status) {
      case 'passed': return 'qa-status-passed'
      case 'failed': return 'qa-status-failed'
      case 'running': return 'qa-status-running'
      default: return 'qa-status-pending'
    }
  }

  return (
    <div className="bob-qa-panel card">
      <div className="card-header">
        <h3 className="card-title">IBM BOB — LIVE QA RESULTS</h3>
      </div>

      <div className="qa-status-bar">
        <div className="qa-status-indicator">
          <span className="status-dot running"></span>
          <span className="status-text">Running 47 test cases...</span>
        </div>
      </div>

      <div className="qa-results">
        {testResults.map((test) => (
          <div key={test.id} className={`qa-result-item ${getStatusClass(test.status)}`}>
            <div className="qa-result-icon">
              {getStatusIcon(test.status)}
            </div>
            <div className="qa-result-content">
              <div className="qa-result-name">{test.name}</div>
              {test.confidence !== null && (
                <div className="qa-result-confidence">
                  Confidence: {test.confidence}%
                </div>
              )}
            </div>
            {test.status === 'running' && (
              <div className="qa-result-spinner">
                <div className="spinner-small"></div>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="qa-summary">
        <div className="qa-summary-item">
          <span className="qa-summary-value text-success">312</span>
          <span className="qa-summary-label">Passed</span>
        </div>
        <div className="qa-summary-item">
          <span className="qa-summary-value text-critical">2</span>
          <span className="qa-summary-label">Failed</span>
        </div>
        <div className="qa-summary-item">
          <span className="qa-summary-value text-warning">47</span>
          <span className="qa-summary-label">Running</span>
        </div>
      </div>
    </div>
  )
}

export default BobQAPanel

// Made with Bob
