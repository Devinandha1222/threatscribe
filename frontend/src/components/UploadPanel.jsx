import React, { useState } from 'react'
import * as XLSX from 'xlsx'

function UploadPanel({ onAnalyze, onClose }) {
  const [uploadMethod, setUploadMethod] = useState('excel') // 'excel' or 'manual'
  const [file, setFile] = useState(null)
  const [formData, setFormData] = useState({
    cve_id: '',
    description: '',
    cvss_score: '',
    severity: 'MEDIUM',
    vendor: '',
    product: '',
    version_range: '',
    attack_vector: 'Network',
    exploitability: 'No known exploit'
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [parsePreview, setParsePreview] = useState(null)

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0]
    if (selectedFile) {
      // Check file type
      const validTypes = [
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv'
      ]
      if (validTypes.includes(selectedFile.type) || selectedFile.name.endsWith('.csv') || selectedFile.name.endsWith('.xlsx') || selectedFile.name.endsWith('.xls')) {
        setFile(selectedFile)
        setError(null)
        // Preview the file
        previewExcelFile(selectedFile)
      } else {
        setError('Please upload a valid Excel (.xlsx, .xls) or CSV file')
        setFile(null)
        setParsePreview(null)
      }
    }
  }

  const previewExcelFile = async (file) => {
    try {
      const data = await file.arrayBuffer()
      const workbook = XLSX.read(data)
      const firstSheet = workbook.Sheets[workbook.SheetNames[0]]
      const jsonData = XLSX.utils.sheet_to_json(firstSheet)
      
      if (jsonData.length > 0) {
        setParsePreview({
          rowCount: jsonData.length,
          columns: Object.keys(jsonData[0]),
          sample: jsonData[0]
        })
      }
    } catch (err) {
      console.error('Preview error:', err)
      setParsePreview(null)
    }
  }

  const handleFormChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const parseExcelToJSON = async (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      
      reader.onload = (e) => {
        try {
          const data = e.target.result
          const workbook = XLSX.read(data, { type: 'array' })
          const firstSheet = workbook.Sheets[workbook.SheetNames[0]]
          const jsonData = XLSX.utils.sheet_to_json(firstSheet)
          
          // Map Excel columns to CVE format
          const cveData = jsonData.map((row, index) => {
            // Flexible column mapping (case-insensitive)
            const getField = (possibleNames) => {
              for (const name of possibleNames) {
                const key = Object.keys(row).find(k => k.toLowerCase() === name.toLowerCase())
                if (key && row[key]) return row[key]
              }
              return null
            }

            const cveId = getField(['cve_id', 'cve id', 'cveid', 'id']) || `CVE-${new Date().getFullYear()}-EXCEL-${String(index + 1).padStart(4, '0')}`
            const description = getField(['description', 'desc', 'details', 'summary']) || 'No description provided'
            const cvssScore = getField(['cvss_score', 'cvss score', 'cvss', 'score']) || '5.0'
            const severity = getField(['severity', 'level', 'priority']) || 'MEDIUM'
            const vendor = getField(['vendor', 'manufacturer', 'company']) || 'Unknown'
            const product = getField(['product', 'software', 'application']) || 'Unknown'
            const versionRange = getField(['version_range', 'version range', 'versions', 'version']) || 'Unknown'
            const attackVector = getField(['attack_vector', 'attack vector', 'vector']) || 'Network'
            const exploitability = getField(['exploitability', 'exploit status', 'exploit']) || 'No known exploit'

            // Build comprehensive raw_text for analysis
            const rawText = `${severity.toUpperCase()} severity vulnerability ${cveId} in ${vendor} ${product}. ${description}. CVSS Score: ${cvssScore}. Version Range: ${versionRange}. Attack Vector: ${attackVector}. Exploitability: ${exploitability}.`

            return {
              cve_id: cveId,
              raw_text: rawText,
              source: 'excel_upload',
              metadata: {
                vendor,
                product,
                version_range: versionRange,
                cvss_score: parseFloat(cvssScore),
                severity: severity.toUpperCase(),
                attack_vector: attackVector,
                exploitability
              }
            }
          })
          
          resolve(cveData)
        } catch (err) {
          reject(new Error(`Failed to parse Excel file: ${err.message}`))
        }
      }
      
      reader.onerror = () => reject(new Error('Failed to read file'))
      reader.readAsArrayBuffer(file)
    })
  }

  const convertFormToJSON = () => {
    const cveId = formData.cve_id || `CVE-${new Date().getFullYear()}-MANUAL-${Date.now().toString().slice(-4)}`
    const rawText = `${formData.severity} severity vulnerability ${cveId} in ${formData.vendor || 'Unknown'} ${formData.product || 'Unknown'}. ${formData.description}. CVSS Score: ${formData.cvss_score}. ${formData.version_range ? `Version Range: ${formData.version_range}.` : ''} Attack Vector: ${formData.attack_vector}. Exploitability: ${formData.exploitability}.`
    
    return {
      cve_id: cveId,
      raw_text: rawText,
      source: 'manual_entry',
      metadata: {
        vendor: formData.vendor,
        product: formData.product,
        version_range: formData.version_range,
        cvss_score: parseFloat(formData.cvss_score),
        severity: formData.severity,
        attack_vector: formData.attack_vector,
        exploitability: formData.exploitability
      }
    }
  }

  const handleAnalyze = async () => {
    setLoading(true)
    setError(null)

    try {
      let cveData

      if (uploadMethod === 'excel') {
        if (!file) {
          setError('Please select a file to upload')
          setLoading(false)
          return
        }
        cveData = await parseExcelToJSON(file)
        
        if (cveData.length === 0) {
          setError('No valid data found in Excel file')
          setLoading(false)
          return
        }
      } else {
        // Validate manual form
        if (!formData.description || !formData.cvss_score) {
          setError('Please fill in at least Description and CVSS Score')
          setLoading(false)
          return
        }
        cveData = [convertFormToJSON()]
      }

      console.log(`Processing ${cveData.length} CVE(s)...`)

      // Send to backend for analysis
      let successCount = 0
      for (const cve of cveData) {
        try {
          // Ingest
          const ingestResponse = await fetch('http://localhost:3001/api/ingest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              raw_text: cve.raw_text,
              source: cve.source
            })
          })

          if (!ingestResponse.ok) {
            console.error(`Ingest failed for ${cve.cve_id}`)
            continue
          }
          
          const ingestResult = await ingestResponse.json()

          // Triage
          const triageResponse = await fetch('http://localhost:3001/api/triage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              ingest_id: ingestResult.ingest_id,
              raw_text: cve.raw_text
            })
          })

          if (!triageResponse.ok) {
            console.error(`Triage failed for ${cve.cve_id}`)
            continue
          }

          successCount++
        } catch (err) {
          console.error(`Error processing ${cve.cve_id}:`, err)
        }
      }

      if (successCount === 0) {
        throw new Error('Failed to process any CVEs')
      }

      // Success - notify parent and close
      console.log(`Successfully processed ${successCount}/${cveData.length} CVE(s)`)
      onAnalyze()
      onClose()
    } catch (err) {
      setError(err.message || 'Analysis failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="upload-panel-overlay">
      <div className="upload-panel">
        <div className="upload-panel-header">
          <h2>📤 Upload CVE Data</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="upload-method-tabs">
          <button
            className={`method-tab ${uploadMethod === 'excel' ? 'active' : ''}`}
            onClick={() => setUploadMethod('excel')}
          >
            📊 Excel Upload
          </button>
          <button
            className={`method-tab ${uploadMethod === 'manual' ? 'active' : ''}`}
            onClick={() => setUploadMethod('manual')}
          >
            ✍️ Manual Entry
          </button>
        </div>

        <div className="upload-panel-content">
          {uploadMethod === 'excel' ? (
            <div className="excel-upload-section">
              <div className="upload-instructions">
                <h3>Upload Excel or CSV File</h3>
                <p>Supported formats: .xlsx, .xls, .csv</p>
                <p className="upload-hint">
                  <strong>Expected columns:</strong> CVE_ID, Description, CVSS_Score, Severity, Vendor, Product, Version_Range, Attack_Vector, Exploitability
                </p>
                <p className="upload-hint-small">
                  (Column names are case-insensitive and flexible)
                </p>
              </div>

              <div className="file-upload-area">
                <input
                  type="file"
                  id="file-input"
                  accept=".xlsx,.xls,.csv"
                  onChange={handleFileChange}
                  className="file-input-hidden"
                />
                <label htmlFor="file-input" className="file-upload-label">
                  <div className="upload-icon">📁</div>
                  <div className="upload-text">
                    {file ? file.name : 'Click to browse or drag file here'}
                  </div>
                  <div className="upload-subtext">
                    {file ? `${(file.size / 1024).toFixed(2)} KB` : 'Max file size: 10MB'}
                  </div>
                </label>
              </div>

              {parsePreview && (
                <div className="parse-preview">
                  <h4>📋 File Preview</h4>
                  <p><strong>Rows found:</strong> {parsePreview.rowCount}</p>
                  <p><strong>Columns:</strong> {parsePreview.columns.join(', ')}</p>
                  <div className="preview-sample">
                    <strong>First row sample:</strong>
                    <pre>{JSON.stringify(parsePreview.sample, null, 2)}</pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="manual-entry-section">
              <div className="form-grid">
                <div className="form-group">
                  <label>CVE ID (Optional)</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="CVE-2024-XXXX"
                    value={formData.cve_id}
                    onChange={(e) => handleFormChange('cve_id', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label>CVSS Score *</label>
                  <input
                    type="number"
                    className="input"
                    placeholder="0.0 - 10.0"
                    min="0"
                    max="10"
                    step="0.1"
                    value={formData.cvss_score}
                    onChange={(e) => handleFormChange('cvss_score', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label>Severity</label>
                  <select
                    className="input"
                    value={formData.severity}
                    onChange={(e) => handleFormChange('severity', e.target.value)}
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>Attack Vector</label>
                  <select
                    className="input"
                    value={formData.attack_vector}
                    onChange={(e) => handleFormChange('attack_vector', e.target.value)}
                  >
                    <option value="Network">Network</option>
                    <option value="Adjacent">Adjacent</option>
                    <option value="Local">Local</option>
                    <option value="Physical">Physical</option>
                  </select>
                </div>

                <div className="form-group full-width">
                  <label>Vendor</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g., Apache, Microsoft, Linux"
                    value={formData.vendor}
                    onChange={(e) => handleFormChange('vendor', e.target.value)}
                  />
                </div>

                <div className="form-group full-width">
                  <label>Product</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g., Log4j, Windows Server, Kernel"
                    value={formData.product}
                    onChange={(e) => handleFormChange('product', e.target.value)}
                  />
                </div>

                <div className="form-group full-width">
                  <label>Version Range</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g., 2.0 to 2.14.1"
                    value={formData.version_range}
                    onChange={(e) => handleFormChange('version_range', e.target.value)}
                  />
                </div>

                <div className="form-group full-width">
                  <label>Description *</label>
                  <textarea
                    className="input"
                    rows="4"
                    placeholder="Describe the vulnerability, its impact, and exploitation method..."
                    value={formData.description}
                    onChange={(e) => handleFormChange('description', e.target.value)}
                  />
                </div>

                <div className="form-group full-width">
                  <label>Exploitability</label>
                  <select
                    className="input"
                    value={formData.exploitability}
                    onChange={(e) => handleFormChange('exploitability', e.target.value)}
                  >
                    <option value="Active exploitation in wild">Active exploitation in wild</option>
                    <option value="PoC public">PoC public</option>
                    <option value="No known exploit">No known exploit</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="upload-error">
              <span className="error-icon">⚠️</span>
              {error}
            </div>
          )}
        </div>

        <div className="upload-panel-footer">
          <button className="btn btn-secondary" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={handleAnalyze}
            disabled={loading || (uploadMethod === 'excel' && !file)}
          >
            {loading ? (
              <>
                <span className="spinner-small"></span>
                Analyzing...
              </>
            ) : (
              <>
                🔍 Analyze with watsonx.ai
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}

export default UploadPanel

// Made with Bob
