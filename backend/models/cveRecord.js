/**
 * CVE Record Schema
 * Defines the structure for CVE data throughout the ThreatScribe pipeline
 */

export class CVERecord {
  constructor(data = {}) {
    this.ingest_id = data.ingest_id || null;
    this.cve_id = data.cve_id || null;
    this.raw_text = data.raw_text || '';
    this.source = data.source || 'unknown';
    this.ingested_at = data.ingested_at || new Date().toISOString();
    
    // Triage output
    this.cvss_score = data.cvss_score || null;
    this.cvss_vector = data.cvss_vector || null;
    this.affected_products = data.affected_products || [];
    this.attack_vector = data.attack_vector || null;
    this.attack_complexity = data.attack_complexity || null;
    this.privileges_required = data.privileges_required || null;
    this.user_interaction = data.user_interaction || null;
    this.description = data.description || '';
    this.severity = data.severity || null;
    this.priority_score = data.priority_score || 0;
    this.exploitability = data.exploitability || null;
    this.recommended_action = data.recommended_action || null;
    
    // MITRE ATT&CK mapping
    this.mitre = data.mitre || {
      tactic: null,
      technique_id: null,
      technique_name: null,
      sub_technique_id: null
    };
    
    // Obfuscation detection
    this.typo_flags = data.typo_flags || [];
    this.suspicious_chars_detected = data.suspicious_chars_detected || false;
    
    // Testing
    this.test_cases = data.test_cases || [];
    
    // QA status
    this.qa_status = data.qa_status || 'PENDING';
    this.qa_report = data.qa_report || null;
    
    // Metadata
    this.triage_confidence = data.triage_confidence || 0;
    this.watsonx_model = data.watsonx_model || null;
    this.human_review_required = data.human_review_required || false;
    
    // Action chain results
    this.action_results = data.action_results || null;
    
    // Generated deliverables
    this.incident_report = data.incident_report || null;
    this.runbook = data.runbook || null;
    this.jira_ticket = data.jira_ticket || null;
    
    // Timestamps
    this.triage_completed_at = data.triage_completed_at || null;
    this.qa_completed_at = data.qa_completed_at || null;
    this.actions_completed_at = data.actions_completed_at || null;
    this.report_generated_at = data.report_generated_at || null;
  }

  /**
   * Validate required fields for triage
   */
  isValidForTriage() {
    return !!(this.ingest_id && this.raw_text && this.source);
  }

  /**
   * Check if CVE is ready for QA
   */
  isReadyForQA() {
    return !!(
      this.cve_id &&
      this.cvss_score !== null &&
      this.severity &&
      this.triage_completed_at
    );
  }

  /**
   * Check if CVE is approved for actions
   */
  isApprovedForActions() {
    return this.qa_status === 'APPROVED' || this.qa_status === 'APPROVED_WITH_WARNINGS';
  }

  /**
   * Check if CVE is critical severity
   */
  isCritical() {
    return this.severity === 'CRITICAL' || this.cvss_score >= 9.0;
  }

  /**
   * Get summary for display
   */
  getSummary() {
    return {
      cve_id: this.cve_id,
      severity: this.severity,
      cvss_score: this.cvss_score,
      qa_status: this.qa_status,
      has_obfuscation: this.typo_flags.length > 0,
      ingested_at: this.ingested_at
    };
  }

  /**
   * Convert to JSON
   */
  toJSON() {
    return { ...this };
  }
}

/**
 * In-memory CVE store
 */
export class CVEStore {
  constructor() {
    this.records = new Map();
  }

  /**
   * Add or update a CVE record
   */
  set(ingestId, record) {
    if (!(record instanceof CVERecord)) {
      record = new CVERecord(record);
    }
    this.records.set(ingestId, record);
    return record;
  }

  /**
   * Get a CVE record by ingest ID
   */
  get(ingestId) {
    return this.records.get(ingestId);
  }

  /**
   * Get all CVE records
   */
  getAll() {
    return Array.from(this.records.values());
  }

  /**
   * Get CVEs by severity
   */
  getBySeverity(severity) {
    return this.getAll().filter(cve => cve.severity === severity);
  }

  /**
   * Get CVEs by QA status
   */
  getByQAStatus(status) {
    return this.getAll().filter(cve => cve.qa_status === status);
  }

  /**
   * Get CVEs with obfuscation
   */
  getWithObfuscation() {
    return this.getAll().filter(cve => cve.typo_flags.length > 0);
  }

  /**
   * Get statistics
   */
  getStats() {
    const all = this.getAll();
    return {
      total: all.length,
      critical: all.filter(c => c.severity === 'CRITICAL').length,
      high: all.filter(c => c.severity === 'HIGH').length,
      medium: all.filter(c => c.severity === 'MEDIUM').length,
      low: all.filter(c => c.severity === 'LOW').length,
      with_obfuscation: all.filter(c => c.typo_flags.length > 0).length,
      qa_approved: all.filter(c => c.qa_status === 'APPROVED' || c.qa_status === 'APPROVED_WITH_WARNINGS').length,
      qa_rejected: all.filter(c => c.qa_status === 'REJECTED').length,
      qa_pending: all.filter(c => c.qa_status === 'PENDING').length
    };
  }

  /**
   * Clear all records
   */
  clear() {
    this.records.clear();
  }

  /**
   * Delete a record
   */
  delete(ingestId) {
    return this.records.delete(ingestId);
  }
}

// Export singleton instance
export const cveStore = new CVEStore();

// Made with Bob
