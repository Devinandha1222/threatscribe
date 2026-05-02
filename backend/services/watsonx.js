/**
 * IBM watsonx.ai Service
 * Handles CVE triage using IBM watsonx.ai LLM
 * Supports both demo mode (mock responses) and production mode (real API calls)
 */

import dotenv from 'dotenv';
dotenv.config();

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * System prompt for watsonx.ai
 * Sent with every triage request
 */
const SYSTEM_PROMPT = `You are ThreatScribe, an intelligent cybersecurity analyst assistant powered by IBM watsonx.ai.

Your mission: Help SOC analysts detect, triage, and respond to critical CVEs and security threats faster — turning raw threat data into QA-verified, actionable intelligence in under 8 minutes.

Your capabilities:
1. Parse and classify CVE advisories from NVD, vendor bulletins, and OSINT feeds
2. Extract CVSS scores, affected systems, attack vectors, and remediation steps with high accuracy
3. Detect character-level anomalies — including obfuscation patterns such as '0' used in place of 'O', '1' in place of 'l', and similar substitutions commonly used by attackers to evade detection
4. Map threats automatically to MITRE ATT&CK tactics and techniques
5. Generate structured incident reports, remediation runbooks, and Jira ticket drafts
6. Trigger and coordinate post-detection response actions

Your tone: Precise, technical, and efficient. Every response should be structured, actionable, and audit-ready.

Output format: Always respond in valid JSON only. No markdown code fences. No preamble. No explanation outside the JSON object.

You never guess. If confidence is below 0.85, set triage_confidence below 0.85 and include a "human_review_required": true field.

IBM Bob QA gate: All detection rules and patch scripts you generate must include "qa_status": "PENDING". Never set qa_status to APPROVED yourself — that is IBM Bob's role.`;

/**
 * Triage user prompt template
 */
function buildTriagePrompt(rawText, source, ingestedAt) {
  return `Perform full CVE triage on the following advisory. Return a single JSON object matching the schema exactly.

RAW ADVISORY:
${rawText}

SOURCE: ${source}
INGESTED AT: ${ingestedAt}

Return JSON with fields: cve_id, cvss_score, cvss_vector, affected_products, attack_vector, attack_complexity, privileges_required, user_interaction, description, severity, priority_score, exploitability, recommended_action, mitre (tactic/technique_id/technique_name/sub_technique_id), typo_flags (array), test_cases (array of at least 3), qa_status ("PENDING"), triage_confidence.`;
}

/**
 * Report generation prompt template
 */
function buildReportPrompt(triageJson, qaJson) {
  return `Generate three deliverables for this QA-approved CVE triage output. Return a single JSON object with keys: incident_report (markdown string), runbook (markdown string), jira_ticket (JSON object).

TRIAGE OUTPUT:
${JSON.stringify(triageJson, null, 2)}

QA REPORT:
${JSON.stringify(qaJson, null, 2)}

Rules:
- Executive summary: 3 sentences max, zero jargon, written for non-technical leadership
- If typo_flags is non-empty, include a dedicated "Obfuscation findings" section in the incident report — this is mandatory
- Runbook must include rollback procedure and verification steps
- Jira ticket must include acceptance_criteria and due_date_hint based on severity`;
}

/**
 * Watsonx.ai Client
 */
export class WatsonxClient {
  constructor() {
    this.demoMode = process.env.DEMO_MODE === 'true';
    this.apiKey = process.env.WATSONX_API_KEY;
    this.projectId = process.env.WATSONX_PROJECT_ID;
    this.url = process.env.WATSONX_URL;
    this.model = process.env.WATSONX_MODEL || 'ibm/granite-13b-instruct-v2';

    // Load mock data for demo mode
    if (this.demoMode) {
      try {
        const mockDataPath = join(__dirname, '../data/mockCVEs.json');
        this.mockData = JSON.parse(readFileSync(mockDataPath, 'utf-8'));
      } catch (error) {
        console.warn('Mock CVE data not loaded, will use fallback responses');
        this.mockData = null;
      }
    }
  }

  /**
   * Simulate realistic API delay
   */
  async simulateDelay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Perform CVE triage
   */
  async triage(rawText, source, ingestedAt) {
    if (this.demoMode) {
      return this.mockTriage(rawText, source, ingestedAt);
    }

    // Real watsonx.ai API call would go here
    return this.realTriage(rawText, source, ingestedAt);
  }

  /**
   * Mock triage for demo mode
   */
  async mockTriage(rawText, source, ingestedAt) {
    // Simulate realistic processing time
    await this.simulateDelay(800);

    // Try to match against mock data
    if (this.mockData && this.mockData.cves) {
      // Check if raw text contains any known CVE IDs from mock data
      for (const mockCve of this.mockData.cves) {
        if (rawText.includes(mockCve.cve_id) || 
            rawText.toLowerCase().includes(mockCve.raw_text.toLowerCase().substring(0, 20))) {
          return {
            ...mockCve.triage_output,
            watsonx_model: this.model,
            triage_completed_at: new Date().toISOString()
          };
        }
      }
    }

    // Fallback: generate a basic response
    return this.generateFallbackTriage(rawText, source);
  }

  /**
   * Generate fallback triage response
   */
  generateFallbackTriage(rawText, source) {
    // Extract CVE ID if present
    const cveMatch = rawText.match(/CVE-\d{4}-\d{4,}/i);
    const cveId = cveMatch ? cveMatch[0].toUpperCase() : 'CVE-2024-UNKNOWN';

    // Determine severity based on keywords
    let severity = 'MEDIUM';
    let cvssScore = 5.5;
    
    if (rawText.toLowerCase().includes('critical') || 
        rawText.toLowerCase().includes('remote code execution')) {
      severity = 'CRITICAL';
      cvssScore = 9.8;
    } else if (rawText.toLowerCase().includes('high')) {
      severity = 'HIGH';
      cvssScore = 7.5;
    }

    return {
      cve_id: cveId,
      cvss_score: cvssScore,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affected_products: [
        {
          vendor: 'Unknown',
          product: 'Unknown',
          version_range: 'Unknown'
        }
      ],
      attack_vector: 'Network',
      attack_complexity: 'Low',
      privileges_required: 'None',
      user_interaction: 'None',
      description: `${cveId} vulnerability detected in the provided advisory. Manual review recommended for complete analysis.`,
      severity: severity,
      priority_score: cvssScore >= 9.0 ? 95 : cvssScore >= 7.0 ? 75 : 50,
      exploitability: 'Unknown',
      recommended_action: severity === 'CRITICAL' ? 'Immediate patch' : 'Patch within 24h',
      mitre: {
        tactic: 'Initial Access',
        technique_id: 'T1190',
        technique_name: 'Exploit Public-Facing Application',
        sub_technique_id: null
      },
      typo_flags: [],
      test_cases: [
        {
          id: 'TC001',
          description: 'Verify CVE ID extraction',
          expected: cveId,
          input: rawText.substring(0, 100)
        },
        {
          id: 'TC002',
          description: 'Verify severity classification',
          expected: severity,
          input: 'severity_field'
        },
        {
          id: 'TC003',
          description: 'Verify CVSS score',
          expected: cvssScore.toString(),
          input: 'cvss_score_field'
        }
      ],
      qa_status: 'PENDING',
      triage_confidence: 0.75,
      watsonx_model: this.model,
      human_review_required: true,
      triage_completed_at: new Date().toISOString()
    };
  }

  /**
   * Get IAM access token from API key
   */
  async getIAMToken() {
    try {
      const response = await fetch('https://iam.cloud.ibm.com/identity/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: `grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=${this.apiKey}`
      });

      if (!response.ok) {
        throw new Error(`IAM token error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data.access_token;
    } catch (error) {
      console.error('IAM token error:', error);
      throw new Error(`Failed to get IAM token: ${error.message}`);
    }
  }

  /**
   * Real watsonx.ai API call (production mode)
   */
  async realTriage(rawText, source, ingestedAt) {
    if (!this.apiKey || !this.projectId) {
      throw new Error('Watsonx.ai credentials not configured. Set WATSONX_API_KEY and WATSONX_PROJECT_ID in .env');
    }

    try {
      // Get IAM access token
      console.log('[Watsonx] Getting IAM access token...');
      const accessToken = await this.getIAMToken();
      console.log('[Watsonx] IAM token obtained successfully');

      const prompt = buildTriagePrompt(rawText, source, ingestedAt);
      
      // Construct the API request with IAM token
      console.log('[Watsonx] Calling watsonx.ai API...');
      const response = await fetch(`${this.url}/ml/v1/text/generation?version=2023-05-29`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          model_id: this.model,
          input: `${SYSTEM_PROMPT}\n\n${prompt}`,
          parameters: {
            max_new_tokens: 2000,
            temperature: 0.1,
            top_p: 0.95,
            top_k: 50
          },
          project_id: this.projectId
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[Watsonx] API error response:', errorText);
        throw new Error(`Watsonx.ai API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      console.log('[Watsonx] API call successful');
      const generatedText = data.results[0].generated_text;

      // Parse JSON response
      const triageOutput = JSON.parse(generatedText);
      
      return {
        ...triageOutput,
        watsonx_model: this.model,
        triage_completed_at: new Date().toISOString()
      };

    } catch (error) {
      console.error('Watsonx.ai triage error:', error);
      throw new Error(`Triage failed: ${error.message}`);
    }
  }

  /**
   * Generate incident report, runbook, and Jira ticket
   */
  async generateReport(triageOutput, qaReport) {
    if (this.demoMode) {
      return this.mockGenerateReport(triageOutput, qaReport);
    }

    return this.realGenerateReport(triageOutput, qaReport);
  }

  /**
   * Mock report generation
   */
  async mockGenerateReport(triageOutput, qaReport) {
    // Simulate processing time
    await this.simulateDelay(600);

    const hasObfuscation = triageOutput.typo_flags && triageOutput.typo_flags.length > 0;

    const incidentReport = `# Incident Report: ${triageOutput.cve_id}

## Executive Summary

${triageOutput.description} This ${triageOutput.severity.toLowerCase()}-severity vulnerability requires ${triageOutput.recommended_action.toLowerCase()}. Immediate action is recommended to prevent potential exploitation.

## Technical Details

**CVE ID:** ${triageOutput.cve_id}  
**CVSS Score:** ${triageOutput.cvss_score} (${triageOutput.severity})  
**Attack Vector:** ${triageOutput.attack_vector}  
**Attack Complexity:** ${triageOutput.attack_complexity}  
**Privileges Required:** ${triageOutput.privileges_required}  
**User Interaction:** ${triageOutput.user_interaction}

**Affected Products:**
${triageOutput.affected_products.map(p => `- ${p.vendor} ${p.product} ${p.version_range}`).join('\n')}

**Exploitability:** ${triageOutput.exploitability}

${hasObfuscation ? `## Obfuscation Findings

**⚠️ Character-level obfuscation detected by IBM Bob QA engine:**

${triageOutput.typo_flags.map(flag => 
  `- Position ${flag.position} in "${flag.field}": Character '${flag.original}' suspected to be '${flag.suspected_intent}' (${flag.risk}, confidence: ${(flag.confidence * 100).toFixed(1)}%)`
).join('\n')}

This obfuscation pattern suggests potential evasion techniques. The vulnerability description may have been intentionally altered to bypass automated detection systems.
` : ''}

## MITRE ATT&CK Context

**Tactic:** ${triageOutput.mitre.tactic}  
**Technique:** ${triageOutput.mitre.technique_id} - ${triageOutput.mitre.technique_name}

## Timeline

- **Ingested:** ${triageOutput.ingested_at || 'N/A'}
- **Triage Completed:** ${triageOutput.triage_completed_at}
- **QA Status:** ${qaReport.qa_status}
- **Report Generated:** ${new Date().toISOString()}

## Recommended Immediate Actions

1. **Patch affected systems** - Apply vendor patches immediately for ${triageOutput.severity} severity
2. **Network segmentation** - Isolate affected systems until patched
3. **Monitor for exploitation** - Enable enhanced logging and alerting
4. **Verify patch deployment** - Run IBM Bob validation tests post-patch
5. **Update threat intelligence** - Add indicators to SIEM and EDR platforms

## Compliance Notes

This incident requires documentation for SOC 2, ISO 27001, and NIST CSF compliance frameworks. Retain all logs and evidence for minimum 90 days.

---
*Generated by ThreatScribe AI + IBM watsonx.ai | QA Validated by IBM Bob*`;

    const runbook = `# Remediation Runbook: ${triageOutput.cve_id}

## Pre-conditions

- [ ] Backup all affected systems
- [ ] Notify change management team
- [ ] Schedule maintenance window
- [ ] Prepare rollback plan

## Containment Steps

1. **Identify affected systems**
   \`\`\`bash
   # Scan for vulnerable versions
   nmap -sV --script vuln <target_range>
   \`\`\`

2. **Isolate affected systems**
   - Apply network ACLs
   - Update firewall rules
   - Enable enhanced monitoring

## Patch Steps

1. **Download vendor patch**
   - Verify patch authenticity
   - Test in staging environment

2. **Apply patch**
   \`\`\`bash
   # Example patch command (adjust for your environment)
   sudo apt-get update && sudo apt-get install <package>
   \`\`\`

3. **Verify patch installation**
   \`\`\`bash
   # Check version
   <package> --version
   \`\`\`

## Rollback Procedure

If issues occur:

1. Restore from backup
2. Revert network changes
3. Document rollback reason
4. Escalate to vendor support

## Verification Steps

- [ ] Run IBM Bob validation tests
- [ ] Verify service functionality
- [ ] Check system logs for errors
- [ ] Confirm vulnerability is remediated

## Estimated Time

- Preparation: 30 minutes
- Execution: 1-2 hours
- Verification: 30 minutes
- **Total: 2-3 hours**

---
*Generated by ThreatScribe AI*`;

    const jiraTicket = {
      summary: `[${triageOutput.severity}] ${triageOutput.cve_id} - ${triageOutput.description.substring(0, 80)}`,
      priority: triageOutput.severity === 'CRITICAL' ? 'Highest' : 
                triageOutput.severity === 'HIGH' ? 'High' : 'Medium',
      labels: [
        'security',
        'cve',
        triageOutput.severity.toLowerCase(),
        triageOutput.mitre.tactic.toLowerCase().replace(' ', '-')
      ],
      assignee_hint: 'security-team',
      description: `## CVE Details

**CVE ID:** ${triageOutput.cve_id}
**CVSS Score:** ${triageOutput.cvss_score}
**Severity:** ${triageOutput.severity}

${triageOutput.description}

## Affected Systems

${triageOutput.affected_products.map(p => `- ${p.vendor} ${p.product} ${p.version_range}`).join('\n')}

## Action Required

${triageOutput.recommended_action}

${hasObfuscation ? `## ⚠️ Obfuscation Alert

IBM Bob detected character-level obfuscation in this CVE. Review the full incident report for details.` : ''}

## Resources

- Incident Report: [Link to report]
- Remediation Runbook: [Link to runbook]
- MITRE ATT&CK: ${triageOutput.mitre.technique_id}`,
      acceptance_criteria: [
        'All affected systems identified',
        'Patches applied and verified',
        'IBM Bob validation tests passed',
        'No residual vulnerabilities detected',
        'Documentation updated'
      ],
      due_date_hint: triageOutput.severity === 'CRITICAL' ? '24 hours' :
                     triageOutput.severity === 'HIGH' ? '72 hours' : '7 days'
    };

    return {
      incident_report: incidentReport,
      runbook: runbook,
      jira_ticket: jiraTicket,
      generated_at: new Date().toISOString(),
      generated_by: 'ThreatScribe + watsonx.ai'
    };
  }

  /**
   * Real report generation (production mode)
   */
  async realGenerateReport(triageOutput, qaReport) {
    if (!this.apiKey || !this.projectId) {
      throw new Error('Watsonx.ai credentials not configured');
    }

    try {
      const prompt = buildReportPrompt(triageOutput, qaReport);
      
      const response = await fetch(`${this.url}/ml/v1/text/generation?version=2023-05-29`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          model_id: this.model,
          input: `${SYSTEM_PROMPT}\n\n${prompt}`,
          parameters: {
            max_new_tokens: 3000,
            temperature: 0.2,
            top_p: 0.95
          },
          project_id: this.projectId
        })
      });

      if (!response.ok) {
        throw new Error(`Watsonx.ai API error: ${response.status}`);
      }

      const data = await response.json();
      const generatedText = data.results[0].generated_text;
      const reportData = JSON.parse(generatedText);

      return {
        ...reportData,
        generated_at: new Date().toISOString(),
        generated_by: 'ThreatScribe + watsonx.ai'
      };

    } catch (error) {
      console.error('Watsonx.ai report generation error:', error);
      throw new Error(`Report generation failed: ${error.message}`);
    }
  }
}

// Export singleton instance
export const watsonxClient = new WatsonxClient();

export default watsonxClient;

// Made with Bob
