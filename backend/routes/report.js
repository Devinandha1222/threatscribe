/**
 * POST /api/report
 * Generate incident report, remediation runbook, and Jira ticket
 */

import express from 'express';
import { cveStore } from '../models/cveRecord.js';
import { watsonxClient } from '../services/watsonx.js';

const router = express.Router();

router.post('/', async (req, res, next) => {
  try {
    const { triage_output, qa_report, ingest_id } = req.body;

    // Validation
    if (!triage_output) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'triage_output is required'
      });
    }

    if (!qa_report) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'qa_report is required'
      });
    }

    // QA Gate: Block if CVE was rejected
    if (qa_report.qa_status === 'REJECTED') {
      return res.status(409).json({
        error: 'QAGateBlocked',
        message: 'Report generation blocked: CVE failed QA validation',
        qa_status: qa_report.qa_status,
        qa_report: qa_report,
        recommendation: 'Reparse CVE and fix issues before generating report'
      });
    }

    console.log(`[Report] Generating deliverables for ${triage_output.cve_id}...`);
    console.log(`[Report] QA Status: ${qa_report.qa_status}`);

    // Generate all three deliverables
    const reportData = await watsonxClient.generateReport(triage_output, qa_report);

    console.log(`[Report] Generated at ${reportData.generated_at}`);
    console.log(`[Report] Incident report: ${reportData.incident_report.length} chars`);
    console.log(`[Report] Runbook: ${reportData.runbook.length} chars`);
    console.log(`[Report] Jira ticket: ${reportData.jira_ticket.summary}`);

    // Update CVE record if ingest_id provided
    if (ingest_id) {
      const cveRecord = cveStore.get(ingest_id);
      if (cveRecord) {
        cveRecord.incident_report = reportData.incident_report;
        cveRecord.runbook = reportData.runbook;
        cveRecord.jira_ticket = reportData.jira_ticket;
        cveRecord.report_generated_at = reportData.generated_at;
        cveStore.set(ingest_id, cveRecord);
      }
    }

    // Response
    res.json({
      ...reportData,
      cve_id: triage_output.cve_id,
      ingest_id: ingest_id || null,
      qa_status: qa_report.qa_status,
      deliverables: {
        incident_report: {
          format: 'markdown',
          length: reportData.incident_report.length,
          sections: [
            'Executive Summary',
            'Technical Details',
            triage_output.typo_flags?.length > 0 ? 'Obfuscation Findings' : null,
            'MITRE ATT&CK Context',
            'Timeline',
            'Recommended Actions',
            'Compliance Notes'
          ].filter(Boolean)
        },
        runbook: {
          format: 'markdown',
          length: reportData.runbook.length,
          sections: [
            'Pre-conditions',
            'Containment Steps',
            'Patch Steps',
            'Rollback Procedure',
            'Verification Steps'
          ]
        },
        jira_ticket: {
          format: 'json',
          priority: reportData.jira_ticket.priority,
          labels: reportData.jira_ticket.labels,
          due_date_hint: reportData.jira_ticket.due_date_hint
        }
      }
    });

  } catch (error) {
    console.error('[Report] Error:', error.message);
    next(error);
  }
});

export default router;

// Made with Bob
