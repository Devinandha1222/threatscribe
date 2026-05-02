/**
 * POST /api/actions
 * Execute 4-lane parallel action chain after QA approval
 */

import express from 'express';
import { cveStore } from '../models/cveRecord.js';
import { executeActionChain } from '../services/actionChain.js';

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
        message: 'Action chain blocked: CVE failed QA validation',
        qa_status: qa_report.qa_status,
        qa_report: qa_report,
        recommendation: 'Reparse CVE and fix issues before proceeding'
      });
    }

    console.log(`[Action Chain] Starting 4-lane execution for ${triage_output.cve_id}...`);
    console.log(`[Action Chain] QA Status: ${qa_report.qa_status}`);

    // Execute all 4 lanes in parallel
    const actionResults = await executeActionChain(triage_output, qa_report);

    console.log(`[Action Chain] Complete in ${actionResults.execution_time_ms}ms`);
    console.log(`[Action Chain] Status: ${actionResults.status}`);
    console.log(`[Action Chain] Total artifacts: ${actionResults.summary?.total_artifacts || 0}`);

    // Update CVE record if ingest_id provided
    if (ingest_id) {
      const cveRecord = cveStore.get(ingest_id);
      if (cveRecord) {
        cveRecord.action_results = actionResults;
        cveRecord.actions_completed_at = new Date().toISOString();
        cveStore.set(ingest_id, cveRecord);
      }
    }

    // Response
    res.json({
      ...actionResults,
      cve_id: triage_output.cve_id,
      ingest_id: ingest_id || null,
      next_step: 'POST /api/report to generate incident report, runbook, and Jira ticket'
    });

  } catch (error) {
    console.error('[Action Chain] Error:', error.message);
    next(error);
  }
});

export default router;

// Made with Bob
