/**
 * POST /api/qa
 * Run IBM Bob QA checks on triage output
 * This is the QA gate that validates all triage results
 * Now with AI-powered threat detection!
 */

import express from 'express';
import { cveStore } from '../models/cveRecord.js';
import { createIBMBob } from '../services/ibmBob.js';
import { watsonxClient } from '../services/watsonx.js';

const router = express.Router();

// Create IBM Bob instance with watsonx client for AI-powered detection
const ibmBob = createIBMBob(watsonxClient);

router.post('/', async (req, res, next) => {
  try {
    const { triage_output, raw_text, ingest_id } = req.body;

    // Validation
    if (!triage_output) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'triage_output is required'
      });
    }

    if (!raw_text) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'raw_text is required for obfuscation detection'
      });
    }

    console.log(`[IBM Bob] Starting QA checks for ${triage_output.cve_id}...`);

    // Run IBM Bob QA engine
    const qaReport = await ibmBob.runQA(triage_output, raw_text);

    console.log(`[IBM Bob] QA Status: ${qaReport.qa_status}`);
    console.log(`[IBM Bob] Tests: ${qaReport.passed} passed, ${qaReport.failed} failed, ${qaReport.warnings} warnings`);
    console.log(`[IBM Bob] Execution time: ${qaReport.execution_time_ms}ms`);

    // Log CHECK-A results (AI-powered threat detection)
    const checkA = qaReport.mandatory_checks['CHECK-A'];
    if (checkA && checkA.data) {
      console.log(`[IBM Bob CHECK-A] Detection method: ${checkA.data.detection_method}`);
      
      if (checkA.data.ai_analysis) {
        const ai = checkA.data.ai_analysis;
        console.log(`[IBM Bob CHECK-A] AI Threat Level: ${ai.threat_level} (confidence: ${(ai.confidence * 100).toFixed(1)}%)`);
        console.log(`[IBM Bob CHECK-A] Obfuscation techniques: ${ai.obfuscation_techniques.length}`);
        console.log(`[IBM Bob CHECK-A] Threat indicators: ${ai.threat_indicators.length}`);
      }
      
      if (checkA.data.pattern_detected_count > 0) {
        console.log(`[IBM Bob CHECK-A] Pattern matching detected ${checkA.data.pattern_detected_count} obfuscation(s)`);
      }
      
      if (checkA.data.missed > 0) {
        console.warn(`[IBM Bob CHECK-A] ⚠️  Missed ${checkA.data.missed} obfuscation(s)`);
      }
    }

    // Update CVE record if ingest_id provided
    if (ingest_id) {
      const cveRecord = cveStore.get(ingest_id);
      if (cveRecord) {
        cveRecord.qa_status = qaReport.qa_status;
        cveRecord.qa_report = qaReport;
        cveRecord.qa_completed_at = new Date().toISOString();
        cveStore.set(ingest_id, cveRecord);
      }
    }

    // Determine next step based on QA status
    let nextStep;
    if (qaReport.qa_status === 'REJECTED') {
      nextStep = 'CVE REJECTED - Reparse required. Do not proceed to actions or report generation.';
    } else if (qaReport.qa_status === 'APPROVED_WITH_WARNINGS') {
      nextStep = 'CVE APPROVED WITH WARNINGS - Human review recommended. Can proceed to POST /api/actions if CVSS >= 9.0';
    } else {
      nextStep = 'CVE APPROVED - Ready for POST /api/actions (if CVSS >= 9.0) and POST /api/report';
    }

    // Response
    res.json({
      ...qaReport,
      cve_id: triage_output.cve_id,
      ingest_id: ingest_id || null,
      next_step: nextStep,
      bob_stats: ibmBob.getStats()
    });

  } catch (error) {
    console.error('[IBM Bob] QA Error:', error.message);
    next(error);
  }
});

// Get IBM Bob statistics
router.get('/stats', (req, res) => {
  const stats = ibmBob.getStats();
  
  if (!stats) {
    return res.json({
      message: 'No QA data available yet',
      total_cves_tested: 0
    });
  }

  res.json(stats);
});

export default router;

// Made with Bob
