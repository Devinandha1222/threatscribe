/**
 * POST /api/triage
 * Run watsonx.ai CVE triage on ingested data
 */

import express from 'express';
import { cveStore } from '../models/cveRecord.js';
import { watsonxClient } from '../services/watsonx.js';

const router = express.Router();

// GET /api/triage - Get all CVE records
router.get('/', async (req, res) => {
  try {
    const allCVEs = cveStore.getAll();
    
    res.json({
      count: allCVEs.length,
      cves: allCVEs
    });
  } catch (error) {
    console.error('[Triage] Error fetching CVEs:', error.message);
    res.status(500).json({
      error: 'InternalServerError',
      message: 'Failed to fetch CVE records'
    });
  }
});

// POST /api/triage - Run watsonx.ai triage
router.post('/', async (req, res, next) => {
  try {
    const { ingest_id, raw_text } = req.body;

    // Validation
    if (!ingest_id && !raw_text) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'Either ingest_id or raw_text is required'
      });
    }

    let cveRecord;
    let textToTriage;
    let source = 'unknown';
    let ingestedAt = new Date().toISOString();

    // Get CVE record if ingest_id provided
    if (ingest_id) {
      cveRecord = cveStore.get(ingest_id);
      
      if (!cveRecord) {
        return res.status(404).json({
          error: 'NotFound',
          message: `CVE with ingest_id ${ingest_id} not found`
        });
      }

      textToTriage = cveRecord.raw_text;
      source = cveRecord.source;
      ingestedAt = cveRecord.ingested_at;
    } else {
      // Direct triage without ingestion
      textToTriage = raw_text;
      source = req.body.source || 'direct';
    }

    console.log(`[Triage] Starting watsonx.ai triage for ${ingest_id || 'direct input'}...`);

    // Call watsonx.ai service
    const triageOutput = await watsonxClient.triage(textToTriage, source, ingestedAt);

    // Update CVE record if exists
    if (cveRecord) {
      Object.assign(cveRecord, triageOutput);
      cveRecord.triage_completed_at = new Date().toISOString();
      cveStore.set(ingest_id, cveRecord);
    }

    console.log(`[Triage] Complete: ${triageOutput.cve_id} - ${triageOutput.severity} (CVSS: ${triageOutput.cvss_score})`);

    // Response
    res.json({
      ...triageOutput,
      ingest_id: ingest_id || null,
      next_step: 'POST /api/qa to run IBM Bob QA checks'
    });

  } catch (error) {
    console.error('[Triage] Error:', error.message);
    next(error);
  }
});

export default router;

// Made with Bob
