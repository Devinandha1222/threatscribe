/**
 * POST /api/ingest
 * Accept raw CVE text and store it for triage
 */

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { cveStore, CVERecord } from '../models/cveRecord.js';
import { detectObfuscation } from '../services/obfuscationDetector.js';

const router = express.Router();

router.post('/', async (req, res, next) => {
  try {
    const { raw_text, source } = req.body;

    // Validation
    if (!raw_text || typeof raw_text !== 'string') {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'raw_text is required and must be a string'
      });
    }

    if (!source) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'source is required (nvd, vendor, or osint)'
      });
    }

    // Generate ingest ID
    const ingestId = uuidv4();
    const ingestedAt = new Date().toISOString();

    // Pre-scan for obfuscation (IBM Bob checkpoint)
    const obfuscationFlags = detectObfuscation(raw_text, 'raw_text');
    const suspiciousCharsDetected = obfuscationFlags.length > 0;

    // Create CVE record
    const cveRecord = new CVERecord({
      ingest_id: ingestId,
      raw_text: raw_text,
      source: source,
      ingested_at: ingestedAt,
      suspicious_chars_detected: suspiciousCharsDetected
    });

    // Store in memory
    cveStore.set(ingestId, cveRecord);

    // Log IBM Bob pre-scan
    if (suspiciousCharsDetected) {
      console.log(`[IBM Bob Pre-Scan] Detected ${obfuscationFlags.length} suspicious character(s) in ${ingestId}`);
    }

    // Response
    res.status(201).json({
      ingest_id: ingestId,
      status: 'queued',
      char_count: raw_text.length,
      suspicious_chars_detected: suspiciousCharsDetected,
      obfuscation_preview: suspiciousCharsDetected ? obfuscationFlags.slice(0, 3) : [],
      ingested_at: ingestedAt,
      next_step: 'POST /api/triage with ingest_id'
    });

  } catch (error) {
    next(error);
  }
});

// Get all ingested CVEs
router.get('/', (req, res) => {
  const allCVEs = cveStore.getAll();
  const stats = cveStore.getStats();

  res.json({
    total: allCVEs.length,
    stats: stats,
    cves: allCVEs.map(cve => cve.getSummary())
  });
});

// Get specific CVE by ingest_id
router.get('/:ingestId', (req, res) => {
  const { ingestId } = req.params;
  const cve = cveStore.get(ingestId);

  if (!cve) {
    return res.status(404).json({
      error: 'NotFound',
      message: `CVE with ingest_id ${ingestId} not found`
    });
  }

  res.json(cve.toJSON());
});

export default router;

// Made with Bob
