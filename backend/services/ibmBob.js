/**
 * IBM Bob QA Engine
 * Automated quality assurance for CVE triage outputs
 *
 * Performs 4 mandatory checks:
 * - CHECK-A: AI-Powered Obfuscation & Threat Detection (uses Watson AI + pattern matching)
 * - CHECK-B: CVSS 3.1 recalculation and validation
 * - CHECK-C: MITRE ATT&CK consistency
 * - CHECK-D: Test coverage completeness
 */

import {
  detectObfuscationInObject,
  compareWithWatsonx,
  generateObfuscationReport
} from './obfuscationDetector.js';
import AIThreatDetector from './aiThreatDetector.js';

/**
 * CVSS 3.1 Base Score Calculation
 * Implements the official CVSS 3.1 specification
 */
class CVSSCalculator {
  constructor() {
    // Attack Vector (AV)
    this.AV = {
      'N': 0.85,  // Network
      'A': 0.62,  // Adjacent
      'L': 0.55,  // Local
      'P': 0.20   // Physical
    };

    // Attack Complexity (AC)
    this.AC = {
      'L': 0.77,  // Low
      'H': 0.44   // High
    };

    // Privileges Required (PR) - depends on Scope
    this.PR = {
      'U': {  // Unchanged scope
        'N': 0.85,  // None
        'L': 0.62,  // Low
        'H': 0.27   // High
      },
      'C': {  // Changed scope
        'N': 0.85,  // None
        'L': 0.68,  // Low
        'H': 0.50   // High
      }
    };

    // User Interaction (UI)
    this.UI = {
      'N': 0.85,  // None
      'R': 0.62   // Required
    };

    // Confidentiality/Integrity/Availability Impact (C/I/A)
    this.Impact = {
      'N': 0.00,  // None
      'L': 0.22,  // Low
      'H': 0.56   // High
    };
  }

  /**
   * Parse CVSS vector string
   * Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
   */
  parseVector(vectorString) {
    const parts = vectorString.split('/');
    const metrics = {};

    for (const part of parts) {
      if (part.includes(':')) {
        const [key, value] = part.split(':');
        metrics[key] = value;
      }
    }

    return {
      AV: metrics.AV || 'N',
      AC: metrics.AC || 'L',
      PR: metrics.PR || 'N',
      UI: metrics.UI || 'N',
      S: metrics.S || 'U',
      C: metrics.C || 'N',
      I: metrics.I || 'N',
      A: metrics.A || 'N'
    };
  }

  /**
   * Calculate CVSS 3.1 Base Score
   */
  calculateBaseScore(vectorString) {
    try {
      const metrics = this.parseVector(vectorString);

      // Get metric values
      const av = this.AV[metrics.AV];
      const ac = this.AC[metrics.AC];
      const pr = this.PR[metrics.S][metrics.PR];
      const ui = this.UI[metrics.UI];
      const scope = metrics.S;
      const c = this.Impact[metrics.C];
      const i = this.Impact[metrics.I];
      const a = this.Impact[metrics.A];

      // Calculate Impact Sub-Score (ISS)
      const iss = 1 - ((1 - c) * (1 - i) * (1 - a));

      // Calculate Impact
      let impact;
      if (scope === 'U') {
        // Unchanged scope
        impact = 6.42 * iss;
      } else {
        // Changed scope
        impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
      }

      // If Impact <= 0, Base Score is 0
      if (impact <= 0) {
        return {
          score: 0.0,
          impact: 0.0,
          exploitability: 0.0,
          metrics: metrics
        };
      }

      // Calculate Exploitability
      const exploitability = 8.22 * av * ac * pr * ui;

      // Calculate Base Score
      let baseScore;
      if (scope === 'U') {
        baseScore = Math.min(impact + exploitability, 10);
      } else {
        baseScore = Math.min(1.08 * (impact + exploitability), 10);
      }

      // Round up to one decimal place
      baseScore = Math.ceil(baseScore * 10) / 10;

      return {
        score: baseScore,
        impact: Math.round(impact * 10) / 10,
        exploitability: Math.round(exploitability * 10) / 10,
        metrics: metrics
      };
    } catch (error) {
      throw new Error(`CVSS calculation failed: ${error.message}`);
    }
  }

  /**
   * Validate CVSS score against vector
   */
  validateScore(vectorString, reportedScore, tolerance = 0.1) {
    const calculated = this.calculateBaseScore(vectorString);
    const difference = Math.abs(calculated.score - reportedScore);

    return {
      valid: difference <= tolerance,
      calculated: calculated.score,
      reported: reportedScore,
      difference: Math.round(difference * 10) / 10,
      details: calculated
    };
  }
}

/**
 * IBM Bob QA Engine
 */
export class IBMBobQA {
  constructor(strictMode = false, watsonxClient = null) {
    this.strictMode = strictMode;
    this.cvssCalculator = new CVSSCalculator();
    this.regressionData = [];
    this.aiDetector = watsonxClient ? new AIThreatDetector(watsonxClient) : null;
  }

  /**
   * Run all QA checks on a triage output
   */
  async runQA(triageOutput, rawText) {
    const startTime = Date.now();
    const results = {
      qa_status: 'PENDING',
      total_tests: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      test_results: [],
      mandatory_checks: {},
      bob_recommendation: '',
      regression_notes: '',
      execution_time_ms: 0
    };

    try {
      // CHECK-A: Obfuscation Detection
      results.mandatory_checks['CHECK-A'] = await this.checkObfuscation(
        triageOutput,
        rawText
      );

      // CHECK-B: CVSS Validation
      results.mandatory_checks['CHECK-B'] = await this.checkCVSS(triageOutput);

      // CHECK-C: MITRE ATT&CK Consistency
      results.mandatory_checks['CHECK-C'] = await this.checkMITRE(triageOutput);

      // CHECK-D: Test Coverage
      results.mandatory_checks['CHECK-D'] = await this.checkTestCoverage(triageOutput);

      // Run watsonx.ai-generated test cases
      if (triageOutput.test_cases && triageOutput.test_cases.length > 0) {
        const testResults = await this.runTestCases(
          triageOutput.test_cases,
          triageOutput
        );
        results.test_results = testResults;
      }

      // Calculate totals
      const checkResults = Object.values(results.mandatory_checks);
      results.total_tests = checkResults.length + results.test_results.length;

      for (const check of checkResults) {
        if (check.result === 'PASS') results.passed++;
        else if (check.result === 'FAIL') results.failed++;
        else if (check.result === 'WARN') results.warnings++;
      }

      for (const test of results.test_results) {
        if (test.passed) results.passed++;
        else results.failed++;
      }

      // Determine QA status
      results.qa_status = this.determineQAStatus(results);
      results.bob_recommendation = this.generateRecommendation(results);
      results.regression_notes = this.analyzeRegressions(triageOutput);

      // Record execution time
      results.execution_time_ms = Date.now() - startTime;

      // Store for regression analysis
      this.regressionData.push({
        cve_id: triageOutput.cve_id,
        timestamp: new Date().toISOString(),
        results: results
      });

    } catch (error) {
      results.qa_status = 'ERROR';
      results.bob_recommendation = `QA execution failed: ${error.message}`;
      results.execution_time_ms = Date.now() - startTime;
    }

    return results;
  }

  /**
   * CHECK-A: AI-Powered Obfuscation & Threat Detection
   * Uses Watson AI for intelligent detection + pattern matching as fallback
   */
  async checkObfuscation(triageOutput, rawText) {
    try {
      let aiAnalysis = null;
      
      // Try AI-powered detection first
      if (this.aiDetector) {
        try {
          aiAnalysis = await this.aiDetector.analyzeThreats(rawText, {
            source: triageOutput.source || 'unknown',
            cve_id: triageOutput.cve_id
          });
        } catch (error) {
          console.warn('AI detection failed, falling back to pattern matching:', error.message);
        }
      }

      // Pattern-based detection (fallback or supplement)
      const detectedInRaw = detectObfuscationInObject({ raw_text: rawText });
      const detectedInTriage = detectObfuscationInObject(triageOutput, [
        'test_cases',
        'qa_status',
        'qa_report'
      ]);

      // Compare with watsonx.ai's typo_flags
      const comparison = compareWithWatsonx(
        [...detectedInRaw, ...detectedInTriage],
        triageOutput.typo_flags || []
      );

      let result = 'PASS';
      let detail = 'Threat detection complete';
      
      // Evaluate AI analysis
      if (aiAnalysis) {
        if (aiAnalysis.threat_level === 'CRITICAL' || aiAnalysis.threat_level === 'HIGH') {
          result = aiAnalysis.requires_human_review ? 'WARN' : 'FAIL';
          detail = `AI detected ${aiAnalysis.threat_level} threat with ${aiAnalysis.obfuscation_techniques.length} obfuscation technique(s)`;
        } else if (aiAnalysis.obfuscation_detected) {
          result = 'WARN';
          detail = `AI detected ${aiAnalysis.obfuscation_techniques.length} obfuscation technique(s)`;
        }
      }

      // Check pattern-based results
      if (comparison.missed > 0 && result === 'PASS') {
        result = this.strictMode ? 'FAIL' : 'WARN';
        detail = `Pattern matching missed ${comparison.missed} obfuscation(s)`;
      }

      return {
        result: result,
        detail: detail,
        data: {
          ai_analysis: aiAnalysis,
          pattern_detected_count: detectedInRaw.length + detectedInTriage.length,
          watsonx_count: (triageOutput.typo_flags || []).length,
          missed: comparison.missed,
          false_positives: comparison.false_positives,
          accuracy: comparison.accuracy,
          obfuscation_report: generateObfuscationReport([...detectedInRaw, ...detectedInTriage]),
          detection_method: aiAnalysis ? 'ai_powered_with_pattern_fallback' : 'pattern_only'
        }
      };
    } catch (error) {
      return {
        result: 'FAIL',
        detail: `Threat detection check failed: ${error.message}`,
        data: {}
      };
    }
  }

  /**
   * CHECK-B: CVSS Validation
   * Recalculates CVSS score and validates against reported score
   */
  async checkCVSS(triageOutput) {
    try {
      if (!triageOutput.cvss_vector || triageOutput.cvss_score === null) {
        return {
          result: 'WARN',
          detail: 'Missing CVSS vector or score',
          data: {}
        };
      }

      const validation = this.cvssCalculator.validateScore(
        triageOutput.cvss_vector,
        triageOutput.cvss_score,
        0.1
      );

      let result = validation.valid ? 'PASS' : 'FAIL';
      let detail = validation.valid
        ? `CVSS score validated (calculated: ${validation.calculated}, reported: ${validation.reported})`
        : `CVSS mismatch: calculated ${validation.calculated}, reported ${validation.reported} (diff: ${validation.difference})`;

      return {
        result: result,
        detail: detail,
        data: validation
      };
    } catch (error) {
      return {
        result: 'FAIL',
        detail: `CVSS validation failed: ${error.message}`,
        data: {}
      };
    }
  }

  /**
   * CHECK-C: MITRE ATT&CK Consistency
   * Validates technique ID format and tactic-technique consistency
   */
  async checkMITRE(triageOutput) {
    try {
      const mitre = triageOutput.mitre;

      if (!mitre || !mitre.technique_id) {
        return {
          result: 'WARN',
          detail: 'No MITRE ATT&CK mapping provided',
          data: {}
        };
      }

      const issues = [];

      // Validate technique ID format (T followed by 4 digits, optional .XXX for sub-technique)
      const techniquePattern = /^T\d{4}(\.\d{3})?$/;
      if (!techniquePattern.test(mitre.technique_id)) {
        issues.push(`Invalid technique ID format: ${mitre.technique_id}`);
      }

      // Validate tactic is provided
      if (!mitre.tactic) {
        issues.push('Missing tactic');
      }

      // Validate technique name is provided
      if (!mitre.technique_name) {
        issues.push('Missing technique name');
      }

      // Basic tactic-technique consistency check
      // (In production, this would query a MITRE ATT&CK database)
      const validTactics = [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Command and Control',
        'Exfiltration',
        'Impact'
      ];

      if (mitre.tactic && !validTactics.includes(mitre.tactic)) {
        issues.push(`Unknown tactic: ${mitre.tactic}`);
      }

      const result = issues.length === 0 ? 'PASS' : 'FAIL';
      const detail = issues.length === 0
        ? `MITRE mapping validated: ${mitre.tactic} - ${mitre.technique_id}`
        : `MITRE issues: ${issues.join(', ')}`;

      return {
        result: result,
        detail: detail,
        data: {
          mitre: mitre,
          issues: issues
        }
      };
    } catch (error) {
      return {
        result: 'FAIL',
        detail: `MITRE validation failed: ${error.message}`,
        data: {}
      };
    }
  }

  /**
   * CHECK-D: Test Coverage Completeness
   * Validates that sufficient test cases were generated
   */
  async checkTestCoverage(triageOutput) {
    try {
      const testCases = triageOutput.test_cases || [];
      const issues = [];

      // Minimum 3 test cases required
      if (testCases.length < 3) {
        issues.push(`Only ${testCases.length} test case(s) generated (minimum: 3)`);
      }

      // Check that critical fields have test coverage
      const requiredFields = ['cve_id', 'cvss_score', 'severity', 'affected_products'];
      const coveredFields = new Set();

      for (const testCase of testCases) {
        if (testCase.description) {
          for (const field of requiredFields) {
            if (testCase.description.toLowerCase().includes(field.toLowerCase().replace('_', ' '))) {
              coveredFields.add(field);
            }
          }
        }
      }

      const uncoveredFields = requiredFields.filter(f => !coveredFields.has(f));
      if (uncoveredFields.length > 0) {
        issues.push(`Missing test coverage for: ${uncoveredFields.join(', ')}`);
      }

      const result = issues.length === 0 ? 'PASS' : 'WARN';
      const detail = issues.length === 0
        ? `Test coverage complete (${testCases.length} test cases)`
        : issues.join('; ');

      return {
        result: result,
        detail: detail,
        data: {
          test_count: testCases.length,
          covered_fields: Array.from(coveredFields),
          uncovered_fields: uncoveredFields
        }
      };
    } catch (error) {
      return {
        result: 'FAIL',
        detail: `Test coverage check failed: ${error.message}`,
        data: {}
      };
    }
  }

  /**
   * Run watsonx.ai-generated test cases
   */
  async runTestCases(testCases, triageOutput) {
    const results = [];

    for (const testCase of testCases) {
      try {
        // Simple test execution: check if expected value matches actual
        let passed = false;
        let actualValue = null;

        // Extract field from description or use input
        const fieldMatch = testCase.description.match(/(\w+)/);
        const field = fieldMatch ? fieldMatch[1] : null;

        if (field && triageOutput[field] !== undefined) {
          actualValue = triageOutput[field];
          passed = String(actualValue) === String(testCase.expected);
        }

        results.push({
          id: testCase.id,
          description: testCase.description,
          expected: testCase.expected,
          actual: actualValue,
          passed: passed
        });
      } catch (error) {
        results.push({
          id: testCase.id,
          description: testCase.description,
          expected: testCase.expected,
          actual: null,
          passed: false,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Determine overall QA status
   */
  determineQAStatus(results) {
    const checkResults = Object.values(results.mandatory_checks);
    const hasFails = checkResults.some(c => c.result === 'FAIL') || results.failed > 0;
    const hasWarnings = checkResults.some(c => c.result === 'WARN') || results.warnings > 0;

    if (hasFails) {
      return 'REJECTED';
    } else if (hasWarnings) {
      return 'APPROVED_WITH_WARNINGS';
    } else {
      return 'APPROVED';
    }
  }

  /**
   * Generate recommendation based on QA results
   */
  generateRecommendation(results) {
    if (results.qa_status === 'REJECTED') {
      return 'Reject — reparse required. Critical issues detected that must be resolved before deployment.';
    } else if (results.qa_status === 'APPROVED_WITH_WARNINGS') {
      return 'Hold for human review. Minor issues detected that should be verified by SOC analyst.';
    } else {
      return 'Escalate to SOC. All checks passed, ready for action chain execution.';
    }
  }

  /**
   * Analyze regressions across multiple CVEs
   */
  analyzeRegressions(triageOutput) {
    if (this.regressionData.length < 2) {
      return 'Insufficient data for regression analysis';
    }

    const notes = [];

    // Check for recurring obfuscation patterns
    const obfuscationCVEs = this.regressionData.filter(r =>
      r.results.mandatory_checks['CHECK-A']?.data?.detected_count > 0
    );

    if (obfuscationCVEs.length >= 2) {
      notes.push(`Pattern detected: ${obfuscationCVEs.length} CVEs with obfuscation in this session`);
    }

    // Check for recurring CVSS mismatches
    const cvssMismatches = this.regressionData.filter(r =>
      r.results.mandatory_checks['CHECK-B']?.result === 'FAIL'
    );

    if (cvssMismatches.length >= 2) {
      notes.push(`Regression alert: ${cvssMismatches.length} CVSS calculation errors detected`);
    }

    return notes.length > 0 ? notes.join('; ') : 'No regressions detected';
  }

  /**
   * Get QA statistics
   */
  getStats() {
    if (this.regressionData.length === 0) {
      return null;
    }

    const total = this.regressionData.length;
    const approved = this.regressionData.filter(r => r.results.qa_status === 'APPROVED').length;
    const approvedWithWarnings = this.regressionData.filter(r => r.results.qa_status === 'APPROVED_WITH_WARNINGS').length;
    const rejected = this.regressionData.filter(r => r.results.qa_status === 'REJECTED').length;

    return {
      total_cves_tested: total,
      approved: approved,
      approved_with_warnings: approvedWithWarnings,
      rejected: rejected,
      approval_rate: ((approved + approvedWithWarnings) / total * 100).toFixed(1) + '%'
    };
  }
}

// Export factory function to create instance with watsonx client
export function createIBMBob(watsonxClient = null) {
  return new IBMBobQA(process.env.IBM_BOB_STRICT_MODE === 'true', watsonxClient);
}

// Export singleton instance (will be initialized in routes with watsonx client)
export const ibmBob = new IBMBobQA(process.env.IBM_BOB_STRICT_MODE === 'true', null);

export default ibmBob;

// Made with Bob
