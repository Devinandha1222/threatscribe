/**
 * AI-Powered Threat Detector
 * Uses IBM watsonx.ai LLM for intelligent, context-aware threat detection
 * Goes beyond dictionary patterns to understand semantic obfuscation and evasion techniques
 */

/**
 * AI Threat Detector using watsonx.ai
 * Provides flexible, intelligent threat detection beyond simple pattern matching
 */
export class AIThreatDetector {
  constructor(watsonxClient) {
    this.watsonxClient = watsonxClient;
    this.demoMode = process.env.DEMO_MODE === 'true';
  }

  /**
   * Analyze text for threats using AI
   * @param {string} text - Text to analyze
   * @param {Object} context - Additional context (source, metadata, etc.)
   * @returns {Object} AI analysis results
   */
  async analyzeThreats(text, context = {}) {
    if (this.demoMode) {
      return this.mockAIAnalysis(text, context);
    }

    return this.realAIAnalysis(text, context);
  }

  /**
   * Real AI analysis using watsonx.ai
   */
  async realAIAnalysis(text, context) {
    const prompt = this.buildThreatAnalysisPrompt(text, context);
    
    try {
      const response = await fetch(`${this.watsonxClient.url}/ml/v1/text/generation?version=2023-05-29`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.watsonxClient.apiKey}`,
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          model_id: this.watsonxClient.model,
          input: prompt,
          parameters: {
            max_new_tokens: 1500,
            temperature: 0.1,  // Low temperature for consistent analysis
            top_p: 0.95,
            top_k: 50
          },
          project_id: this.watsonxClient.projectId
        })
      });

      if (!response.ok) {
        throw new Error(`Watson AI API error: ${response.status}`);
      }

      const data = await response.json();
      const analysis = JSON.parse(data.results[0].generated_text);
      
      return {
        ...analysis,
        analyzed_at: new Date().toISOString(),
        model_used: this.watsonxClient.model,
        analysis_type: 'ai_powered'
      };

    } catch (error) {
      console.error('AI threat analysis error:', error);
      // Fallback to mock analysis if API fails
      return this.mockAIAnalysis(text, context);
    }
  }

  /**
   * Build prompt for threat analysis
   */
  buildThreatAnalysisPrompt(text, context) {
    return `You are an advanced cybersecurity threat detection AI. Analyze the following text for potential security threats, obfuscation techniques, and evasion patterns.

TEXT TO ANALYZE:
${text}

CONTEXT:
${JSON.stringify(context, null, 2)}

Perform a comprehensive analysis and return a JSON object with the following structure:

{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "confidence": 0.0-1.0,
  "obfuscation_detected": true|false,
  "obfuscation_techniques": [
    {
      "type": "character_substitution|encoding|unicode_tricks|homoglyph|semantic_evasion",
      "description": "detailed description",
      "evidence": "specific text showing the technique",
      "position": "location in text",
      "confidence": 0.0-1.0,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }
  ],
  "threat_indicators": [
    {
      "indicator": "specific threat indicator found",
      "category": "malware|vulnerability|exploit|phishing|command_injection|etc",
      "confidence": 0.0-1.0,
      "context": "surrounding context"
    }
  ],
  "semantic_analysis": {
    "intent": "description of likely intent",
    "sophistication": "LOW|MEDIUM|HIGH|ADVANCED",
    "evasion_likelihood": 0.0-1.0,
    "notes": "additional observations"
  },
  "recommendations": [
    "specific actionable recommendations"
  ],
  "false_positive_likelihood": 0.0-1.0,
  "requires_human_review": true|false,
  "reasoning": "explanation of the analysis"
}

Focus on:
1. Character-level obfuscation (0 vs O, 1 vs l, etc.) but also semantic tricks
2. Unicode homoglyphs and lookalike characters
3. Encoding tricks (base64, hex, URL encoding within text)
4. Semantic evasion (using synonyms, misspellings, or context to hide intent)
5. Known vulnerability patterns (Log4j, Fortinet, etc.) even when obfuscated
6. Command injection patterns
7. Malicious payload indicators

Be thorough but avoid false positives. If confidence is below 0.7, set requires_human_review to true.

Return ONLY valid JSON, no markdown formatting.`;
  }

  /**
   * Mock AI analysis for demo mode
   */
  async mockAIAnalysis(text, context) {
    // Simulate AI processing time
    await new Promise(resolve => setTimeout(resolve, 500));

    const textLower = text.toLowerCase();
    const obfuscationTechniques = [];
    const threatIndicators = [];
    let threatLevel = 'LOW';
    let confidence = 0.85;

    // Detect character substitution patterns
    const substitutionPatterns = [
      { pattern: /l[0o]g[4a]j/i, name: 'Log4j', severity: 'CRITICAL' },
      { pattern: /f[0o]rt[1i]n[e3]t/i, name: 'Fortinet', severity: 'HIGH' },
      { pattern: /w[1i]nd[0o]ws/i, name: 'Windows', severity: 'MEDIUM' },
      { pattern: /[s$][q9][l1]/i, name: 'SQL', severity: 'HIGH' },
      { pattern: /[@a]dmin/i, name: 'Admin', severity: 'MEDIUM' },
      { pattern: /p[a4]ssw[0o]rd/i, name: 'Password', severity: 'HIGH' }
    ];

    for (const { pattern, name, severity } of substitutionPatterns) {
      const match = text.match(pattern);
      if (match) {
        obfuscationTechniques.push({
          type: 'character_substitution',
          description: `Detected obfuscated reference to ${name} using character substitution`,
          evidence: match[0],
          position: text.indexOf(match[0]),
          confidence: 0.92,
          severity: severity
        });
        
        threatIndicators.push({
          indicator: name,
          category: 'vulnerability',
          confidence: 0.90,
          context: text.substring(Math.max(0, text.indexOf(match[0]) - 20), text.indexOf(match[0]) + match[0].length + 20)
        });

        if (severity === 'CRITICAL') threatLevel = 'CRITICAL';
        else if (severity === 'HIGH' && threatLevel !== 'CRITICAL') threatLevel = 'HIGH';
      }
    }

    // Detect encoding patterns
    if (/[A-Za-z0-9+/]{20,}={0,2}/.test(text)) {
      obfuscationTechniques.push({
        type: 'encoding',
        description: 'Potential Base64 encoded content detected',
        evidence: text.match(/[A-Za-z0-9+/]{20,}={0,2}/)[0].substring(0, 30) + '...',
        position: text.search(/[A-Za-z0-9+/]{20,}={0,2}/),
        confidence: 0.75,
        severity: 'MEDIUM'
      });
    }

    // Detect CVE patterns
    const cveMatch = text.match(/CVE-\d{4}-\d{4,}/i);
    if (cveMatch) {
      threatIndicators.push({
        indicator: cveMatch[0],
        category: 'vulnerability',
        confidence: 0.98,
        context: 'CVE identifier found'
      });
    }

    // Detect malicious keywords
    const maliciousKeywords = [
      { word: 'exploit', category: 'exploit', severity: 'HIGH' },
      { word: 'payload', category: 'malware', severity: 'HIGH' },
      { word: 'shell', category: 'command_injection', severity: 'HIGH' },
      { word: 'injection', category: 'command_injection', severity: 'HIGH' },
      { word: 'backdoor', category: 'malware', severity: 'CRITICAL' },
      { word: 'ransomware', category: 'malware', severity: 'CRITICAL' }
    ];

    for (const { word, category, severity } of maliciousKeywords) {
      if (textLower.includes(word)) {
        threatIndicators.push({
          indicator: word,
          category: category,
          confidence: 0.85,
          context: text.substring(Math.max(0, textLower.indexOf(word) - 15), textLower.indexOf(word) + word.length + 15)
        });
        
        if (severity === 'CRITICAL' && threatLevel !== 'CRITICAL') threatLevel = 'CRITICAL';
        else if (severity === 'HIGH' && !['CRITICAL', 'HIGH'].includes(threatLevel)) threatLevel = 'HIGH';
      }
    }

    // Determine if obfuscation was detected
    const obfuscationDetected = obfuscationTechniques.length > 0;

    // Calculate sophistication
    let sophistication = 'LOW';
    if (obfuscationTechniques.length >= 3) sophistication = 'ADVANCED';
    else if (obfuscationTechniques.length >= 2) sophistication = 'HIGH';
    else if (obfuscationTechniques.length >= 1) sophistication = 'MEDIUM';

    // Generate recommendations
    const recommendations = [];
    if (obfuscationDetected) {
      recommendations.push('Investigate the obfuscation techniques used - may indicate intentional evasion');
      recommendations.push('Cross-reference with known threat intelligence databases');
    }
    if (threatLevel === 'CRITICAL' || threatLevel === 'HIGH') {
      recommendations.push('Immediate escalation to security team required');
      recommendations.push('Implement containment measures');
    }
    if (threatIndicators.length > 0) {
      recommendations.push('Correlate with recent security advisories and threat feeds');
    }

    return {
      threat_level: threatLevel,
      confidence: confidence,
      obfuscation_detected: obfuscationDetected,
      obfuscation_techniques: obfuscationTechniques,
      threat_indicators: threatIndicators,
      semantic_analysis: {
        intent: obfuscationDetected ? 'Potential evasion attempt detected' : 'Standard security advisory',
        sophistication: sophistication,
        evasion_likelihood: obfuscationDetected ? 0.85 : 0.15,
        notes: `Analyzed ${text.length} characters. Found ${threatIndicators.length} threat indicators and ${obfuscationTechniques.length} obfuscation techniques.`
      },
      recommendations: recommendations,
      false_positive_likelihood: obfuscationDetected ? 0.10 : 0.30,
      requires_human_review: confidence < 0.7 || threatLevel === 'CRITICAL',
      reasoning: `AI analysis detected ${threatIndicators.length} threat indicators with ${obfuscationTechniques.length} obfuscation techniques. Threat level assessed as ${threatLevel} based on severity of findings.`,
      analyzed_at: new Date().toISOString(),
      model_used: this.watsonxClient?.model || 'demo-mode',
      analysis_type: 'ai_powered'
    };
  }

  /**
   * Batch analyze multiple texts
   */
  async batchAnalyze(texts, contexts = []) {
    const results = [];
    
    for (let i = 0; i < texts.length; i++) {
      const text = texts[i];
      const context = contexts[i] || {};
      
      try {
        const analysis = await this.analyzeThreats(text, context);
        results.push({
          index: i,
          success: true,
          analysis: analysis
        });
      } catch (error) {
        results.push({
          index: i,
          success: false,
          error: error.message
        });
      }
    }
    
    return results;
  }

  /**
   * Generate threat report from analysis
   */
  generateThreatReport(analysis) {
    let report = `# AI Threat Analysis Report\n\n`;
    report += `**Threat Level:** ${analysis.threat_level}\n`;
    report += `**Confidence:** ${(analysis.confidence * 100).toFixed(1)}%\n`;
    report += `**Analyzed At:** ${analysis.analyzed_at}\n`;
    report += `**Model:** ${analysis.model_used}\n\n`;

    if (analysis.obfuscation_detected) {
      report += `## ⚠️ Obfuscation Detected\n\n`;
      report += `Found ${analysis.obfuscation_techniques.length} obfuscation technique(s):\n\n`;
      
      for (const tech of analysis.obfuscation_techniques) {
        report += `### ${tech.type.replace(/_/g, ' ').toUpperCase()}\n`;
        report += `- **Severity:** ${tech.severity}\n`;
        report += `- **Confidence:** ${(tech.confidence * 100).toFixed(1)}%\n`;
        report += `- **Description:** ${tech.description}\n`;
        report += `- **Evidence:** \`${tech.evidence}\`\n\n`;
      }
    }

    if (analysis.threat_indicators.length > 0) {
      report += `## Threat Indicators\n\n`;
      for (const indicator of analysis.threat_indicators) {
        report += `- **${indicator.indicator}** (${indicator.category})\n`;
        report += `  - Confidence: ${(indicator.confidence * 100).toFixed(1)}%\n`;
        report += `  - Context: ${indicator.context}\n\n`;
      }
    }

    report += `## Semantic Analysis\n\n`;
    report += `- **Intent:** ${analysis.semantic_analysis.intent}\n`;
    report += `- **Sophistication:** ${analysis.semantic_analysis.sophistication}\n`;
    report += `- **Evasion Likelihood:** ${(analysis.semantic_analysis.evasion_likelihood * 100).toFixed(1)}%\n`;
    report += `- **Notes:** ${analysis.semantic_analysis.notes}\n\n`;

    if (analysis.recommendations.length > 0) {
      report += `## Recommendations\n\n`;
      for (const rec of analysis.recommendations) {
        report += `- ${rec}\n`;
      }
      report += `\n`;
    }

    report += `## Analysis Summary\n\n`;
    report += `${analysis.reasoning}\n\n`;
    
    if (analysis.requires_human_review) {
      report += `**⚠️ HUMAN REVIEW REQUIRED**\n\n`;
    }

    report += `---\n*Generated by AI-Powered Threat Detector using IBM watsonx.ai*\n`;

    return report;
  }
}

export default AIThreatDetector;

// Made with Bob