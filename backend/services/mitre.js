/**
 * MITRE ATT&CK Service
 * Provides MITRE ATT&CK framework integration for threat mapping
 */

/**
 * MITRE ATT&CK Tactics (Enterprise)
 * Ordered by typical attack lifecycle
 */
export const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access', description: 'Trying to get into your network' },
  { id: 'TA0002', name: 'Execution', description: 'Trying to run malicious code' },
  { id: 'TA0003', name: 'Persistence', description: 'Trying to maintain their foothold' },
  { id: 'TA0004', name: 'Privilege Escalation', description: 'Trying to gain higher-level permissions' },
  { id: 'TA0005', name: 'Defense Evasion', description: 'Trying to avoid being detected' },
  { id: 'TA0006', name: 'Credential Access', description: 'Trying to steal account names and passwords' },
  { id: 'TA0007', name: 'Discovery', description: 'Trying to figure out your environment' },
  { id: 'TA0008', name: 'Lateral Movement', description: 'Trying to move through your environment' },
  { id: 'TA0009', name: 'Collection', description: 'Trying to gather data of interest' },
  { id: 'TA0011', name: 'Command and Control', description: 'Trying to communicate with compromised systems' },
  { id: 'TA0010', name: 'Exfiltration', description: 'Trying to steal data' },
  { id: 'TA0040', name: 'Impact', description: 'Trying to manipulate, interrupt, or destroy systems and data' }
];

/**
 * Common MITRE ATT&CK Techniques (subset for demo)
 * In production, this would be a complete database or API call
 */
export const MITRE_TECHNIQUES = {
  // Initial Access
  'T1190': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system',
    sub_techniques: []
  },
  'T1133': {
    id: 'T1133',
    name: 'External Remote Services',
    tactic: 'Initial Access',
    description: 'Adversaries may leverage external-facing remote services',
    sub_techniques: []
  },
  'T1566': {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access',
    sub_techniques: ['T1566.001', 'T1566.002', 'T1566.003']
  },

  // Execution
  'T1059': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters',
    sub_techniques: ['T1059.001', 'T1059.003', 'T1059.005']
  },
  'T1203': {
    id: 'T1203',
    name: 'Exploitation for Client Execution',
    tactic: 'Execution',
    description: 'Adversaries may exploit software vulnerabilities in client applications',
    sub_techniques: []
  },

  // Persistence
  'T1053': {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    description: 'Adversaries may abuse task scheduling functionality',
    sub_techniques: ['T1053.002', 'T1053.005']
  },
  'T1543': {
    id: 'T1543',
    name: 'Create or Modify System Process',
    tactic: 'Persistence',
    description: 'Adversaries may create or modify system-level processes',
    sub_techniques: ['T1543.003']
  },

  // Privilege Escalation
  'T1068': {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may exploit software vulnerabilities to elevate privileges',
    sub_techniques: []
  },
  'T1078': {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may obtain and abuse credentials of existing accounts',
    sub_techniques: ['T1078.001', 'T1078.002', 'T1078.003']
  },

  // Defense Evasion
  'T1027': {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    description: 'Adversaries may attempt to make files or information difficult to discover or analyze',
    sub_techniques: ['T1027.001', 'T1027.002', 'T1027.005']
  },
  'T1070': {
    id: 'T1070',
    name: 'Indicator Removal',
    tactic: 'Defense Evasion',
    description: 'Adversaries may delete or modify artifacts to remove evidence',
    sub_techniques: ['T1070.001', 'T1070.004']
  },

  // Credential Access
  'T1110': {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Adversaries may use brute force techniques to gain access',
    sub_techniques: ['T1110.001', 'T1110.003']
  },
  'T1555': {
    id: 'T1555',
    name: 'Credentials from Password Stores',
    tactic: 'Credential Access',
    description: 'Adversaries may search for common password storage locations',
    sub_techniques: ['T1555.003']
  },

  // Discovery
  'T1083': {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may enumerate files and directories',
    sub_techniques: []
  },
  'T1082': {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get detailed information about the system',
    sub_techniques: []
  },

  // Lateral Movement
  'T1021': {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use valid accounts to log into remote services',
    sub_techniques: ['T1021.001', 'T1021.002']
  },

  // Collection
  'T1005': {
    id: 'T1005',
    name: 'Data from Local System',
    tactic: 'Collection',
    description: 'Adversaries may search local system sources for data',
    sub_techniques: []
  },

  // Command and Control
  'T1071': {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols',
    sub_techniques: ['T1071.001', 'T1071.004']
  },

  // Exfiltration
  'T1041': {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    description: 'Adversaries may steal data by exfiltrating it over an existing C2 channel',
    sub_techniques: []
  },

  // Impact
  'T1486': {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries may encrypt data to impact availability',
    sub_techniques: []
  },
  'T1499': {
    id: 'T1499',
    name: 'Endpoint Denial of Service',
    tactic: 'Impact',
    description: 'Adversaries may perform DoS attacks to degrade or block availability',
    sub_techniques: ['T1499.002', 'T1499.004']
  }
};

/**
 * Lookup a MITRE technique by ID
 */
export function lookupTechnique(techniqueId) {
  // Handle sub-techniques (e.g., T1566.001)
  const baseId = techniqueId.split('.')[0];
  const technique = MITRE_TECHNIQUES[baseId];

  if (!technique) {
    return null;
  }

  // If it's a sub-technique, note that
  const isSubTechnique = techniqueId.includes('.');

  return {
    ...technique,
    is_sub_technique: isSubTechnique,
    requested_id: techniqueId
  };
}

/**
 * Validate MITRE technique ID format
 */
export function validateTechniqueId(techniqueId) {
  if (!techniqueId) {
    return { valid: false, error: 'Technique ID is required' };
  }

  // Format: T followed by 4 digits, optional .XXX for sub-technique
  const pattern = /^T\d{4}(\.\d{3})?$/;

  if (!pattern.test(techniqueId)) {
    return {
      valid: false,
      error: `Invalid technique ID format: ${techniqueId}. Expected format: TXXXX or TXXXX.XXX`
    };
  }

  return { valid: true };
}

/**
 * Validate tactic name
 */
export function validateTactic(tacticName) {
  if (!tacticName) {
    return { valid: false, error: 'Tactic name is required' };
  }

  const tactic = MITRE_TACTICS.find(t => t.name === tacticName);

  if (!tactic) {
    return {
      valid: false,
      error: `Unknown tactic: ${tacticName}`,
      valid_tactics: MITRE_TACTICS.map(t => t.name)
    };
  }

  return { valid: true, tactic: tactic };
}

/**
 * Check if a technique belongs to a tactic
 */
export function validateTacticTechniqueConsistency(tacticName, techniqueId) {
  const technique = lookupTechnique(techniqueId);

  if (!technique) {
    return {
      valid: false,
      error: `Unknown technique: ${techniqueId}`
    };
  }

  if (technique.tactic !== tacticName) {
    return {
      valid: false,
      error: `Technique ${techniqueId} belongs to tactic "${technique.tactic}", not "${tacticName}"`
    };
  }

  return { valid: true };
}

/**
 * Get all techniques for a tactic
 */
export function getTechniquesByTactic(tacticName) {
  return Object.values(MITRE_TECHNIQUES).filter(t => t.tactic === tacticName);
}

/**
 * Map CVE characteristics to likely MITRE techniques
 * This is a simplified heuristic for demo purposes
 */
export function suggestTechniques(cveData) {
  const suggestions = [];

  // Check attack vector
  if (cveData.attack_vector === 'Network') {
    suggestions.push({
      technique_id: 'T1190',
      reason: 'Network-based attack vector suggests exploitation of public-facing application',
      confidence: 0.8
    });
  }

  // Check for RCE indicators
  const description = (cveData.description || '').toLowerCase();
  if (description.includes('remote code execution') || description.includes('rce')) {
    suggestions.push({
      technique_id: 'T1203',
      reason: 'Remote code execution capability',
      confidence: 0.9
    });
  }

  // Check for privilege escalation
  if (cveData.privileges_required === 'Low' && description.includes('privilege')) {
    suggestions.push({
      technique_id: 'T1068',
      reason: 'Privilege escalation vulnerability',
      confidence: 0.85
    });
  }

  // Check for obfuscation
  if (cveData.typo_flags && cveData.typo_flags.length > 0) {
    suggestions.push({
      technique_id: 'T1027',
      reason: 'Obfuscation detected in vulnerability description',
      confidence: 0.75
    });
  }

  // Check for credential access
  if (description.includes('password') || description.includes('credential')) {
    suggestions.push({
      technique_id: 'T1555',
      reason: 'Credential access indicators',
      confidence: 0.7
    });
  }

  // Check for DoS
  if (description.includes('denial of service') || description.includes('dos')) {
    suggestions.push({
      technique_id: 'T1499',
      reason: 'Denial of service capability',
      confidence: 0.8
    });
  }

  return suggestions;
}

/**
 * Generate MITRE ATT&CK coverage statistics
 */
export function generateCoverageStats(cveList) {
  const tacticCounts = {};

  // Initialize counts
  for (const tactic of MITRE_TACTICS) {
    tacticCounts[tactic.name] = 0;
  }

  // Count CVEs per tactic
  for (const cve of cveList) {
    if (cve.mitre && cve.mitre.tactic) {
      tacticCounts[cve.mitre.tactic] = (tacticCounts[cve.mitre.tactic] || 0) + 1;
    }
  }

  return {
    total_cves: cveList.length,
    tactics: Object.entries(tacticCounts).map(([name, count]) => ({
      name,
      count,
      percentage: cveList.length > 0 ? ((count / cveList.length) * 100).toFixed(1) : 0
    })),
    most_common: Object.entries(tacticCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, count]) => ({ name, count }))
  };
}

/**
 * Validate complete MITRE mapping
 */
export function validateMitreMapping(mitreData) {
  const errors = [];
  const warnings = [];

  // Validate technique ID
  const techniqueValidation = validateTechniqueId(mitreData.technique_id);
  if (!techniqueValidation.valid) {
    errors.push(techniqueValidation.error);
  }

  // Validate tactic
  const tacticValidation = validateTactic(mitreData.tactic);
  if (!tacticValidation.valid) {
    errors.push(tacticValidation.error);
  }

  // Validate consistency
  if (techniqueValidation.valid && tacticValidation.valid) {
    const consistencyCheck = validateTacticTechniqueConsistency(
      mitreData.tactic,
      mitreData.technique_id
    );
    if (!consistencyCheck.valid) {
      errors.push(consistencyCheck.error);
    }
  }

  // Check if technique exists in our database
  const technique = lookupTechnique(mitreData.technique_id);
  if (!technique && techniqueValidation.valid) {
    warnings.push(`Technique ${mitreData.technique_id} not in local database (may be valid but unknown)`);
  }

  // Validate technique name matches
  if (technique && mitreData.technique_name) {
    if (technique.name !== mitreData.technique_name) {
      warnings.push(`Technique name mismatch: expected "${technique.name}", got "${mitreData.technique_name}"`);
    }
  }

  return {
    valid: errors.length === 0,
    errors: errors,
    warnings: warnings,
    technique: technique
  };
}

export default {
  MITRE_TACTICS,
  MITRE_TECHNIQUES,
  lookupTechnique,
  validateTechniqueId,
  validateTactic,
  validateTacticTechniqueConsistency,
  getTechniquesByTactic,
  suggestTechniques,
  generateCoverageStats,
  validateMitreMapping
};

// Made with Bob
