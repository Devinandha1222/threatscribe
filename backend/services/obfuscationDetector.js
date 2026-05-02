/**
 * Obfuscation Detector - IBM Bob's Core Algorithm
 * Detects character-level substitution attacks (O vs 0, l vs 1, etc.)
 * 
 * This is the showcase feature that catches sophisticated evasion techniques
 * like "L0g4j" where attackers use visually similar characters to bypass detection.
 */

/**
 * Substitution pairs with visual similarity weights
 * Higher weight = more visually similar = more likely to be intentional obfuscation
 */
const SUBSTITUTION_MAP = {
  '0': { chars: ['O', 'o'], weight: 0.95, description: 'Zero vs Letter O' },
  '1': { chars: ['l', 'I', 'i'], weight: 0.90, description: 'One vs lowercase L/uppercase I' },
  '$': { chars: ['S', 's'], weight: 0.85, description: 'Dollar sign vs Letter S' },
  '@': { chars: ['a', 'A'], weight: 0.80, description: 'At sign vs Letter A' },
  '3': { chars: ['E', 'e'], weight: 0.85, description: 'Three vs Letter E' },
  '|': { chars: ['l', 'I', '1'], weight: 0.75, description: 'Pipe vs lowercase L/uppercase I/one' },
  '!': { chars: ['1', 'I', 'l'], weight: 0.70, description: 'Exclamation vs one/uppercase I/lowercase L' },
  '5': { chars: ['S', 's'], weight: 0.80, description: 'Five vs Letter S' },
  '6': { chars: ['G', 'b'], weight: 0.75, description: 'Six vs Letter G/b' },
  '8': { chars: ['B'], weight: 0.80, description: 'Eight vs Letter B' },
  '4': { chars: ['A', 'a'], weight: 0.75, description: 'Four vs Letter A' }
};

// Build reverse map for efficient lookup
const REVERSE_SUBSTITUTION_MAP = {};
for (const [original, data] of Object.entries(SUBSTITUTION_MAP)) {
  for (const char of data.chars) {
    if (!REVERSE_SUBSTITUTION_MAP[char]) {
      REVERSE_SUBSTITUTION_MAP[char] = [];
    }
    REVERSE_SUBSTITUTION_MAP[char].push({ original, weight: data.weight, description: data.description });
  }
}

/**
 * Calculate visual similarity score between two characters
 * @param {string} char1 - First character
 * @param {string} char2 - Second character
 * @returns {number} Similarity score (0-1)
 */
function calculateVisualSimilarity(char1, char2) {
  // Check direct substitution map
  if (SUBSTITUTION_MAP[char1]) {
    if (SUBSTITUTION_MAP[char1].chars.includes(char2)) {
      return SUBSTITUTION_MAP[char1].weight;
    }
  }
  
  // Check reverse map
  if (REVERSE_SUBSTITUTION_MAP[char1]) {
    const matches = REVERSE_SUBSTITUTION_MAP[char1].filter(m => m.original === char2);
    if (matches.length > 0) {
      return matches[0].weight;
    }
  }
  
  // Unicode distance-based similarity (fallback)
  const code1 = char1.charCodeAt(0);
  const code2 = char2.charCodeAt(0);
  const distance = Math.abs(code1 - code2);
  
  // Close Unicode points might be similar
  if (distance <= 5) {
    return 0.6 - (distance * 0.1);
  }
  
  return 0;
}

/**
 * Detect obfuscation in a single text string
 * @param {string} text - Text to analyze
 * @param {string} fieldName - Name of the field being analyzed
 * @returns {Array} Array of obfuscation matches
 */
export function detectObfuscation(text, fieldName = 'unknown') {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const matches = [];
  const textLower = text.toLowerCase();
  
  // Sliding window analysis (size 1-3 characters)
  for (let windowSize = 1; windowSize <= 3; windowSize++) {
    for (let i = 0; i <= text.length - windowSize; i++) {
      const window = text.substring(i, i + windowSize);
      
      // Analyze each character in the window
      for (let j = 0; j < window.length; j++) {
        const char = window[j];
        const position = i + j;
        
        // Check if this character is a known substitution
        if (SUBSTITUTION_MAP[char]) {
          const data = SUBSTITUTION_MAP[char];
          
          // Look at context to determine if this is likely obfuscation
          const context = getContext(text, position, 3);
          const confidence = analyzeContext(char, context, data);
          
          if (confidence >= 0.5) {
            const risk = confidence >= 0.7 ? 'obfuscation' : 'ocr_error';
            
            matches.push({
              field: fieldName,
              position: position,
              original: char,
              suspected_intent: data.chars[0], // Most likely intended character
              alternatives: data.chars,
              confidence: confidence,
              risk: risk,
              context: context,
              description: data.description
            });
          }
        }
        
        // Check reverse substitutions (letter that should be number)
        if (REVERSE_SUBSTITUTION_MAP[char]) {
          const possibilities = REVERSE_SUBSTITUTION_MAP[char];
          
          for (const possibility of possibilities) {
            const context = getContext(text, position, 3);
            const confidence = analyzeContext(char, context, possibility);
            
            if (confidence >= 0.5) {
              const risk = confidence >= 0.7 ? 'obfuscation' : 'ocr_error';
              
              matches.push({
                field: fieldName,
                position: position,
                original: char,
                suspected_intent: possibility.original,
                alternatives: [possibility.original],
                confidence: confidence,
                risk: risk,
                context: context,
                description: possibility.description
              });
            }
          }
        }
      }
    }
  }
  
  // Remove duplicates (same position)
  const uniqueMatches = [];
  const seenPositions = new Set();
  
  for (const match of matches) {
    if (!seenPositions.has(match.position)) {
      seenPositions.add(match.position);
      uniqueMatches.push(match);
    }
  }
  
  return uniqueMatches;
}

/**
 * Get context around a character position
 * @param {string} text - Full text
 * @param {number} position - Character position
 * @param {number} radius - Number of characters before/after
 * @returns {string} Context string
 */
function getContext(text, position, radius = 3) {
  const start = Math.max(0, position - radius);
  const end = Math.min(text.length, position + radius + 1);
  return text.substring(start, end);
}

/**
 * Analyze context to determine obfuscation confidence
 * @param {string} char - Character being analyzed
 * @param {string} context - Surrounding text
 * @param {Object} substitutionData - Substitution data
 * @returns {number} Confidence score (0-1)
 */
function analyzeContext(char, context, substitutionData) {
  let confidence = substitutionData.weight;
  
  // Boost confidence if surrounded by alphanumeric characters (likely part of a word)
  const alphanumericPattern = /[a-zA-Z0-9]/;
  const beforeChar = context[Math.floor(context.length / 2) - 1];
  const afterChar = context[Math.floor(context.length / 2) + 1];
  
  if (beforeChar && alphanumericPattern.test(beforeChar) && 
      afterChar && alphanumericPattern.test(afterChar)) {
    confidence += 0.1;
  }
  
  // Check for common obfuscation patterns
  const contextLower = context.toLowerCase();
  
  // Known vulnerability names with common obfuscations
  const knownPatterns = [
    { pattern: /l.?0.?g.?4.?j/i, boost: 0.15 }, // L0g4j variants
    { pattern: /f.?0.?rt.?1.?n.?et/i, boost: 0.15 }, // F0rt1net variants
    { pattern: /w.?1.?nd.?0.?ws/i, boost: 0.10 }, // W1nd0ws variants
    { pattern: /l.?1.?nux/i, boost: 0.10 }, // L1nux variants
    { pattern: /\$ql/i, boost: 0.15 }, // $QL (SQL) variants
    { pattern: /@dmin/i, boost: 0.12 }, // @dmin (admin) variants
  ];
  
  for (const { pattern, boost } of knownPatterns) {
    if (pattern.test(contextLower)) {
      confidence += boost;
    }
  }
  
  // Reduce confidence if in a URL or file path (might be legitimate)
  if (context.includes('://') || context.includes('\\') || context.includes('/')) {
    confidence -= 0.15;
  }
  
  // Reduce confidence if it's a version number (e.g., "1.0.2")
  if (/\d+\.\d+/.test(context)) {
    confidence -= 0.20;
  }
  
  return Math.max(0, Math.min(1, confidence));
}

/**
 * Detect obfuscation across all fields in an object
 * @param {Object} obj - Object to analyze
 * @param {Array} excludeFields - Fields to skip
 * @returns {Array} Array of all obfuscation matches
 */
export function detectObfuscationInObject(obj, excludeFields = []) {
  const allMatches = [];
  
  function traverse(current, path = '') {
    if (typeof current === 'string') {
      const matches = detectObfuscation(current, path);
      allMatches.push(...matches);
    } else if (Array.isArray(current)) {
      current.forEach((item, index) => {
        traverse(item, `${path}[${index}]`);
      });
    } else if (typeof current === 'object' && current !== null) {
      for (const [key, value] of Object.entries(current)) {
        if (!excludeFields.includes(key)) {
          const newPath = path ? `${path}.${key}` : key;
          traverse(value, newPath);
        }
      }
    }
  }
  
  traverse(obj);
  return allMatches;
}

/**
 * Compare detected obfuscations with watsonx.ai's typo_flags
 * This is CHECK-A in the IBM Bob QA pipeline
 * @param {Array} detectedFlags - Flags detected by this module
 * @param {Array} watsonxFlags - Flags reported by watsonx.ai
 * @returns {Object} Comparison result
 */
export function compareWithWatsonx(detectedFlags, watsonxFlags = []) {
  const missed = [];
  const falsePositives = [];
  const correct = [];
  
  // Check for missed obfuscations
  for (const detected of detectedFlags) {
    const found = watsonxFlags.some(wf => 
      wf.field === detected.field && 
      Math.abs(wf.position - detected.position) <= 2 // Allow small position variance
    );
    
    if (!found && detected.risk === 'obfuscation') {
      missed.push(detected);
    } else if (found) {
      correct.push(detected);
    }
  }
  
  // Check for false positives
  for (const watsonxFlag of watsonxFlags) {
    const found = detectedFlags.some(df => 
      df.field === watsonxFlag.field && 
      Math.abs(df.position - watsonxFlag.position) <= 2
    );
    
    if (!found) {
      falsePositives.push(watsonxFlag);
    }
  }
  
  return {
    total_detected: detectedFlags.length,
    total_watsonx: watsonxFlags.length,
    correct: correct.length,
    missed: missed.length,
    false_positives: falsePositives.length,
    missed_details: missed,
    false_positive_details: falsePositives,
    accuracy: detectedFlags.length > 0 ? (correct.length / detectedFlags.length) : 1.0
  };
}

/**
 * Generate a human-readable report of obfuscation findings
 * @param {Array} matches - Obfuscation matches
 * @returns {string} Formatted report
 */
export function generateObfuscationReport(matches) {
  if (matches.length === 0) {
    return 'No obfuscation detected.';
  }
  
  let report = `Found ${matches.length} potential obfuscation(s):\n\n`;
  
  for (const match of matches) {
    report += `• Position ${match.position} in "${match.field}":\n`;
    report += `  Character: '${match.original}' → Suspected: '${match.suspected_intent}'\n`;
    report += `  Context: "${match.context}"\n`;
    report += `  Risk: ${match.risk.toUpperCase()} (confidence: ${(match.confidence * 100).toFixed(1)}%)\n`;
    report += `  ${match.description}\n\n`;
  }
  
  return report;
}

export default {
  detectObfuscation,
  detectObfuscationInObject,
  compareWithWatsonx,
  generateObfuscationReport,
  SUBSTITUTION_MAP
};

// Made with Bob
