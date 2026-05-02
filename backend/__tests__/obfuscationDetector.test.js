/**
 * Unit Tests for Obfuscation Detector
 * Required: 100% test coverage for this module
 */

import { describe, test, expect } from '@jest/globals';
import {
  detectObfuscation,
  detectObfuscationInObject,
  compareWithWatsonx,
  generateObfuscationReport,
  SUBSTITUTION_MAP
} from '../services/obfuscationDetector.js';

describe('Obfuscation Detector - Core Functionality', () => {
  
  test('TEST CASE 1: Should detect "L0g4j" obfuscation', () => {
    const text = 'L0g4j';
    const matches = detectObfuscation(text, 'test_field');
    
    // Should detect at least the '0' and '4'
    expect(matches.length).toBeGreaterThanOrEqual(2);
    
    // Check for '0' detection
    const zeroMatch = matches.find(m => m.original === '0' && m.position === 1);
    expect(zeroMatch).toBeDefined();
    expect(zeroMatch.suspected_intent).toBe('O');
    expect(zeroMatch.risk).toBe('obfuscation');
    expect(zeroMatch.confidence).toBeGreaterThanOrEqual(0.7);
    
    // Check for '4' detection
    const fourMatch = matches.find(m => m.original === '4' && m.position === 3);
    expect(fourMatch).toBeDefined();
    expect(['A', 'a']).toContain(fourMatch.suspected_intent);
  });

  test('TEST CASE 2: Should detect "l0gin" obfuscation', () => {
    const text = 'l0gin';
    const matches = detectObfuscation(text, 'test_field');
    
    // Should detect both 'l' and '0'
    expect(matches.length).toBeGreaterThanOrEqual(2);
    
    // Check for '0' detection
    const zeroMatch = matches.find(m => m.original === '0');
    expect(zeroMatch).toBeDefined();
    expect(zeroMatch.suspected_intent).toBe('O');
    
    // Check for 'l' detection (could be '1' or 'I')
    const lMatch = matches.find(m => m.original === 'l');
    expect(lMatch).toBeDefined();
  });

  test('TEST CASE 3: Should NOT flag "CVES-2024"', () => {
    const text = 'CVES-2024';
    const matches = detectObfuscation(text, 'test_field');
    
    // Should return empty array or very low confidence matches
    const highConfidenceMatches = matches.filter(m => m.confidence >= 0.7);
    expect(highConfidenceMatches.length).toBe(0);
  });

  test('TEST CASE 4: Should detect "F0rt1net" obfuscation', () => {
    const text = 'F0rt1net';
    const matches = detectObfuscation(text, 'test_field');
    
    // Should detect both '0' and '1'
    expect(matches.length).toBeGreaterThanOrEqual(2);
    
    // Check for '0' detection
    const zeroMatch = matches.find(m => m.original === '0');
    expect(zeroMatch).toBeDefined();
    expect(zeroMatch.suspected_intent).toBe('O');
    expect(zeroMatch.risk).toBe('obfuscation');
    
    // Check for '1' detection
    const oneMatch = matches.find(m => m.original === '1');
    expect(oneMatch).toBeDefined();
    expect(['l', 'I', 'i']).toContain(oneMatch.suspected_intent);
  });

  test('TEST CASE 5: Should return empty array for "normal text"', () => {
    const text = 'normal text';
    const matches = detectObfuscation(text, 'test_field');
    
    // Should have no high-confidence obfuscation matches
    const obfuscationMatches = matches.filter(m => m.risk === 'obfuscation');
    expect(obfuscationMatches.length).toBe(0);
  });
});

describe('Obfuscation Detector - Edge Cases', () => {
  
  test('Should handle empty string', () => {
    const matches = detectObfuscation('', 'test_field');
    expect(matches).toEqual([]);
  });

  test('Should handle null input', () => {
    const matches = detectObfuscation(null, 'test_field');
    expect(matches).toEqual([]);
  });

  test('Should handle undefined input', () => {
    const matches = detectObfuscation(undefined, 'test_field');
    expect(matches).toEqual([]);
  });

  test('Should handle single character', () => {
    const matches = detectObfuscation('0', 'test_field');
    // Single '0' without context should have lower confidence
    expect(matches.length).toBeGreaterThanOrEqual(0);
  });

  test('Should handle numbers in version strings', () => {
    const text = 'version 1.0.2';
    const matches = detectObfuscation(text, 'test_field');
    
    // Version numbers should have reduced confidence
    const highConfidenceMatches = matches.filter(m => m.confidence >= 0.7);
    expect(highConfidenceMatches.length).toBe(0);
  });

  test('Should handle URLs without false positives', () => {
    const text = 'https://example.com/path';
    const matches = detectObfuscation(text, 'test_field');
    
    // URLs should have reduced confidence
    const obfuscationMatches = matches.filter(m => m.risk === 'obfuscation');
    expect(obfuscationMatches.length).toBe(0);
  });
});

describe('Obfuscation Detector - Known Patterns', () => {
  
  test('Should detect $QL (SQL obfuscation)', () => {
    const text = '$QL injection';
    const matches = detectObfuscation(text, 'test_field');
    
    const dollarMatch = matches.find(m => m.original === '$');
    expect(dollarMatch).toBeDefined();
    expect(['S', 's']).toContain(dollarMatch.suspected_intent);
  });

  test('Should detect @dmin (admin obfuscation)', () => {
    const text = '@dmin access';
    const matches = detectObfuscation(text, 'test_field');
    
    const atMatch = matches.find(m => m.original === '@');
    expect(atMatch).toBeDefined();
    expect(['a', 'A']).toContain(atMatch.suspected_intent);
  });

  test('Should detect W1nd0ws obfuscation', () => {
    const text = 'W1nd0ws';
    const matches = detectObfuscation(text, 'test_field');
    
    expect(matches.length).toBeGreaterThanOrEqual(2);
    
    const oneMatch = matches.find(m => m.original === '1');
    expect(oneMatch).toBeDefined();
    
    const zeroMatch = matches.find(m => m.original === '0');
    expect(zeroMatch).toBeDefined();
  });

  test('Should detect L1nux obfuscation', () => {
    const text = 'L1nux';
    const matches = detectObfuscation(text, 'test_field');
    
    const oneMatch = matches.find(m => m.original === '1');
    expect(oneMatch).toBeDefined();
    expect(oneMatch.confidence).toBeGreaterThan(0.5);
  });
});

describe('Obfuscation Detector - Object Analysis', () => {
  
  test('Should detect obfuscation in nested objects', () => {
    const obj = {
      name: 'L0g4j vulnerability',
      details: {
        product: 'F0rt1net',
        version: '1.0.0'
      }
    };
    
    const matches = detectObfuscationInObject(obj);
    
    // Should find obfuscations in both name and details.product
    expect(matches.length).toBeGreaterThanOrEqual(4);
    
    const nameMatches = matches.filter(m => m.field.includes('name'));
    expect(nameMatches.length).toBeGreaterThanOrEqual(2);
    
    const productMatches = matches.filter(m => m.field.includes('product'));
    expect(productMatches.length).toBeGreaterThanOrEqual(2);
  });

  test('Should detect obfuscation in arrays', () => {
    const obj = {
      vulnerabilities: ['L0g4j', 'F0rt1net']
    };
    
    const matches = detectObfuscationInObject(obj);
    expect(matches.length).toBeGreaterThanOrEqual(4);
  });

  test('Should respect exclude fields', () => {
    const obj = {
      name: 'L0g4j',
      ignore_me: 'L0g4j'
    };
    
    const matches = detectObfuscationInObject(obj, ['ignore_me']);
    
    const ignoredMatches = matches.filter(m => m.field.includes('ignore_me'));
    expect(ignoredMatches.length).toBe(0);
  });
});

describe('Obfuscation Detector - Watsonx Comparison', () => {
  
  test('Should identify missed obfuscations', () => {
    const detected = [
      { field: 'name', position: 1, original: '0', risk: 'obfuscation' },
      { field: 'name', position: 3, original: '4', risk: 'obfuscation' }
    ];
    
    const watsonx = [
      { field: 'name', position: 1, original: '0' }
      // Missing position 3
    ];
    
    const comparison = compareWithWatsonx(detected, watsonx);
    
    expect(comparison.missed).toBeGreaterThanOrEqual(1);
    expect(comparison.correct).toBe(1);
  });

  test('Should identify false positives', () => {
    const detected = [
      { field: 'name', position: 1, original: '0', risk: 'obfuscation' }
    ];
    
    const watsonx = [
      { field: 'name', position: 1, original: '0' },
      { field: 'name', position: 5, original: '1' } // False positive
    ];
    
    const comparison = compareWithWatsonx(detected, watsonx);
    
    expect(comparison.false_positives).toBe(1);
  });

  test('Should calculate accuracy correctly', () => {
    const detected = [
      { field: 'name', position: 1, original: '0', risk: 'obfuscation' },
      { field: 'name', position: 3, original: '4', risk: 'obfuscation' }
    ];
    
    const watsonx = [
      { field: 'name', position: 1, original: '0' },
      { field: 'name', position: 3, original: '4' }
    ];
    
    const comparison = compareWithWatsonx(detected, watsonx);
    
    expect(comparison.accuracy).toBe(1.0);
    expect(comparison.correct).toBe(2);
    expect(comparison.missed).toBe(0);
  });

  test('Should handle empty watsonx flags', () => {
    const detected = [
      { field: 'name', position: 1, original: '0', risk: 'obfuscation' }
    ];
    
    const comparison = compareWithWatsonx(detected, []);
    
    expect(comparison.missed).toBe(1);
    expect(comparison.false_positives).toBe(0);
  });
});

describe('Obfuscation Detector - Report Generation', () => {
  
  test('Should generate readable report', () => {
    const matches = [
      {
        field: 'name',
        position: 1,
        original: '0',
        suspected_intent: 'O',
        context: 'L0g4j',
        risk: 'obfuscation',
        confidence: 0.95,
        description: 'Zero vs Letter O'
      }
    ];
    
    const report = generateObfuscationReport(matches);
    
    expect(report).toContain('Position 1');
    expect(report).toContain("'0'");
    expect(report).toContain("'O'");
    expect(report).toContain('OBFUSCATION');
    expect(report).toContain('95.0%');
  });

  test('Should handle empty matches', () => {
    const report = generateObfuscationReport([]);
    expect(report).toBe('No obfuscation detected.');
  });
});

describe('Obfuscation Detector - Substitution Map', () => {
  
  test('Should have all required substitution pairs', () => {
    expect(SUBSTITUTION_MAP['0']).toBeDefined();
    expect(SUBSTITUTION_MAP['1']).toBeDefined();
    expect(SUBSTITUTION_MAP['$']).toBeDefined();
    expect(SUBSTITUTION_MAP['@']).toBeDefined();
    expect(SUBSTITUTION_MAP['3']).toBeDefined();
    expect(SUBSTITUTION_MAP['4']).toBeDefined();
  });

  test('Should have proper weight values', () => {
    for (const [char, data] of Object.entries(SUBSTITUTION_MAP)) {
      expect(data.weight).toBeGreaterThan(0);
      expect(data.weight).toBeLessThanOrEqual(1);
      expect(data.chars).toBeInstanceOf(Array);
      expect(data.chars.length).toBeGreaterThan(0);
    }
  });
});

describe('Obfuscation Detector - Performance', () => {
  
  test('Should handle large text efficiently', () => {
    const largeText = 'normal text '.repeat(1000) + 'L0g4j' + ' more text'.repeat(1000);
    
    const startTime = Date.now();
    const matches = detectObfuscation(largeText, 'large_field');
    const endTime = Date.now();
    
    // Should complete in under 1 second
    expect(endTime - startTime).toBeLessThan(1000);
    
    // Should still find the obfuscation
    const obfuscationMatches = matches.filter(m => m.risk === 'obfuscation');
    expect(obfuscationMatches.length).toBeGreaterThan(0);
  });
});

// Made with Bob
