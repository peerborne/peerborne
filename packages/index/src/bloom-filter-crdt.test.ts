import { describe, expect, test } from '@jest/globals';
import { BloomFilterCRDT } from './bloom-filter-crdt.js';

describe('BloomFilterCRDT', () => {
  describe('add and has', () => {
    test('should return true for added terms', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('hello');
      filter.add('world');
      expect(filter.has('hello')).toBe(true);
      expect(filter.has('world')).toBe(true);
    });

    test('should return false for terms not added', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('hello');
      expect(filter.has('goodbye')).toBe(false);
    });

    test('should handle empty strings', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('');
      expect(filter.has('')).toBe(true);
    });

    test('should handle special characters', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('hello world!@#$%');
      expect(filter.has('hello world!@#$%')).toBe(true);
    });

    test('should handle unicode', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('日本語');
      expect(filter.has('日本語')).toBe(true);
      expect(filter.has('中文')).toBe(false);
    });
  });

  describe('false positive rate', () => {
    test('should maintain acceptable false positive rate with 10K terms', () => {
      const filter = new BloomFilterCRDT(131072, 7); // 16 KB, 7 hashes
      const terms = Array.from({ length: 10000 }, (_, i) => `term_${i}`);
      for (const term of terms) {
        filter.add(term);
      }

      // All added terms must be found (no false negatives)
      for (const term of terms) {
        expect(filter.has(term)).toBe(true);
      }

      // Check false positive rate with 10K non-existing terms
      let falsePositives = 0;
      const testTerms = Array.from({ length: 10000 }, (_, i) => `nonexistent_${i}`);
      for (const term of testTerms) {
        if (filter.has(term)) {
          falsePositives++;
        }
      }
      const fpRate = falsePositives / testTerms.length;
      // With 131072 bits, 7 hashes, 10K terms: theoretical FP rate well under 1%
      // Allow up to 10% for statistical variance
      expect(fpRate).toBeLessThan(0.10);
    });
  });

  describe('merge', () => {
    test('should combine filters via bitwise OR', () => {
      const filter1 = new BloomFilterCRDT(1024, 3);
      const filter2 = new BloomFilterCRDT(1024, 3);

      filter1.add('alice');
      filter2.add('bob');

      filter1.merge(filter2);

      expect(filter1.has('alice')).toBe(true);
      expect(filter1.has('bob')).toBe(true);
    });

    test('should be idempotent', () => {
      const filter1 = new BloomFilterCRDT(1024, 3);
      const filter2 = new BloomFilterCRDT(1024, 3);

      filter1.add('alice');
      filter2.add('alice');
      filter2.add('bob');

      const beforeMerge = filter1.fillRatio();
      filter1.merge(filter2);
      const afterFirstMerge = filter1.fillRatio();
      filter1.merge(filter2);
      const afterSecondMerge = filter1.fillRatio();

      // Second merge should not change anything
      expect(afterSecondMerge).toEqual(afterFirstMerge);
    });

    test('should be commutative', () => {
      const filter1a = new BloomFilterCRDT(1024, 3);
      const filter1b = new BloomFilterCRDT(1024, 3);
      const filter2a = new BloomFilterCRDT(1024, 3);
      const filter2b = new BloomFilterCRDT(1024, 3);

      filter1a.add('x');
      filter1b.add('x');
      filter2a.add('y');
      filter2b.add('y');

      filter1a.merge(filter2a); // 1 merge 2
      filter2b.merge(filter1b); // 2 merge 1

      expect(filter1a.serialize()).toEqual(filter2b.serialize());
    });

    test('should throw on different sizes', () => {
      const filter1 = new BloomFilterCRDT(1024, 3);
      const filter2 = new BloomFilterCRDT(2048, 3);
      expect(() => filter1.merge(filter2)).toThrow('different sizes');
    });

    test('should throw on different hash function counts', () => {
      const filter1 = new BloomFilterCRDT(1024, 3);
      const filter2 = new BloomFilterCRDT(1024, 5);
      expect(() => filter1.merge(filter2)).toThrow('different hash function counts');
    });
  });

  describe('constructor validation', () => {
    test('should reject non-positive sizeInBits', () => {
      expect(() => new BloomFilterCRDT(0, 3)).toThrow();
      expect(() => new BloomFilterCRDT(-1, 3)).toThrow();
    });
    test('should reject non-positive numHashFunctions', () => {
      expect(() => new BloomFilterCRDT(1024, 0)).toThrow();
      expect(() => new BloomFilterCRDT(1024, -1)).toThrow();
    });
  });

  describe('serialize/deserialize', () => {
    test('should round-trip correctly', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('hello');
      filter.add('world');

      const data = filter.serialize();
      const restored = BloomFilterCRDT.deserialize(data, 1024, 3);

      expect(restored.has('hello')).toBe(true);
      expect(restored.has('world')).toBe(true);
      expect(restored.has('other')).toBe(false);
    });

    test('should reject data with wrong length', () => {
      expect(() => BloomFilterCRDT.deserialize(new Uint8Array(10), 1024, 3)).toThrow();
    });

    test('should produce independent copy', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      filter.add('hello');
      const data = filter.serialize();
      filter.add('world');

      const restored = BloomFilterCRDT.deserialize(data, 1024, 3);
      expect(restored.has('hello')).toBe(true);
      expect(restored.has('world')).toBe(false); // should not have 'world'
    });
  });

  describe('fillRatio', () => {
    test('should be 0 for empty filter', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      expect(filter.fillRatio()).toBe(0);
    });

    test('should increase as terms are added', () => {
      const filter = new BloomFilterCRDT(1024, 3);
      const r0 = filter.fillRatio();
      filter.add('a');
      const r1 = filter.fillRatio();
      filter.add('b');
      const r2 = filter.fillRatio();
      expect(r1).toBeGreaterThan(r0);
      expect(r2).toBeGreaterThanOrEqual(r1);
    });
  });
});
