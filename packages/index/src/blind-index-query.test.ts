import { describe, expect, test, beforeAll } from '@jest/globals';
import { SubtleBlindIndexProvider } from './subtle-blind-index-provider.js';
import { BlindIndexQuery, BlindIndexEntry } from './blind-index-query.js';

describe('BlindIndexQuery', () => {
  let provider: SubtleBlindIndexProvider;
  let query: BlindIndexQuery;
  let masterKey: CryptoKey;
  let nameKey: CryptoKey;

  beforeAll(async () => {
    provider = new SubtleBlindIndexProvider();
    query = new BlindIndexQuery(provider);
    masterKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign'],
    );
    nameKey = await provider.deriveFieldKey(masterKey, 'name');
  });

  async function makeEntry(documentPath: string, name: string): Promise<BlindIndexEntry> {
    const token = await provider.computeToken(nameKey, name);
    return { documentPath, blindIndexTokens: { name: token } };
  }

  describe('exactMatch', () => {
    test('should find matching entries', async () => {
      const entries = [
        await makeEntry('/users/1', 'Alice'),
        await makeEntry('/users/2', 'Bob'),
        await makeEntry('/users/3', 'Alice'),
      ];

      const results = await query.exactMatch(nameKey, 'name', 'Alice', entries);
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath)).toEqual(['/users/1', '/users/3']);
    });

    test('should return empty array when no match', async () => {
      const entries = [
        await makeEntry('/users/1', 'Alice'),
        await makeEntry('/users/2', 'Bob'),
      ];

      const results = await query.exactMatch(nameKey, 'name', 'Charlie', entries);
      expect(results).toHaveLength(0);
    });

    test('should handle empty entries array', async () => {
      const results = await query.exactMatch(nameKey, 'name', 'Alice', []);
      expect(results).toHaveLength(0);
    });

    test('should match case-insensitively (via normalization)', async () => {
      const entries = [await makeEntry('/users/1', 'Alice')];
      const results = await query.exactMatch(nameKey, 'name', 'alice', entries);
      expect(results).toHaveLength(1);
    });
  });

  describe('compoundMatch', () => {
    test.each([
      {
        description: 'matches exact compound key',
        storedValues: [['Alice', 30], ['Bob', 25]],
        queryValues: ['Alice', 30],
        expectedPaths: ['/users/0'],
      },
      {
        description: 'returns multiple matches',
        storedValues: [['Alice', 30], ['Bob', 25], ['Alice', 30]],
        queryValues: ['Alice', 30],
        expectedPaths: ['/users/0', '/users/2'],
      },
      {
        description: 'no match when name differs',
        storedValues: [['Alice', 30]],
        queryValues: ['Bob', 30],
        expectedPaths: [],
      },
      {
        description: 'no match when age differs',
        storedValues: [['Alice', 30]],
        queryValues: ['Alice', 25],
        expectedPaths: [],
      },
      {
        description: 'no match against empty entries',
        storedValues: [],
        queryValues: ['Alice', 30],
        expectedPaths: [],
      },
      {
        description: 'distinguishes field order (values are ordered)',
        storedValues: [['Alice', 30]],
        queryValues: [30, 'Alice'] as (string | number)[],
        expectedPaths: [],
      },
    ])('$description', async ({ storedValues, queryValues, expectedPaths }) => {
      const compoundKey = await provider.deriveFieldKey(masterKey, 'name+age');
      const entries: BlindIndexEntry[] = await Promise.all(
        storedValues.map(async (values: (string | number)[], i: number) => ({
          documentPath: `/users/${i}`,
          blindIndexTokens: { 'name+age': await provider.computeCompoundToken(compoundKey, values) },
        })),
      );

      const results = await query.compoundMatch(compoundKey, 'name+age', queryValues as (string | number)[], entries);
      expect(results.map(r => r.documentPath)).toEqual(expectedPaths);
    });
  });
});
