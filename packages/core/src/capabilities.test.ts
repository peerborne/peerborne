import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { getFieldPath } from './capabilities.js';

const field = fc
  .array(
    fc
      .integer({ min: 0, max: 0xffff })
      .filter((code) => ![10, 13, 0x2028, 0x2029].includes(code)),
    { maxLength: 80 },
  )
  .map((units) => String.fromCharCode(...units));

describe('field-path extraction outside the formal regex subset', () => {
  test('preserves arbitrary nonempty field suffixes and rejects document-only capabilities', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('/doc/read', '/doc/write', '/doc/admin'),
        field,
        (prefix, path) => {
          expect(getFieldPath(prefix + '/field/' + path)).toBe(
            path.length === 0 ? undefined : path,
          );
          expect(getFieldPath(prefix)).toBeUndefined();
        },
      ),
      {
        seed: 9546,
        numRuns: 1000,
        examples: [
          ['/doc/write', ''],
          ['/doc/read', 'items.0.name'],
        ],
      },
    );
  });
});
