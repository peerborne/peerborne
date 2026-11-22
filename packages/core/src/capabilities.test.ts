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

describe('field-path extraction at the native string boundary', () => {
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

  test('starts at the first complete marker in the final line and preserves UTF-16 code units', () => {
    const input = fc
      .array(
        fc.oneof(
          field,
          fc.constantFrom(
            '/field/',
            '/field',
            '\r\n',
            '\n',
            '\r',
            '\u2028',
            '\u2029',
            '\ud800',
            '\udfff',
          ),
        ),
        { maxLength: 30 },
      )
      .map((parts) => parts.join(''));

    fc.assert(
      fc.property(input, (capability) => {
        const lastLine = capability.split(/[\r\n\u2028\u2029]/).at(-1)!;
        const marker = lastLine.indexOf('/field/');
        const path = marker < 0 ? '' : lastLine.slice(marker + 7);
        expect(getFieldPath(capability)).toBe(path || undefined);
      }),
      {
        seed: 9547,
        numRuns: 1000,
        examples: [
          ['/field/first/field/second'],
          ['/field/first\n/field/second'],
          ['/field/first\u2028'],
          ['/field/\ud800'],
        ],
      },
    );
  });
});
