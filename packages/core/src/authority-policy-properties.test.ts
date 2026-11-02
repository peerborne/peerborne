import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  documentAuthorityControllerIndex,
  isDocumentAuthorityRosterValid,
  canBindDocumentController,
  bindDocumentController,
} from './policy/document-authority.js';

const id = (value: number) => value.toString(16).padStart(64, '0');

test('calibrates authority roles against native noninteger and nonfinite numbers without mutating inputs', () => {
  fc.assert(
    fc.property(
      fc.oneof(
        fc.array(
          fc.oneof(
            fc.integer({ min: -2, max: 5 }),
            fc.constantFrom(NaN, Infinity, -Infinity, -0, 1.5, 2.5, 3.5),
          ),
          { maxLength: 270 },
        ),
        fc
          .tuple(fc.array(fc.constantFrom(1, 2), { maxLength: 255 }), fc.nat())
          .map(([roles, offset]) => {
            const result = roles.slice();
            result.splice(offset % (roles.length + 1), 0, 3);
            return result;
          }),
      ),
      fc.string({ maxLength: 50 }),
      (roles, keyPrefix) => {
        const before = roles.slice();
        const controllers = roles.flatMap((role, index) =>
          role === 3 ? [index] : [],
        );
        const expected =
          roles.length > 0 &&
          roles.length <= 256 &&
          roles.every((role) => [1, 2, 3].includes(role)) &&
          controllers.length === 1;
        expect(documentAuthorityControllerIndex(roles)).toBe(
          expected ? controllers[0] : -1,
        );
        const ids = roles.map((_, index) => id(index));
        const keys = roles.map((_, index) => `${keyPrefix}/${index}`);
        expect(isDocumentAuthorityRosterValid(ids, keys, roles)).toBe(expected);
        expect(roles).toEqual(before);
      },
    ),
    { seed: 2011211, numRuns: 200 },
  );
});

test('keeps bounded controller bindings and detached native Maps across hostile replay histories', () => {
  fc.assert(
    fc.property(
      fc.array(
        fc.record({
          head: fc.oneof(
            fc.string({ maxLength: 10 }),
            fc.constantFrom('__proto__', 'constructor', '\ud800', '\ufeff'),
          ),
          controller: fc.integer({ min: 0, max: 255 }),
          authorized: fc.boolean(),
        }),
        { maxLength: 120 },
      ),
      fc.integer({ min: 0, max: 64 }),
      (attempts, limit) => {
        let bindings = new Map<string, number>();
        const oracle: Array<readonly [string, number]> = [];
        for (const attempt of attempts) {
          const before = bindings,
            snapshot = [...before];
          const fresh =
            oracle.length < limit &&
            !oracle.some(([head]) => head === attempt.head);
          expect(canBindDocumentController(bindings, attempt.head, limit)).toBe(
            fresh,
          );
          if (fresh && attempt.authorized) {
            const candidate = bindDocumentController(
              bindings,
              attempt.head,
              attempt.controller,
              limit,
            );
            expect([...before]).toEqual(snapshot);
            before.clear();
            before.set('mutated-parent', -1);
            expect([...candidate]).toEqual([
              ...oracle,
              [attempt.head, attempt.controller],
            ]);
            candidate.delete('missing-child');
            expect([...before]).toEqual([['mutated-parent', -1]]);
            bindings = candidate;
            oracle.push([attempt.head, attempt.controller]);
          }
          expect([...bindings]).toEqual(oracle);
          expect(bindings.size).toBeLessThanOrEqual(limit);
        }
      },
    ),
    { seed: 2011212, numRuns: 100 },
  );
});
