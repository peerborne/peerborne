import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { defaultStateSelector } from './default-state-selector.js';

describe('default Redux state selector runtime identity', () => {
  test('preserves the supplied JavaScript value and reference without inspecting it', () => {
    fc.assert(
      fc.property(fc.anything(), (value) => {
        expect(
          Object.is(
            defaultStateSelector<any, any, any, any, any, any>(value),
            value,
          ),
        ).toBe(true);
      }),
      { seed: 9547, numRuns: 500 },
    );
  });
});
