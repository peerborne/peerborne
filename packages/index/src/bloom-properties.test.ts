import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { BloomFilterCRDT } from './bloom-filter-crdt.js';

const terms = fc.array(fc.string({ maxLength: 50 }), { maxLength: 50 });
describe('Bloom CRDT generated algebra', () => {
  test('merge is associative, commutative, idempotent and preserves all inserted terms', () => {
    fc.assert(
      fc.property(
        terms,
        terms,
        terms,
        fc.integer({ min: 1, max: 8 }),
        (a, b, c, hashes) => {
          const create = (values: string[]) => {
            const filter = new BloomFilterCRDT(1024, hashes);
            values.forEach((value) => filter.add(value));
            return filter;
          };
          const copy = (filter: BloomFilterCRDT) =>
            BloomFilterCRDT.deserialize(filter.serialize(), 1024, hashes);
          const left = create(a),
            right = create(b),
            third = create(c);
          const original = left.serialize();
          left.merge(left);
          expect([...left.serialize()]).toEqual([...original]);
          const ab = copy(left),
            ba = copy(right);
          ab.merge(right);
          ba.merge(left);
          expect([...ab.serialize()]).toEqual([...ba.serialize()]);
          const abc = copy(ab);
          abc.merge(third);
          const bc = copy(right);
          bc.merge(third);
          const a_bc = copy(left);
          a_bc.merge(bc);
          expect([...abc.serialize()]).toEqual([...a_bc.serialize()]);
          for (const term of [...a, ...b, ...c])
            expect(abc.has(term)).toBe(true);
          const encoded = abc.serialize();
          const recovered = BloomFilterCRDT.deserialize(encoded, 1024, hashes);
          encoded.fill(0);
          expect([...recovered.serialize()]).toEqual([...abc.serialize()]);
          expect(abc.fillRatio()).toBeGreaterThanOrEqual(
            Math.max(left.fillRatio(), right.fillRatio(), third.fillRatio()),
          );
          expect(abc.fillRatio()).toBeLessThanOrEqual(1);
        },
      ),
      { seed: 9520, numRuns: 300 },
    );
  });
});
