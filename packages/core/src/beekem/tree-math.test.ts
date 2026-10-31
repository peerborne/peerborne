import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  isLeaf,
  isInternal,
  level,
  left,
  right,
  root,
  parent,
  sibling,
  directPath,
  leafToNodeIndex,
  nodeToLeafIndex,
  copath,
} from './tree-math.js';

const supportedNode = fc.integer({ min: 0, max: 2 ** 31 - 2 });
const supportedLeafCount = fc.oneof(
  fc.integer({ min: 1, max: 2 ** 30 }),
  fc.constantFrom(1, 2, 3, 5, 8191, 8192, 8193, 2 ** 30 - 1, 2 ** 30),
);

describe('isLeaf / isInternal', () => {
  test('partitions the supported node domain by parity', () => {
    fc.assert(
      fc.property(supportedNode, (index) => {
        expect(isLeaf(index)).toBe(BigInt(index) % 2n === 0n);
        expect(isInternal(index)).toBe(!isLeaf(index));
      }),
      { seed: 9423, numRuns: 1000, examples: [[0], [2 ** 31 - 2]] },
    );
  });

  test('returns false outside the supported node domain', () => {
    for (const index of [-1, 1.5, Number.MAX_SAFE_INTEGER, Number.NaN]) {
      expect(isLeaf(index)).toBe(false);
      expect(isInternal(index)).toBe(false);
    }
  });
});

describe('level', () => {
  test('equals the number of trailing one bits without int32 truncation', () => {
    fc.assert(
      fc.property(supportedNode, (index) => {
        const trailingOnes = index.toString(2).match(/1*$/)![0].length;
        expect(level(index)).toBe(trailingOnes);
      }),
      {
        seed: 9424,
        numRuns: 1000,
        examples: [[0], [2 ** 30 - 1], [2 ** 31 - 2]],
      },
    );
  });

  test('rejects nodes outside the supported arithmetic domain', () => {
    expect(() => level(Number.MAX_SAFE_INTEGER)).toThrow(
      /supported tree-math node range/,
    );
  });
});

describe('left / right', () => {
  test('children straddle each internal node at the preceding level', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 2 ** 30 - 2 }), (position) => {
        const node = 2 * position + 1;
        const lower = left(node);
        const upper = right(node);
        expect(BigInt(lower) + BigInt(upper)).toBe(2n * BigInt(node));
        expect(lower).toBeLessThan(node);
        expect(upper).toBeGreaterThan(node);
        expect(level(lower)).toBe(level(node) - 1);
        expect(level(upper)).toBe(level(node) - 1);
      }),
      { seed: 9425, numRuns: 1000 },
    );
  });

  test('throws for leaf nodes', () => {
    expect(() => left(0)).toThrow('Leaves have no children');
    expect(() => right(0)).toThrow('Leaves have no children');
    expect(() => left(2)).toThrow('Leaves have no children');
    expect(() => right(4)).toThrow('Leaves have no children');
  });

  test('uses safe arithmetic at the largest supported tree level', () => {
    const largestRoot = 2 ** 30 - 1;
    expect(left(largestRoot)).toBe(2 ** 29 - 1);
    expect(right(largestRoot)).toBe(3 * 2 ** 29 - 1);
  });

  test('rejects nodes whose child arithmetic is outside the supported domain', () => {
    expect(() => left(Number.MAX_SAFE_INTEGER)).toThrow(
      /supported tree-math node range/,
    );
    expect(() => right(Number.MAX_SAFE_INTEGER)).toThrow(
      /supported tree-math node range/,
    );
  });
});

describe('root', () => {
  test('is one below the greatest power of two within the node width', () => {
    fc.assert(
      fc.property(supportedLeafCount, (numLeaves) => {
        const width = 2n * BigInt(numLeaves) - 1n;
        const exponent = BigInt(width.toString(2).length - 1);
        expect(BigInt(root(numLeaves))).toBe((1n << exponent) - 1n);
      }),
      { seed: 9426, numRuns: 1000 },
    );
  });

  test('throws for 0 leaves', () => {
    expect(() => root(0)).toThrow('Tree must have at least one leaf');
  });

  test('calculates the largest supported root without 32-bit truncation', () => {
    expect(root(2 ** 30)).toBe(2 ** 30 - 1);
  });
});

describe('parent', () => {
  test.each([
    [0, 4, 1],
    [2, 4, 1],
    [1, 4, 3],
    [4, 4, 5],
    [5, 4, 3],
    [6, 4, 5],
  ])('parent(%i, numLeaves=%i) = %i', (index, numLeaves, expected) => {
    expect(parent(index, numLeaves)).toBe(expected);
  });

  test('throws for root node', () => {
    expect(() => parent(3, 4)).toThrow('Root has no parent');
    expect(() => parent(7, 8)).toThrow('Root has no parent');
  });

  test('clamps the rightmost leaf of a five-leaf tree to root', () => {
    expect(parent(8, 5)).toBe(7);
  });

  test('rejects out-of-range inputs before parent traversal', () => {
    expect(() => parent(Number.MAX_SAFE_INTEGER, 5)).toThrow(
      /supported tree-math node range/,
    );
    expect(() => parent(0, Number.MAX_SAFE_INTEGER)).toThrow(/numLeaves/);
  });
});

describe('sibling', () => {
  test.each([
    [0, 4, 2],
    [2, 4, 0],
    [4, 4, 6],
    [6, 4, 4],
    [1, 4, 5],
    [5, 4, 1],
  ])('sibling(%i, numLeaves=%i) = %i', (index, numLeaves, expected) => {
    expect(sibling(index, numLeaves)).toBe(expected);
  });
});

describe('directPath', () => {
  test('4 leaves, leaf 0', () => {
    expect(directPath(0, 4)).toEqual([1, 3]);
  });

  test('4 leaves, leaf 4 (node index)', () => {
    expect(directPath(4, 4)).toEqual([5, 3]);
  });

  test('8 leaves, leaf 0', () => {
    expect(directPath(0, 8)).toEqual([1, 3, 7]);
  });

  test('1 leaf returns empty path', () => {
    expect(directPath(0, 1)).toEqual([]);
  });

  test('5 leaves, rightmost leaf reaches root without exposing clamped nodes', () => {
    expect(directPath(8, 5)).toEqual([7]);
  });

  test('paths and copaths stay bounded, acyclic and connected across the supported domain', () => {
    const leaf = supportedLeafCount.chain((numLeaves) =>
      fc
        .integer({ min: 0, max: numLeaves - 1 })
        .map((position) => ({ numLeaves, position })),
    );
    fc.assert(
      fc.property(leaf, ({ numLeaves, position }) => {
        const node = leafToNodeIndex(position);
        const path = directPath(node, numLeaves);
        const branch = [node, ...path];
        expect(branch.at(-1)).toBe(root(numLeaves));
        expect(new Set(branch).size).toBe(branch.length);
        expect(path.length).toBeLessThanOrEqual(numLeaves <= 8192 ? 13 : 30);
        branch.forEach((current, index) => {
          expect(current).toBeGreaterThanOrEqual(0);
          expect(current).toBeLessThan(2 * numLeaves - 1);
          if (index > 0) {
            expect(parent(branch[index - 1], numLeaves)).toBe(current);
            expect(level(current)).toBeGreaterThan(level(branch[index - 1]));
          }
        });
        const co = copath(node, numLeaves);
        expect(co).toHaveLength(path.length);
        co.forEach((other, index) => {
          const current = branch[index];
          expect(other).toBeGreaterThanOrEqual(0);
          expect(other).toBeLessThan(2 * numLeaves - 1);
          expect(sibling(current, numLeaves)).toBe(other);
          expect(sibling(other, numLeaves)).toBe(current);
          expect(parent(other, numLeaves)).toBe(path[index]);
        });
      }),
      {
        seed: 9427,
        numRuns: 1000,
        examples: [
          [{ numLeaves: 1, position: 0 }],
          [{ numLeaves: 5, position: 4 }],
          [{ numLeaves: 2 ** 30, position: 2 ** 30 - 1 }],
        ],
      },
    );
  });

  test('rejects invalid leaves before direct-path traversal', () => {
    expect(() => directPath(9, 5)).toThrow(/not a leaf/);
    expect(() => directPath(Number.MAX_SAFE_INTEGER - 1, 5)).toThrow(
      /supported tree-math node range/,
    );
  });
});

describe('copath', () => {
  test('1 leaf returns an empty copath', () => {
    expect(copath(0, 1)).toEqual([]);
  });

  test('4 leaves, leaf 0: siblings of [0, 1] = [2, 5]', () => {
    expect(copath(0, 4)).toEqual([2, 5]);
  });

  test('4 leaves, leaf 4: siblings of [4, 5] = [6, 1]', () => {
    expect(copath(4, 4)).toEqual([6, 1]);
  });
});

describe('leafToNodeIndex / nodeToLeafIndex', () => {
  test('are exact inverses throughout the supported leaf domain', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 2 ** 30 - 1 }), (position) => {
        const node = leafToNodeIndex(position);
        expect(BigInt(node)).toBe(2n * BigInt(position));
        expect(nodeToLeafIndex(node)).toBe(position);
      }),
      { seed: 9428, numRuns: 1000, examples: [[0], [2 ** 30 - 1]] },
    );
  });

  test('nodeToLeafIndex throws for internal nodes', () => {
    expect(() => nodeToLeafIndex(1)).toThrow('Not a leaf node');
    expect(() => nodeToLeafIndex(3)).toThrow('Not a leaf node');
    expect(() => nodeToLeafIndex(7)).toThrow('Not a leaf node');
  });

  test('converts the largest supported leaf without 32-bit truncation', () => {
    const leafPosition = 2 ** 30 - 1;
    const nodeIndex = 2 ** 31 - 2;
    expect(leafToNodeIndex(leafPosition)).toBe(nodeIndex);
    expect(nodeToLeafIndex(nodeIndex)).toBe(leafPosition);
  });

  test('rejects conversions outside the supported arithmetic domain', () => {
    expect(() => leafToNodeIndex(Number.MAX_SAFE_INTEGER)).toThrow(
      /supported tree-math leaf range/,
    );
    expect(() => nodeToLeafIndex(Number.MAX_SAFE_INTEGER - 1)).toThrow(
      /supported tree-math node range/,
    );
  });
});
