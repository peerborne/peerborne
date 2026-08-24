import { describe, expect, test } from '@jest/globals';
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

describe('isLeaf / isInternal', () => {
  test.each([
    [0, true],
    [2, true],
    [4, true],
    [6, true],
    [14, true],
  ])('isLeaf(%i) = %s', (index, expected) => {
    expect(isLeaf(index)).toBe(expected);
    expect(isInternal(index)).toBe(!expected);
  });

  test.each([
    [1, true],
    [3, true],
    [5, true],
    [7, true],
    [13, true],
  ])('isInternal(%i) = %s', (index, expected) => {
    expect(isInternal(index)).toBe(expected);
    expect(isLeaf(index)).toBe(!expected);
  });
});

describe('level', () => {
  test.each([
    [0, 0],
    [2, 0],
    [4, 0],
    [6, 0],
    [1, 1],
    [5, 1],
    [3, 2],
    [7, 3],
    [15, 4],
  ])('level(%i) = %i', (index, expected) => {
    expect(level(index)).toBe(expected);
  });
});

describe('left / right', () => {
  test.each([
    [1, 0, 2],
    [3, 1, 5],
    [5, 4, 6],
    [7, 3, 11],
  ])('left(%i) = %i, right(%i) = %i', (index, expectedLeft, expectedRight) => {
    expect(left(index)).toBe(expectedLeft);
    expect(right(index)).toBe(expectedRight);
  });

  test('throws for leaf nodes', () => {
    expect(() => left(0)).toThrow('Leaves have no children');
    expect(() => right(0)).toThrow('Leaves have no children');
    expect(() => left(2)).toThrow('Leaves have no children');
    expect(() => right(4)).toThrow('Leaves have no children');
  });
});

describe('root', () => {
  test.each([
    [1, 0],
    [2, 1],
    [4, 3],
    [8, 7],
  ])('root(%i) = %i', (numLeaves, expected) => {
    expect(root(numLeaves)).toBe(expected);
  });

  test('throws for 0 leaves', () => {
    expect(() => root(0)).toThrow('Tree must have at least one leaf');
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
});

describe('copath', () => {
  test('4 leaves, leaf 0: siblings of [0, 1] = [2, 5]', () => {
    expect(copath(0, 4)).toEqual([2, 5]);
  });

  test('4 leaves, leaf 4: siblings of [4, 5] = [6, 1]', () => {
    expect(copath(4, 4)).toEqual([6, 1]);
  });
});

describe('leafToNodeIndex / nodeToLeafIndex', () => {
  test.each([
    [0, 0],
    [1, 2],
    [2, 4],
    [3, 6],
  ])('leafToNodeIndex(%i) = %i', (leafPos, nodeIdx) => {
    expect(leafToNodeIndex(leafPos)).toBe(nodeIdx);
  });

  test.each([
    [0, 0],
    [2, 1],
    [4, 2],
    [6, 3],
  ])('nodeToLeafIndex(%i) = %i', (nodeIdx, leafPos) => {
    expect(nodeToLeafIndex(nodeIdx)).toBe(leafPos);
  });

  test('nodeToLeafIndex throws for internal nodes', () => {
    expect(() => nodeToLeafIndex(1)).toThrow('Not a leaf node');
    expect(() => nodeToLeafIndex(3)).toThrow('Not a leaf node');
    expect(() => nodeToLeafIndex(7)).toThrow('Not a leaf node');
  });
});
