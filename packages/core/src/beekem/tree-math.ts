/**
 * Tree math utilities for BeeKEM's left-balanced binary tree.
 *
 * Based on the MLS RFC 9420 tree math (Appendix C).
 *
 * For an eight-leaf tree, breadth layout uses root 7; its children 3 and 11;
 * the next internal level 1, 5, 9, and 13; and leaves 0, 2, 4, 6, 8, 10, 12,
 * and 14.
 *
 * - Leaves are at even indices (0, 2, 4, ...)
 * - Internal nodes are at odd indices (1, 3, 5, ...)
 * - The level of a node equals the number of trailing 1-bits in its index
 */

const MAX_TREE_MATH_LEAVES = 1 << 30;
const MAX_TREE_TRAVERSAL_STEPS = 31;

/** Throws if the value is negative or not a safe integer. */
function assertNonNegativeSafeInt(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `${name} must be a non-negative safe integer, got ${value}`,
    );
  }
}

function assertLeafCount(numLeaves: number): void {
  if (
    !Number.isSafeInteger(numLeaves) ||
    numLeaves < 1 ||
    numLeaves > MAX_TREE_MATH_LEAVES
  ) {
    throw new Error(
      `numLeaves must be an integer from 1 to ${MAX_TREE_MATH_LEAVES}, got ${numLeaves}`,
    );
  }
}

/** Returns true if the node index is a leaf (even index). */
export function isLeaf(index: number): boolean {
  return (index & 1) === 0;
}

/** Returns true if the node index is an internal node (odd index). */
export function isInternal(index: number): boolean {
  return (index & 1) === 1;
}

/**
 * Level of a node in the tree.
 * Leaves are level 0; the level equals the number of trailing 1-bits.
 */
export function level(index: number): number {
  assertNonNegativeSafeInt(index, 'index');
  let k = 0;
  let remaining = index;
  while (remaining % 2 === 1) {
    k++;
    remaining = (remaining - 1) / 2;
  }
  return k;
}

/** Total node count for a tree with numLeaves leaves. */
function nodeWidth(numLeaves: number): number {
  return numLeaves === 0 ? 0 : 2 * numLeaves - 1;
}

/** Floor of log2(x). Returns the position of the most significant 1-bit. */
function log2(x: number): number {
  assertNonNegativeSafeInt(x, 'x');
  if (x === 0) return 0;
  let k = 0;
  while ((x >> k) !== 0) {
    k++;
  }
  return k - 1;
}

/**
 * Left child of an internal node.
 * @throws if the node is a leaf
 */
export function left(index: number): number {
  const k = level(index);
  if (k === 0) throw new Error('Leaves have no children');
  return index ^ (1 << (k - 1));
}

/**
 * Right child of an internal node.
 * For non-power-of-2 trees, clamps to the rightmost valid node.
 * @throws if the node is a leaf
 */
export function right(index: number, numLeaves?: number): number {
  const k = level(index);
  if (k === 0) throw new Error('Leaves have no children');
  let r = index ^ (0b11 << (k - 1));
  // For non-power-of-2 leaf counts, clamp to valid range
  if (numLeaves !== undefined) {
    const w = nodeWidth(numLeaves);
    while (r >= w) {
      r = left(r);
    }
  }
  return r;
}

/**
 * One step of the parent computation (bitwise formula).
 */
function parentStep(index: number): number {
  const k = level(index);
  return (index | (1 << k)) & ~(1 << (k + 1));
}

/**
 * Parent of a node, given total number of leaves in the tree.
 *
 * For non-power-of-2 trees, repeatedly applies parentStep until
 * the result falls within the valid node range.
 * @throws if the node is the root
 */
export function parent(index: number, numLeaves: number): number {
  assertLeafCount(numLeaves);
  assertNonNegativeSafeInt(index, 'index');
  const w = nodeWidth(numLeaves);
  if (index >= w) {
    throw new Error(`index ${index} is outside the ${w}-node tree`);
  }
  const r = root(numLeaves);
  if (index === r) throw new Error('Root has no parent');

  const visited = new Set<number>([index]);
  let current = index;
  for (let step = 0; step < MAX_TREE_TRAVERSAL_STEPS; step++) {
    const next = parentStep(current);
    if (
      !Number.isSafeInteger(next) ||
      next < 0 ||
      next === current ||
      visited.has(next)
    ) {
      throw new Error('Parent traversal made no progress');
    }
    if (next < w) return next;
    visited.add(next);
    current = next;
  }
  throw new Error('Parent traversal exceeded the supported depth');
}

/**
 * Sibling of a node (the other child of the same parent).
 */
export function sibling(index: number, numLeaves: number): number {
  const p = parent(index, numLeaves);
  if (left(p) === index) return right(p, numLeaves);
  return left(p);
}

/**
 * Direct path from a leaf to the root (exclusive of leaf, inclusive of root).
 */
export function directPath(leafIndex: number, numLeaves: number): number[] {
  assertLeafCount(numLeaves);
  assertNonNegativeSafeInt(leafIndex, 'leafIndex');
  const w = nodeWidth(numLeaves);
  if (!isLeaf(leafIndex) || leafIndex >= w) {
    throw new Error(`leafIndex ${leafIndex} is not a leaf in the ${w}-node tree`);
  }
  if (numLeaves <= 1) return [];
  const r = root(numLeaves);
  const path: number[] = [];
  const visited = new Set<number>([leafIndex]);
  let current = leafIndex;
  while (current !== r) {
    if (path.length >= MAX_TREE_TRAVERSAL_STEPS) {
      throw new Error('Direct-path traversal exceeded the supported depth');
    }
    const next = parent(current, numLeaves);
    if (next === current || visited.has(next)) {
      throw new Error('Direct-path traversal made no progress');
    }
    visited.add(next);
    path.push(next);
    current = next;
  }
  return path;
}

/**
 * Copath: siblings of the leaf and nodes on the direct path (excluding root).
 * These are the nodes whose public keys are needed to encrypt path updates.
 */
export function copath(leafIndex: number, numLeaves: number): number[] {
  const dp = directPath(leafIndex, numLeaves);
  if (dp.length === 0) return [];
  // The first sibling is the sibling of the leaf itself, then siblings of path nodes
  const nodes = [leafIndex, ...dp.slice(0, -1)]; // all except root
  return nodes.map((n) => sibling(n, numLeaves));
}

/**
 * Root node index for a tree with numLeaves leaves.
 */
export function root(numLeaves: number): number {
  if (numLeaves === 0) throw new Error('Tree must have at least one leaf');
  assertLeafCount(numLeaves);
  if (numLeaves === 1) return 0;
  const w = nodeWidth(numLeaves);
  return (1 << log2(w)) - 1;
}

/** Convert leaf position (0-based member index) to tree node index. */
export function leafToNodeIndex(leafPosition: number): number {
  return leafPosition * 2;
}

/** Convert tree node index to leaf position (0-based member index). */
export function nodeToLeafIndex(nodeIndex: number): number {
  if (!isLeaf(nodeIndex)) throw new Error('Not a leaf node');
  return nodeIndex >> 1;
}
