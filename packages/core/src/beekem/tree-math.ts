import * as tree from '../policy/tree-index.js';

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

const MAX_TREE_MATH_LEAVES = 2 ** 30;
const MAX_TREE_NODE_INDEX = 2 * MAX_TREE_MATH_LEAVES - 2;

/** Throws if the value is negative or not a safe integer. */
function assertNonNegativeSafeInt(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `${name} must be a non-negative safe integer, got ${value}`,
    );
  }
}

function assertSupportedNodeIndex(value: number, name: string): void {
  assertNonNegativeSafeInt(value, name);
  if (value > MAX_TREE_NODE_INDEX) {
    throw new Error(
      `${name} exceeds the supported tree-math node range, got ${value}`,
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
  return (
    Number.isSafeInteger(index) &&
    index >= 0 &&
    index <= MAX_TREE_NODE_INDEX &&
    index % 2 === 0
  );
}

/** Returns true if the node index is an internal node (odd index). */
export function isInternal(index: number): boolean {
  return (
    Number.isSafeInteger(index) &&
    index >= 0 &&
    index <= MAX_TREE_NODE_INDEX &&
    index % 2 === 1
  );
}

/**
 * Level of a node in the tree.
 * Leaves are level 0; the level equals the number of trailing 1-bits.
 */
export function level(index: number): number {
  assertSupportedNodeIndex(index, 'index');
  return tree.nodeLevel(index);
}

/** Total node count for a tree with numLeaves leaves. */
function nodeWidth(numLeaves: number): number {
  return tree.treeWidth(numLeaves);
}

/**
 * Left child of an internal node.
 * @throws if the node is a leaf
 */
export function left(index: number): number {
  const k = level(index);
  if (k === 0) throw new Error('Leaves have no children');
  return tree.leftChild(index);
}

/**
 * Right child of an internal node.
 * For non-power-of-2 trees, clamps to the rightmost valid node.
 * @throws if the node is a leaf
 */
export function right(index: number, numLeaves?: number): number {
  const k = level(index);
  if (k === 0) throw new Error('Leaves have no children');
  if (numLeaves === undefined) return tree.rightChild(index);
  assertTreeNode(index, numLeaves);
  return tree.treeRight(index, numLeaves);
}

function assertTreeNode(index: number, numLeaves: number): void {
  assertLeafCount(numLeaves);
  assertSupportedNodeIndex(index, 'index');
  const width = nodeWidth(numLeaves);
  if (index >= width) {
    throw new Error(`index ${index} is outside the ${width}-node tree`);
  }
}

function assertNonRootNode(index: number, numLeaves: number): void {
  assertTreeNode(index, numLeaves);
  if (index === root(numLeaves)) throw new Error('Root has no parent');
}

/**
 * Parent of a node, given total number of leaves in the tree.
 *
 * For non-power-of-2 trees, repeatedly applies parentStep until
 * the result falls within the valid node range.
 * @throws if the node is the root
 */
export function parent(index: number, numLeaves: number): number {
  assertNonRootNode(index, numLeaves);
  return tree.treeParent(index, numLeaves);
}

/**
 * Sibling of a node (the other child of the same parent).
 */
export function sibling(index: number, numLeaves: number): number {
  assertNonRootNode(index, numLeaves);
  return tree.treeSibling(index, numLeaves);
}

function assertTreeLeaf(leafIndex: number, numLeaves: number): void {
  assertLeafCount(numLeaves);
  assertSupportedNodeIndex(leafIndex, 'leafIndex');
  const width = nodeWidth(numLeaves);
  if (!isLeaf(leafIndex) || leafIndex >= width) {
    throw new Error(
      `leafIndex ${leafIndex} is not a leaf in the ${width}-node tree`,
    );
  }
}

/**
 * Direct path from a leaf to the root (exclusive of leaf, inclusive of root).
 */
export function directPath(leafIndex: number, numLeaves: number): number[] {
  assertTreeLeaf(leafIndex, numLeaves);
  return tree.treeDirectPath(leafIndex, numLeaves);
}

/**
 * Copath: siblings of the leaf and nodes on the direct path (excluding root).
 * These are the nodes whose public keys are needed to encrypt path updates.
 */
export function copath(leafIndex: number, numLeaves: number): number[] {
  assertTreeLeaf(leafIndex, numLeaves);
  return tree.treeCopath(leafIndex, numLeaves);
}

/**
 * Root node index for a tree with numLeaves leaves.
 */
export function root(numLeaves: number): number {
  if (numLeaves === 0) throw new Error('Tree must have at least one leaf');
  assertLeafCount(numLeaves);
  if (numLeaves === 1) return 0;
  return tree.treeRoot(numLeaves);
}

/** Convert leaf position (0-based member index) to tree node index. */
export function leafToNodeIndex(leafPosition: number): number {
  assertNonNegativeSafeInt(leafPosition, 'leafPosition');
  if (leafPosition >= MAX_TREE_MATH_LEAVES) {
    throw new Error(
      `leafPosition exceeds the supported tree-math leaf range, got ${leafPosition}`,
    );
  }
  return tree.leafNodeIndex(leafPosition);
}

/** Convert tree node index to leaf position (0-based member index). */
export function nodeToLeafIndex(nodeIndex: number): number {
  assertSupportedNodeIndex(nodeIndex, 'nodeIndex');
  if (!isLeaf(nodeIndex)) throw new Error('Not a leaf node');
  return tree.leafPosition(nodeIndex);
}
