import { CHANGE_TREE_COMPACTION_DEPTH } from './change-tree-walk.js';
import type { CRDTChangeNode } from './crdt-change-node.js';
import {
  MAX_CROSS_LINKS,
  collectReferencedAncestors,
} from './merkle-cross-links.js';

/**
 * CIDs one generation of the known-change sets may gain before a trim. A
 * peer's retained tree has at most one primary parent and `MAX_CROSS_LINKS`
 * cross-links per level up to the depth-bound compaction depth, so a whole
 * honest tree fits in one generation.
 */
export const KNOWN_CHANGE_GENERATION =
  CHANGE_TREE_COMPACTION_DEPTH * (1 + MAX_CROSS_LINKS);

// How many leading, insertion-ordered entries of each known-change set predate
// its current generation. A set that was never trimmed, including one restored
// from a checkpoint, starts a generation at its first entry.
const generationFloors = new WeakMap<ReadonlySet<string>, number>();

function currentGeneration(known: ReadonlySet<string>): number {
  return known.size - (generationFloors.get(known) ?? 0);
}

/** @internal Whether either known-change set has outgrown its current generation. */
export function knownChangesNeedTrim(
  hashes: ReadonlySet<string>,
  ancestors: ReadonlySet<string>,
): boolean {
  return (
    currentGeneration(hashes) > KNOWN_CHANGE_GENERATION ||
    currentGeneration(ancestors) > KNOWN_CHANGE_GENERATION
  );
}

/**
 * @internal CIDs that stay known across every trim: each node of the retained
 * tree, the snapshot boundary, the recent tips and the current frontier heads.
 */
export function retainedKnownChanges<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType> | undefined,
  snapshotBoundary: string | undefined,
  tips: Iterable<string>,
  heads: Iterable<string>,
): Set<string> {
  const retained = new Set<string>(heads);
  for (const tip of tips) retained.add(tip);
  if (snapshotBoundary) retained.add(snapshotBoundary);
  if (rootId !== undefined) retained.add(rootId);
  if (root !== undefined) collectReferencedAncestors(rootId, root, retained);
  return retained;
}

function dropPreviousGeneration(
  known: Set<string>,
  keep: (cid: string) => boolean,
): void {
  const floor = generationFloors.get(known) ?? 0;
  const dropped: string[] = [];
  let index = 0;
  for (const cid of known) {
    if (index++ >= floor) break;
    if (!keep(cid)) dropped.push(cid);
  }
  for (const cid of dropped) known.delete(cid);
}

/**
 * @internal Trim both known-change sets in place and start a new generation.
 * Entries learned in the current generation are kept, so every CID stays known
 * for at least one full generation. A previous-generation hash is kept only if
 * `retained` names it. A previous-generation referenced ancestor is kept if it
 * is retained or still a known hash, so the frontier (`hashes \ ancestors`) is
 * unchanged whenever `retained` includes every head.
 */
export function trimKnownChanges(
  hashes: Set<string>,
  ancestors: Set<string>,
  retained: ReadonlySet<string>,
): void {
  dropPreviousGeneration(hashes, (cid) => retained.has(cid));
  dropPreviousGeneration(
    ancestors,
    (cid) => retained.has(cid) || hashes.has(cid),
  );
  generationFloors.set(hashes, hashes.size);
  generationFloors.set(ancestors, ancestors.size);
}
