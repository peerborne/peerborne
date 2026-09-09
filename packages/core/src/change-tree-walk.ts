import {
  type CRDTChangeNode,
  type CRDTChangeNodeKind,
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import { snapshotEnumerableOwnDataObject } from './utils.js';

/** Aggregate limits for one accepted in-memory change tree. */
export const MAX_CHANGE_TREE_NODES = 32_768;
export const MAX_CHANGE_TREE_EDGES = 131_072;
export const MAX_CHANGE_TREE_DEPTH = 32_768;

export interface BoundedChangeTreeEntry<ChangesType> {
  readonly nodeId: string | undefined;
  readonly kind: CRDTChangeNodeKind;
  readonly change: ChangesType | undefined;
}

export interface BoundedChangeTreeOptions {
  readonly rejectDeferred?: boolean;
  readonly stopBelowNodeIds?: ReadonlySet<string>;
}

const VALID_KINDS: ReadonlySet<CRDTChangeNodeKind> = new Set([
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
]);

function isValidKind(value: unknown): value is CRDTChangeNodeKind {
  return (
    typeof value === 'string' &&
    VALID_KINDS.has(value as CRDTChangeNodeKind)
  );
}

/**
 * Validate and flatten a change tree before a consumer performs any mutation.
 * The iterative walk is stack-safe, rejects object cycles and malformed nodes,
 * and applies aggregate node/edge/depth budgets to aliases as occurrences.
 */
export function collectBoundedChangeTree<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType>,
  options: BoundedChangeTreeOptions = {},
): BoundedChangeTreeEntry<ChangesType>[] {
  type Task =
    | {
        readonly phase: 'enter';
        readonly nodeId: string | undefined;
        readonly node: CRDTChangeNode<ChangesType>;
        readonly depth: number;
      }
    | { readonly phase: 'leave'; readonly node: object };

  const result: BoundedChangeTreeEntry<ChangesType>[] = [];
  const active = new WeakSet<object>();
  const pending: Task[] = [
    { phase: 'enter', nodeId: rootId, node: root, depth: 1 },
  ];
  let edgeCount = 0;

  while (pending.length > 0) {
    const task = pending.pop()!;
    if (task.phase === 'leave') {
      active.delete(task.node);
      continue;
    }

    const { nodeId, node, depth } = task;
    if (depth > MAX_CHANGE_TREE_DEPTH) {
      throw new RangeError(
        `change tree exceeds maximum depth ${MAX_CHANGE_TREE_DEPTH}`,
      );
    }
    if (node === null || typeof node !== 'object' || Array.isArray(node)) {
      throw new TypeError('change tree node must be an object');
    }
    if (active.has(node)) {
      throw new TypeError('change tree must not contain object cycles');
    }
    if (result.length >= MAX_CHANGE_TREE_NODES) {
      throw new RangeError(
        `change tree exceeds ${MAX_CHANGE_TREE_NODES} nodes`,
      );
    }

    const snapshot = snapshotEnumerableOwnDataObject<
      Record<string, unknown>
    >(node, 'change tree node');
    const kind = snapshot.kind;
    if (!isValidKind(kind)) {
      throw new TypeError('change tree node has an invalid kind');
    }
    if (snapshot.keyID !== undefined && typeof snapshot.keyID !== 'string') {
      throw new TypeError('change tree node has an invalid keyID');
    }
    const change = snapshot.change as ChangesType | undefined;
    const children = snapshot.children;
    const childrenDeferred = children === crdtChangeNodeDeferred;
    if (childrenDeferred && options.rejectDeferred === true) {
      throw new TypeError('change tree contains a deferred node');
    }
    result.push({ nodeId, kind, change });

    if (
      children === undefined ||
      childrenDeferred ||
      (nodeId !== undefined && options.stopBelowNodeIds?.has(nodeId))
    ) {
      continue;
    }
    if (
      children === null ||
      typeof children !== 'object' ||
      Array.isArray(children)
    ) {
      throw new TypeError('change tree children must be an object');
    }

    const stableChildren = snapshotEnumerableOwnDataObject<
      Record<string, CRDTChangeNode<ChangesType>>
    >(children, 'change tree children');
    const childEntries = Object.entries(stableChildren);
    edgeCount += childEntries.length;
    if (!Number.isSafeInteger(edgeCount) || edgeCount > MAX_CHANGE_TREE_EDGES) {
      throw new RangeError(
        `change tree exceeds ${MAX_CHANGE_TREE_EDGES} edges`,
      );
    }
    active.add(node);
    pending.push({ phase: 'leave', node });
    for (let index = childEntries.length - 1; index >= 0; index--) {
      const [childId, childNode] = childEntries[index]!;
      pending.push({
        phase: 'enter',
        nodeId: childId,
        node: childNode,
        depth: depth + 1,
      });
    }
  }

  return result;
}
