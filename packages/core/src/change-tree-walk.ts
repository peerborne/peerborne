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
// A change-node level adds both a node object and a children-map object to the
// JSON representation. Keep enough headroom below native JSON serializer stack
// limits that every accepted tree can be re-serialized for signature checks.
export const MAX_CHANGE_TREE_DEPTH = 512;

export interface BoundedChangeTreeEntry<ChangesType> {
  readonly nodeId: string | undefined;
  readonly kind: CRDTChangeNodeKind;
  readonly change: ChangesType | undefined;
}

export interface BoundedChangeTreeOptions {
  readonly rejectDeferred?: boolean;
  readonly stopBelowNodeIds?: ReadonlySet<string>;
  readonly canonicalizeNodeId?: (value: string) => string;
}

export interface BoundedChangeTreeSnapshot<ChangesType> {
  readonly entries: BoundedChangeTreeEntry<ChangesType>[];
  readonly root: Readonly<CRDTChangeNode<ChangesType>>;
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

function assertCanonicalCID(
  value: unknown,
  canonicalize: (value: string) => string,
): asserts value is string {
  if (typeof value !== 'string') {
    throw new TypeError('change tree identifier must be a canonical CID');
  }
  let canonical: string;
  try {
    canonical = canonicalize(value);
  } catch {
    throw new TypeError('change tree identifier must be a canonical CID');
  }
  if (canonical !== value) {
    throw new TypeError('change tree identifier must be a canonical CID');
  }
}

/**
 * Validate and flatten a change tree before a consumer performs any mutation.
 * The iterative walk is stack-safe, rejects object cycles and malformed nodes,
 * and applies aggregate node/edge/depth budgets to aliases as occurrences.
 */
function collectBoundedChangeTreeInternal<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType>,
  options: BoundedChangeTreeOptions,
  snapshotTree: boolean,
): {
  readonly entries: BoundedChangeTreeEntry<ChangesType>[];
  readonly rootSnapshot: CRDTChangeNode<ChangesType> | undefined;
} {
  type Task =
    | {
        readonly phase: 'enter';
        readonly nodeId: string | undefined;
        readonly node: CRDTChangeNode<ChangesType>;
        readonly depth: number;
        readonly parentSnapshot?: Record<
          string,
          CRDTChangeNode<ChangesType>
        >;
        readonly childId?: string;
      }
    | {
        readonly phase: 'leave';
        readonly node: object;
        readonly nodeSnapshot?: CRDTChangeNode<ChangesType>;
        readonly childrenSnapshot?: Record<
          string,
          CRDTChangeNode<ChangesType>
        >;
      };

  const result: BoundedChangeTreeEntry<ChangesType>[] = [];
  const active = new WeakSet<object>();
  const pending: Task[] = [
    { phase: 'enter', nodeId: rootId, node: root, depth: 1 },
  ];
  let edgeCount = 0;
  let rootSnapshot: CRDTChangeNode<ChangesType> | undefined;

  while (pending.length > 0) {
    const task = pending.pop()!;
    if (task.phase === 'leave') {
      active.delete(task.node);
      if (task.childrenSnapshot !== undefined) {
        Object.freeze(task.childrenSnapshot);
      }
      if (task.nodeSnapshot !== undefined) Object.freeze(task.nodeSnapshot);
      continue;
    }

    const { nodeId, node, depth, parentSnapshot, childId } = task;
    if (nodeId !== undefined && options.canonicalizeNodeId !== undefined) {
      assertCanonicalCID(nodeId, options.canonicalizeNodeId);
    }
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
    const nodeSnapshot =
      snapshotTree
        ? ({ ...snapshot } as unknown as CRDTChangeNode<ChangesType>)
        : undefined;
    if (parentSnapshot !== undefined) {
      parentSnapshot[childId!] = nodeSnapshot!;
    } else if (nodeSnapshot !== undefined) {
      rootSnapshot = nodeSnapshot;
    }
    result.push({ nodeId, kind, change });

    if (children === undefined || childrenDeferred) {
      if (nodeSnapshot !== undefined) Object.freeze(nodeSnapshot);
      continue;
    }
    if (nodeId !== undefined && options.stopBelowNodeIds?.has(nodeId)) {
      if (nodeSnapshot !== undefined) {
        nodeSnapshot.children = crdtChangeNodeDeferred;
        Object.freeze(nodeSnapshot);
      }
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
    const childrenSnapshot:
      | Record<string, CRDTChangeNode<ChangesType>>
      | undefined =
      nodeSnapshot === undefined ? undefined : Object.create(null);
    if (nodeSnapshot !== undefined) nodeSnapshot.children = childrenSnapshot!;
    active.add(node);
    pending.push({
      phase: 'leave',
      node,
      nodeSnapshot,
      childrenSnapshot,
    });
    for (let index = childEntries.length - 1; index >= 0; index--) {
      const [childId, childNode] = childEntries[index]!;
      pending.push({
        phase: 'enter',
        nodeId: childId,
        node: childNode,
        depth: depth + 1,
        parentSnapshot: childrenSnapshot,
        childId,
      });
    }
  }

  return { entries: result, rootSnapshot };
}

export function collectBoundedChangeTree<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType>,
  options: BoundedChangeTreeOptions = {},
): BoundedChangeTreeEntry<ChangesType>[] {
  return collectBoundedChangeTreeInternal(rootId, root, options, false)
    .entries;
}

/** Validate a tree and return the exact detached structure that was checked. */
export function snapshotBoundedChangeTree<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType>,
  options: BoundedChangeTreeOptions = {},
): BoundedChangeTreeSnapshot<ChangesType> {
  const { entries, rootSnapshot } = collectBoundedChangeTreeInternal(
    rootId,
    root,
    options,
    true,
  );
  return { entries, root: rootSnapshot! };
}
