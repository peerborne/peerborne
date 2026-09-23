import {
  CRDTChangeNode,
  CRDTChangeNodeDeferred,
  CRDTChangeNodeKind,
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import {
  MAX_CHANGE_TREE_DEPTH,
  MAX_CHANGE_TREE_EDGES,
  MAX_CHANGE_TREE_NODES,
  snapshotBoundedChangeTree,
} from './change-tree-walk.js';
import {
  snapshotDeepEnumerableData,
  snapshotEnumerableOwnDataObject,
} from './utils.js';

/**
 * Bound all detached change payloads as one value. The synthetic outer array
 * accounts for one property per changed node; the remaining object/property
 * budget is shared by every payload rather than reset for each tree node.
 */
const MERKLE_DAG_CHANGE_SNAPSHOT_LIMITS = {
  maxDepth: MAX_CHANGE_TREE_NODES,
  maxObjects: MAX_CHANGE_TREE_NODES + MAX_CHANGE_TREE_EDGES + 1,
  maxProperties: MAX_CHANGE_TREE_NODES + MAX_CHANGE_TREE_EDGES,
  maxArrayLength: MAX_CHANGE_TREE_NODES + MAX_CHANGE_TREE_EDGES,
  maxValueBytes: 64 * 1024 * 1024,
};

// Allow-list of `kind` discriminants accepted from peer wire messages.
//
// The allow-list is derived from an exhaustive `Record<CRDTChangeNodeKind,
// true>` so that adding a new variant to the `CRDTChangeNodeKind` union will
// be a compile-time error here until the corresponding entry is added: TS
// requires every key of the union to be present in the record literal.
// Using a `ReadonlySet` alone would not give that guarantee -- a strict
// subset of the union is assignable to `ReadonlySet<CRDTChangeNodeKind>`
// without error.
const VALID_CHANGE_NODE_KIND_RECORD: Record<CRDTChangeNodeKind, true> = {
  [crdtDocumentChangeNode]: true,
  [crdtWriterChangeNode]: true,
  [crdtReaderChangeNode]: true,
};
const VALID_CHANGE_NODE_KINDS: ReadonlySet<CRDTChangeNodeKind> = new Set(
  Object.keys(VALID_CHANGE_NODE_KIND_RECORD) as CRDTChangeNodeKind[],
);

/**
 * Maximum number of change nodes on one root-to-leaf wire path. This shared
 * limit also bounds GossipSub trees so native JSON serialization
 * remains stack-safe when signatures require an exact re-encoding.
 */
export const MAX_MERKLE_DAG_DEPTH = MAX_CHANGE_TREE_DEPTH;

function isValidChangeNodeKind(value: unknown): value is CRDTChangeNodeKind {
  return (
    typeof value === 'string' &&
    VALID_CHANGE_NODE_KINDS.has(value as CRDTChangeNodeKind)
  );
}

/**
 * Human-readable label for an unknown value's runtime type, used in wire
 * validation error messages.
 *
 * `typeof` alone reports `'object'` for both `null` and arrays, which
 * obscures common malformed-peer cases. This helper distinguishes those:
 * - `null`           -> `'null'`
 * - any array        -> `'array'`
 * - anything else    -> raw `typeof` result (`'object'`, `'string'`,
 *                      `'number'`, `'boolean'`, `'undefined'`, etc.)
 *
 * Use in validation error strings whenever a field's expected type is not
 * already enforced to be a primitive, so error attribution back to the peer
 * is unambiguous.
 */
export function describeValue(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

/**
 * Wire-shape mirror of `CRDTChangeNode<T>` used during JSON serialization.
 *
 * The `kind` / `keyID` / `children` shape is preserved exactly; only the
 * `change` payload at each leaf is rewritten to a JSON-friendly type by the
 * caller-provided encoder.
 */
export type CRDTChangeNodeWire<TOut> = {
  kind: CRDTChangeNode<unknown>['kind'];
  keyID?: string;
  change?: TOut;
  children?:
    | { [hash: string]: CRDTChangeNodeWire<TOut> }
    | CRDTChangeNodeDeferred;
};

/**
 * Iteratively serialize a `CRDTChangeNode` tree by transforming each node's
 * `change` payload via the provided encoder, preserving the `kind`, `keyID`,
 * and `children` structure for round-tripping through JSON.
 *
 * A `children` value equal to `crdtChangeNodeDeferred` (i.e. `false`) is
 * preserved verbatim so deferred subtrees survive the round-trip.
 *
 * The output is intentionally byte-identical (modulo the leaf encoding) to
 * the input shape so peers running this code interoperate with peers using
 * the prior per-provider helpers.
 *
 * @typeParam TIn  Input leaf payload type (e.g. `Uint8Array` or
 *                 `Uint8Array[]`).
 * @typeParam TOut Output leaf payload type (e.g. `string` or `string[]`).
 * @param node      The change node tree to serialize.
 * @param encodeLeaf Function that maps an input leaf payload to its
 *                  JSON-serializable representation.
 */
export function serializeChangeNodeForJSON<TIn, TOut>(
  node: CRDTChangeNode<TIn>,
  encodeLeaf: (leaf: TIn) => TOut,
): CRDTChangeNodeWire<TOut> {
  // Match the receive-side aggregate policy and validate the whole structure
  // before an encoder callback can observe a partial traversal.
  const { root: preflightRoot } = snapshotBoundedChangeTree(undefined, node);

  type Task =
    | {
        readonly phase: 'enter';
        readonly source: CRDTChangeNode<TIn>;
        readonly parent?: { [hash: string]: CRDTChangeNodeWire<TOut> };
        readonly hash?: string;
      }
    | {
        readonly phase: 'leave';
        readonly source: CRDTChangeNode<TIn>;
      };

  let root!: CRDTChangeNodeWire<TOut>;
  const active = new WeakSet<object>();
  const pending: Task[] = [{ phase: 'enter', source: preflightRoot }];
  while (pending.length > 0) {
    const task = pending.pop()!;
    if (task.phase === 'leave') {
      active.delete(task.source);
      continue;
    }
    const { source, parent, hash } = task;
    if (active.has(source)) {
      throw new TypeError('merkle-dag tree must not contain object cycles');
    }
    active.add(source);
    const change =
      source.change !== undefined ? encodeLeaf(source.change) : undefined;
    // Preserve the prior recursive codec's exact property insertion order.
    // Signatures cover the serialized JSON bytes, so reordering otherwise
    // semantically equivalent node fields would break mixed-version peers.
    const converted = {
      ...source,
      change,
      children: source.children,
    } as unknown as CRDTChangeNodeWire<TOut>;
    if (
      source.children !== undefined &&
      source.children !== crdtChangeNodeDeferred
    ) {
      // Use a null-prototype dictionary so hash keys such as `__proto__` and
      // `constructor` cannot alter shared prototype state or lookup semantics.
      const children: { [hash: string]: CRDTChangeNodeWire<TOut> } =
        Object.create(null);
      converted.children = children;
      pending.push({ phase: 'leave', source });
      const entries = Object.entries(source.children);
      for (let index = entries.length - 1; index >= 0; index--) {
        const [childHash, child] = entries[index]!;
        pending.push({
          phase: 'enter',
          source: child,
          parent: children,
          hash: childHash,
        });
      }
    } else {
      active.delete(source);
    }
    if (parent === undefined) {
      root = converted;
    } else {
      parent[hash!] = converted;
    }
  }
  return root;
}

/**
 * Inverse of {@link serializeChangeNodeForJSON}: iteratively reconstruct a
 * `CRDTChangeNode` tree from its JSON-friendly wire form, decoding each
 * node's `change` payload via the provided decoder.
 *
 * Preserves `crdtChangeNodeDeferred` children verbatim, matching the
 * serializer.
 *
 * Wire input is treated as untrusted: the reconstructed `children` map uses a
 * null prototype so peer-supplied hash keys (e.g. `__proto__`,
 * `constructor`) cannot pollute `Object.prototype` or shadow inherited
 * members. The shape of the node itself is also validated up front: `node`
 * must be a non-null, non-array object; `kind` must be a known
 * {@link CRDTChangeNodeKind} discriminant; and each entry in `children`
 * must be a plain object. A malformed peer message throws a descriptive
 * `Error` rather than a bare `TypeError` from property access on `null` /
 * non-object input, which would otherwise be a trivial DoS vector.
 *
 * @typeParam TIn  Wire leaf payload type (e.g. `string` or `string[]`).
 * @typeParam TOut Decoded leaf payload type (e.g. `Uint8Array` or
 *                 `Uint8Array[]`).
 * @param node       The wire-form change node tree to deserialize.
 * @param decodeLeaf Function that maps a wire leaf payload back to its
 *                   in-memory representation.
 */
export function deserializeChangeNodeFromJSON<TIn, TOut>(
  node: CRDTChangeNodeWire<TIn>,
  decodeLeaf: (leaf: TIn) => TOut,
): CRDTChangeNode<TOut> {
  type Task =
    | {
        readonly phase: 'enter';
        readonly source: CRDTChangeNodeWire<TIn>;
        readonly parent?: { [hash: string]: CRDTChangeNode<TOut> };
        readonly hash?: string;
        readonly depth: number;
      }
    | {
        readonly phase: 'leave';
        readonly source: CRDTChangeNodeWire<TIn>;
      };

  let root!: CRDTChangeNode<TOut>;
  const active = new WeakSet<object>();
  const pending: Task[] = [{ phase: 'enter', source: node, depth: 1 }];
  const changeTargets: CRDTChangeNode<TOut>[] = [];
  const wireChanges: TIn[] = [];
  let nodeCount = 0;
  let edgeCount = 0;
  while (pending.length > 0) {
    const task = pending.pop()!;
    if (task.phase === 'leave') {
      active.delete(task.source);
      continue;
    }
    const { source, parent, hash, depth } = task;
    if (depth > MAX_CHANGE_TREE_DEPTH) {
      throw new RangeError(
        `Invalid merkle-dag tree: exceeds maximum depth ${MAX_CHANGE_TREE_DEPTH}`,
      );
    }
    nodeCount++;
    if (nodeCount > MAX_CHANGE_TREE_NODES) {
      throw new RangeError(
        `Invalid merkle-dag tree: exceeds ${MAX_CHANGE_TREE_NODES} nodes`,
      );
    }
    if (
      typeof source !== 'object' ||
      source === null ||
      Array.isArray(source)
    ) {
      if (hash !== undefined) {
        throw new Error(
          `Invalid merkle-dag node: child at key ${JSON.stringify(
            hash,
          )} must be a plain object (got ${describeValue(source)})`,
        );
      }
      throw new Error(
        `Invalid merkle-dag node: expected a plain object (got ${describeValue(
          source,
        )})`,
      );
    }
    if (active.has(source)) {
      throw new TypeError('merkle-dag tree must not contain object cycles');
    }
    active.add(source);
    const sourceSnapshot = snapshotEnumerableOwnDataObject<
      Record<string, unknown>
    >(source, 'merkle-dag node');
    if (!Object.prototype.hasOwnProperty.call(sourceSnapshot, 'kind')) {
      throw new Error(
        'Invalid merkle-dag node: "kind" must be an own property',
      );
    }
    const kind = sourceSnapshot.kind;
    const keyID = sourceSnapshot.keyID;
    const wireChange = sourceSnapshot.change as TIn | undefined;
    const wireChildren = sourceSnapshot.children;
    if (!isValidChangeNodeKind(kind)) {
      throw new Error(
        `Invalid merkle-dag node: "kind" must be one of ${Array.from(
          VALID_CHANGE_NODE_KINDS,
        )
          .map((kind) => JSON.stringify(kind))
          .join(', ')} (got ${JSON.stringify(kind)})`,
      );
    }
    if (keyID !== undefined && typeof keyID !== 'string') {
      throw new Error(
        `Invalid merkle-dag node: "keyID" must be a string when present (got ${describeValue(
          keyID,
        )})`,
      );
    }

    let decodedChildren:
      | { [hash: string]: CRDTChangeNode<TOut> }
      | CRDTChangeNodeDeferred
      | undefined;
    let stableChildren:
      | Record<string, CRDTChangeNodeWire<TIn>>
      | undefined;
    if (
      wireChildren !== undefined &&
      wireChildren !== crdtChangeNodeDeferred
    ) {
      if (
        typeof wireChildren !== 'object' ||
        wireChildren === null ||
        Array.isArray(wireChildren)
      ) {
        throw new Error(
          'Invalid merkle-dag node: "children" must be an object keyed by hash',
        );
      }
      stableChildren = snapshotEnumerableOwnDataObject<
        Record<string, CRDTChangeNodeWire<TIn>>
      >(wireChildren, 'merkle-dag children');
      decodedChildren = Object.create(null) as {
        [hash: string]: CRDTChangeNode<TOut>;
      };
    } else if (wireChildren !== undefined) {
      decodedChildren = wireChildren;
    }

    // Keep the relative insertion order of every recognized wire field. The
    // surrounding sync-message signature covers exact JSON bytes, so rebuilding
    // a valid node in schema order would make a deserialize/serialize round trip
    // unverifiable. Unknown fields are still dropped.
    const result = {} as CRDTChangeNode<TOut>;
    for (const field of Object.keys(sourceSnapshot)) {
      switch (field) {
        case 'kind':
          result.kind = kind;
          break;
        case 'keyID':
          if (keyID !== undefined) result.keyID = keyID;
          break;
        case 'change':
          if (wireChange !== undefined) {
            // Define the field now to preserve signed JSON field order, but do
            // not retain the caller's mutable payload on the result tree.
            result.change = undefined as unknown as TOut;
            changeTargets.push(result);
            wireChanges.push(wireChange);
          }
          break;
        case 'children':
          if (decodedChildren !== undefined) {
            result.children = decodedChildren;
          }
          break;
      }
    }

    if (stableChildren !== undefined) {
      const children = decodedChildren as {
        [hash: string]: CRDTChangeNode<TOut>;
      };
      pending.push({ phase: 'leave', source });
      const entries = Object.entries(stableChildren);
      edgeCount += entries.length;
      if (
        !Number.isSafeInteger(edgeCount) ||
        edgeCount > MAX_CHANGE_TREE_EDGES
      ) {
        throw new RangeError(
          `Invalid merkle-dag tree: exceeds ${MAX_CHANGE_TREE_EDGES} edges`,
        );
      }
      for (let index = entries.length - 1; index >= 0; index--) {
        const [childHash, child] = entries[index]!;
        pending.push({
          phase: 'enter',
          source: child,
          parent: children,
          hash: childHash,
          depth: depth + 1,
        });
      }
    } else {
      active.delete(source);
    }

    if (parent === undefined) {
      root = result;
    } else {
      parent[hash!] = result;
    }
  }

  // Run provider decoding only after the complete wire topology and all leaf
  // payloads have been validated and detached. Snapshotting one synthetic
  // array applies a single aggregate allocation/work budget to the whole DAG,
  // while the deep snapshot's independent alias copies prevent one decoder
  // callback from mutating a later Automerge `string[]` payload.
  const detachedChanges = snapshotDeepEnumerableData(
    wireChanges,
    'merkle-dag change payloads',
    MERKLE_DAG_CHANGE_SNAPSHOT_LIMITS,
  );
  for (let index = 0; index < detachedChanges.length; index++) {
    changeTargets[index]!.change = decodeLeaf(detachedChanges[index]!);
  }
  return root;
}
