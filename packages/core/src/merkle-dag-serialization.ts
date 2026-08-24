import {
  CRDTChangeNode,
  CRDTChangeNodeDeferred,
  CRDTChangeNodeKind,
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';

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
  children?: { [hash: string]: CRDTChangeNodeWire<TOut> } | CRDTChangeNodeDeferred;
};

/**
 * Recursively serialize a `CRDTChangeNode` tree by transforming each node's
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
  const change = node.change !== undefined ? encodeLeaf(node.change) : undefined;
  if (node.children !== undefined && node.children !== crdtChangeNodeDeferred) {
    // Use a null-prototype dictionary so that hash keys coming from peer
    // wire messages (e.g. `__proto__`, `constructor`) cannot mutate the
    // shared `Object.prototype` or otherwise alter lookup semantics.
    const children: { [hash: string]: CRDTChangeNodeWire<TOut> } =
      Object.create(null);
    for (const [hash, child] of Object.entries(node.children)) {
      children[hash] = serializeChangeNodeForJSON(child, encodeLeaf);
    }
    return {
      ...node,
      change,
      children,
    };
  }
  return {
    ...node,
    change,
    children: node.children,
  };
}

/**
 * Inverse of {@link serializeChangeNodeForJSON}: recursively reconstruct a
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
  // Wire input is untrusted: a malformed peer can send `null`, an array, or
  // a primitive in place of a node object. Reading `node.kind` on those
  // values would throw a bare `TypeError` (`Cannot read properties of null`)
  // that is hard to attribute back to the peer; reject up front with a
  // descriptive error instead. This also denies a trivial DoS path where a
  // peer crashes the deserializer by supplying `changes: null`.
  if (typeof node !== 'object' || node === null || Array.isArray(node)) {
    throw new Error(
      `Invalid merkle-dag node: expected a plain object (got ${describeValue(
        node,
      )})`,
    );
  }
  // Wire input is untrusted: a malformed peer message can omit or supply a
  // non-string `kind`. Reject up front so downstream consumers can rely on
  // the discriminant being one of the documented `CRDTChangeNodeKind`s
  // rather than silently propagating an invalid value via `...node`.
  if (!isValidChangeNodeKind(node.kind)) {
    throw new Error(
      `Invalid merkle-dag node: "kind" must be one of ${Array.from(
        VALID_CHANGE_NODE_KINDS,
      )
        .map((k) => JSON.stringify(k))
        .join(', ')} (got ${JSON.stringify(node.kind)})`,
    );
  }
  // Wire input is untrusted: a peer can send `keyID: 123` / object / null
  // in place of the documented `keyID?: string`. Reject any non-string value
  // (when present) so we don't silently propagate it via `...node` and
  // violate the `CRDTChangeNode.keyID?: string` contract.
  if (node.keyID !== undefined && typeof node.keyID !== 'string') {
    throw new Error(
      `Invalid merkle-dag node: "keyID" must be a string when present (got ${describeValue(
        node.keyID,
      )})`,
    );
  }
  const change = node.change !== undefined ? decodeLeaf(node.change) : undefined;
  if (node.children !== undefined && node.children !== crdtChangeNodeDeferred) {
    // Wire input is untrusted: validate the children shape before iterating,
    // since `Object.entries(null)` / non-object inputs throw a `TypeError`
    // that's hard to attribute back to a malformed peer message.
    if (
      typeof node.children !== 'object' ||
      node.children === null ||
      Array.isArray(node.children)
    ) {
      throw new Error(
        'Invalid merkle-dag node: "children" must be an object keyed by hash',
      );
    }
    // Null-prototype dictionary: peer-supplied JSON keys like `__proto__`
    // or `constructor` cannot pollute `Object.prototype` or shadow
    // inherited members on the resulting children map.
    const children: { [hash: string]: CRDTChangeNode<TOut> } =
      Object.create(null);
    for (const [hash, child] of Object.entries(node.children)) {
      // Each child must itself be a plain object (not null, not an array,
      // not a primitive) before we recurse -- otherwise the recursive call
      // would fail deep in the stack with a less helpful error and might
      // partially construct a children map.
      if (
        typeof child !== 'object' ||
        child === null ||
        Array.isArray(child)
      ) {
        throw new Error(
          `Invalid merkle-dag node: child at key ${JSON.stringify(
            hash,
          )} must be a plain object (got ${describeValue(child)})`,
        );
      }
      children[hash] = deserializeChangeNodeFromJSON(
        child as CRDTChangeNodeWire<TIn>,
        decodeLeaf,
      );
    }
    // Construct the output node explicitly rather than spreading `...node`.
    // The wire input is untrusted, so spreading would silently propagate any
    // extra peer-supplied properties into our typed `CRDTChangeNode<TOut>`,
    // including under field names we may add in the future. Listing each
    // field by name keeps the in-memory shape tight to the documented type.
    const result: CRDTChangeNode<TOut> = { kind: node.kind, children };
    if (node.keyID !== undefined) {
      result.keyID = node.keyID;
    }
    if (change !== undefined) {
      result.change = change;
    }
    return result;
  }
  // Same explicit-construction rationale as above; here `children` is either
  // `undefined` or the `crdtChangeNodeDeferred` sentinel, both of which are
  // preserved verbatim.
  const result: CRDTChangeNode<TOut> = { kind: node.kind };
  if (node.keyID !== undefined) {
    result.keyID = node.keyID;
  }
  if (change !== undefined) {
    result.change = change;
  }
  if (node.children !== undefined) {
    result.children = node.children;
  }
  return result;
}
