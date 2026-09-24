/**
 * Wire serialization for BeeKEM `PathUpdate`s.
 *
 * `BeeKEM.removeMember` / `BeeKEM.update` / `BeeKEM.processPathUpdate`
 * deal in the runtime `PathUpdate` shape from
 * `packages/core/src/beekem/types.ts`, which is a small
 * record of `Uint8Array`s. The `beekemPathUpdateV1` wire protocol
 * carries this record as a JSON-safe payload inside a
 * `CRDTSyncMessage`, so we need a base64-encoded shape per
 * `Uint8Array` and the matching encoder/decoder pair. V2 is a separate,
 * explicitly-versioned shape; the v1 decoder rejects v2-only fields.
 *
 * The shape and helpers live here, rather than in the BeeKEM module, so
 * `beekem/types.ts` can evolve without coupling runtime types to this wire
 * codec.
 */

import { Base64 } from 'js-base64';
import {
  MAX_BEEKEM_TREE_LEAVES,
  PathNodeUpdate,
  PathNodeUpdateV2,
  PathUpdate,
  PathUpdateV2,
  WelcomeNodePublicKey,
} from './beekem/types.js';
import * as TreeMath from './beekem/tree-math.js';
import {
  createV2DecodeBudget,
  decodeV2Bytes,
  describe,
  encodeRuntimeBytes,
  requireNonNegativeInteger,
  requirePositiveInteger,
  snapshotBoundedArray,
  snapshotPlainObject,
  V2WireCodec,
} from './wire-v2-validation.js';

const MAX_V2_PATH_NODES = 64;
const MAX_V2_BUNDLE_CIPHERTEXT_BYTES = 64 * (4096 + 8) + 4096;
const PATH_UPDATE_V2: V2WireCodec = {
  typeName: 'PathUpdateV2',
  maxAggregateDecodedBytes: 8 * 1024 * 1024,
  maxAggregateWorkItems: 4 * MAX_BEEKEM_TREE_LEAVES,
};
const PATH_UPDATE_V2_FIELDS = [
  'version',
  'generation',
  'parentTreeHash',
  'numLeaves',
  'senderLeafIndex',
  'senderLeafPublicKey',
  'nodes',
  'treeNodePublicKeys',
  'treeHash',
] as const;

/** JSON-safe encoding of a single `PathNodeUpdate`. */
export interface SerializedPathNodeUpdate {
  /** Tree node index. */
  nodeIndex: number;
  /** Base64-encoded raw P-256 SEC1-uncompressed public key. */
  publicKey: string;
  /** Base64-encoded ECIES ciphertext (BeeKEM internal format). */
  encryptedPrivateKey: string;
}

/** JSON-safe encoding of a `PathUpdate`. */
export interface SerializedPathUpdate {
  senderLeafIndex: number;
  /** Base64-encoded raw P-256 SEC1-uncompressed leaf public key. */
  senderLeafPublicKey: string;
  nodes: SerializedPathNodeUpdate[];
}

export interface SerializedEncryptedPathKeyBundle {
  recipientNodeIndex: number;
  ciphertext: string;
}

export interface SerializedPathNodeUpdateV2 {
  nodeIndex: number;
  publicKey: string;
  encryptedPathKeyBundles: SerializedEncryptedPathKeyBundle[];
}

export interface SerializedPathTreeNodePublicKey {
  nodeIndex: number;
  publicKey: string | null;
}

/** Explicit wire shape reserved for `beekemPathUpdateV2`. */
export interface SerializedPathUpdateV2 {
  version: 2;
  generation: number;
  parentTreeHash: string;
  numLeaves: number;
  senderLeafIndex: number;
  senderLeafPublicKey: string;
  nodes: SerializedPathNodeUpdateV2[];
  treeNodePublicKeys: SerializedPathTreeNodePublicKey[];
  treeHash: string;
}

/** Convert a `PathUpdate` to a JSON-safe wire representation. */
export function serializePathUpdateForWire(
  update: PathUpdate,
): SerializedPathUpdate {
  for (const field of [
    'version',
    'generation',
    'parentTreeHash',
    'numLeaves',
    'treeNodePublicKeys',
    'treeHash',
  ]) {
    if (Reflect.has(update, field)) {
      throw new Error(
        `Cannot serialize PathUpdate with v2-only field '${field}' as v1`,
      );
    }
  }
  for (const node of update.nodes) {
    if (Reflect.has(node, 'encryptedPathKeyBundles')) {
      throw new Error(
        "Cannot serialize PathUpdate with v2-only field 'encryptedPathKeyBundles' as v1",
      );
    }
  }
  return {
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: Base64.fromUint8Array(update.senderLeafPublicKey),
    nodes: update.nodes.map((n) => ({
      nodeIndex: n.nodeIndex,
      publicKey: Base64.fromUint8Array(n.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(n.encryptedPrivateKey),
    })),
  };
}

/**
 * Encode the nested v2 PathUpdate value.
 *
 * This codec cannot enforce the shared-protocol request limit because the
 * signed sync-message fields and path framing are added by its caller. The
 * transport sender must enforce that limit on the complete serialized frame;
 * this boundary independently caps arrays, work, and decoded byte material.
 */
export function serializePathUpdateV2ForWire(
  update: PathUpdateV2,
): SerializedPathUpdateV2 {
  // Snapshot and encode only; `deserializePathUpdateV2FromWire` is the single
  // structural validator for the result.
  const budget = createV2DecodeBudget(PATH_UPDATE_V2);
  const raw = snapshotPlainObject(
    update,
    PATH_UPDATE_V2_FIELDS,
    'Invalid PathUpdateV2',
  );
  const numLeaves = requirePositiveInteger(
    raw.numLeaves,
    'numLeaves',
    'PathUpdateV2',
  );
  if (numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid PathUpdateV2: numLeaves exceeds ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const nodes = snapshotBoundedArray(
    raw.nodes,
    MAX_V2_PATH_NODES,
    'Invalid PathUpdateV2: nodes',
    budget,
  ).map((value, nodeOffset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPathKeyBundles'],
      `Invalid PathUpdateV2: node[${nodeOffset}]`,
    );
    return {
      nodeIndex: node.nodeIndex as number,
      publicKey: encodeRuntimeBytes(
        node.publicKey,
        65,
        65,
        `node[${nodeOffset}].publicKey`,
        budget,
      ),
      encryptedPathKeyBundles: snapshotBoundedArray(
        node.encryptedPathKeyBundles,
        numLeaves,
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles`,
        budget,
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles exceeds numLeaves`,
      ).map((value, bundleOffset) => {
        const bundle = snapshotPlainObject(
          value,
          ['recipientNodeIndex', 'ciphertext'],
          `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}]`,
        );
        return {
          recipientNodeIndex: bundle.recipientNodeIndex as number,
          ciphertext: encodeRuntimeBytes(
            bundle.ciphertext,
            1,
            MAX_V2_BUNDLE_CIPHERTEXT_BYTES,
            `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].ciphertext`,
            budget,
          ),
        };
      }),
    };
  });
  const treeNodePublicKeys = snapshotBoundedArray(
    raw.treeNodePublicKeys,
    2 * numLeaves - 1,
    'Invalid PathUpdateV2: treeNodePublicKeys',
    budget,
  ).map((value, nodeOffset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey'],
      `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}]`,
    );
    return {
      nodeIndex: node.nodeIndex as number,
      publicKey:
        node.publicKey === null
          ? null
          : encodeRuntimeBytes(
              node.publicKey,
              65,
              65,
              `treeNodePublicKeys[${nodeOffset}].publicKey`,
              budget,
            ),
    };
  });

  const wire: SerializedPathUpdateV2 = {
    version: raw.version as 2,
    generation: raw.generation as number,
    parentTreeHash: encodeRuntimeBytes(
      raw.parentTreeHash,
      32,
      32,
      'parentTreeHash',
      budget,
    ),
    numLeaves,
    senderLeafIndex: raw.senderLeafIndex as number,
    senderLeafPublicKey: encodeRuntimeBytes(
      raw.senderLeafPublicKey,
      65,
      65,
      'senderLeafPublicKey',
      budget,
    ),
    nodes,
    treeNodePublicKeys,
    treeHash: encodeRuntimeBytes(raw.treeHash, 32, 32, 'treeHash', budget),
  };
  deserializePathUpdateV2FromWire(wire);
  return wire;
}

/**
 * Decode a wire-format `SerializedPathUpdate` back into a `PathUpdate`.
 *
 * Validates the input shape so a malformed peer payload (missing
 * fields, wrong types, etc.) surfaces as a descriptive error
 * instead of a confusing crash inside `BeeKEM.processPathUpdate`.
 * Mirrors the validation posture used by the sync-message
 * deserializers (`YjsJSONSerializer`, `AutomergeJSONSerializer`).
 */
export function deserializePathUpdateFromWire(
  wire: unknown,
): PathUpdate {
  if (typeof wire !== 'object' || wire === null || Array.isArray(wire)) {
    throw new Error(
      `Invalid PathUpdate: expected a plain object, got ${describe(wire)}`,
    );
  }
  const raw = wire as Record<string, unknown>;

  for (const field of [
    'version',
    'generation',
    'parentTreeHash',
    'numLeaves',
    'treeNodePublicKeys',
    'treeHash',
  ]) {
    if (Object.prototype.hasOwnProperty.call(raw, field)) {
      throw new Error(
        `Invalid PathUpdate v1: v2-only field '${field}' is not allowed`,
      );
    }
  }

  if (
    typeof raw.senderLeafIndex !== 'number' ||
    !Number.isInteger(raw.senderLeafIndex) ||
    raw.senderLeafIndex < 0
  ) {
    throw new Error(
      `Invalid PathUpdate: 'senderLeafIndex' must be a non-negative integer (got ${describe(raw.senderLeafIndex)})`,
    );
  }
  if (typeof raw.senderLeafPublicKey !== 'string') {
    throw new Error(
      `Invalid PathUpdate: 'senderLeafPublicKey' must be a base64 string (got ${describe(raw.senderLeafPublicKey)})`,
    );
  }
  if (!Array.isArray(raw.nodes)) {
    throw new Error(
      `Invalid PathUpdate: 'nodes' must be an array (got ${describe(raw.nodes)})`,
    );
  }

  const nodes: PathNodeUpdate[] = raw.nodes.map((n, i) => {
    if (typeof n !== 'object' || n === null || Array.isArray(n)) {
      throw new Error(
        `Invalid PathUpdate: node[${i}] must be a plain object, got ${describe(n)}`,
      );
    }
    const nn = n as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(nn, 'encryptedPathKeyBundles')) {
      throw new Error(
        "Invalid PathUpdate v1: v2-only field 'encryptedPathKeyBundles' is not allowed",
      );
    }
    if (
      typeof nn.nodeIndex !== 'number' ||
      !Number.isInteger(nn.nodeIndex) ||
      nn.nodeIndex < 0
    ) {
      throw new Error(
        `Invalid PathUpdate: node[${i}].nodeIndex must be a non-negative integer (got ${describe(nn.nodeIndex)})`,
      );
    }
    if (typeof nn.publicKey !== 'string') {
      throw new Error(
        `Invalid PathUpdate: node[${i}].publicKey must be a base64 string (got ${describe(nn.publicKey)})`,
      );
    }
    if (typeof nn.encryptedPrivateKey !== 'string') {
      throw new Error(
        `Invalid PathUpdate: node[${i}].encryptedPrivateKey must be a base64 string (got ${describe(nn.encryptedPrivateKey)})`,
      );
    }
    return {
      nodeIndex: nn.nodeIndex,
      publicKey: decodeBase64(nn.publicKey, `node[${i}].publicKey`),
      encryptedPrivateKey: decodeBase64(
        nn.encryptedPrivateKey,
        `node[${i}].encryptedPrivateKey`,
      ),
    };
  });

  return {
    senderLeafIndex: raw.senderLeafIndex,
    senderLeafPublicKey: decodeBase64(
      raw.senderLeafPublicKey,
      'senderLeafPublicKey',
    ),
    nodes,
  };
}

/** Decode and structurally validate the explicit v2 wire representation. */
export function deserializePathUpdateV2FromWire(
  wire: unknown,
): PathUpdateV2 {
  const budget = createV2DecodeBudget(PATH_UPDATE_V2);
  const raw = snapshotPlainObject(
    wire,
    PATH_UPDATE_V2_FIELDS,
    'Invalid PathUpdateV2',
  );
  if (raw.version !== 2) {
    throw new Error("Invalid PathUpdateV2: 'version' must be 2");
  }
  const generation = requirePositiveInteger(
    raw.generation,
    'generation',
    'PathUpdateV2',
  );
  if (generation > 0xffffffff) {
    throw new Error('Invalid PathUpdateV2: generation exceeds 2^32-1');
  }
  const numLeaves = requirePositiveInteger(
    raw.numLeaves,
    'numLeaves',
    'PathUpdateV2',
  );
  if (numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid PathUpdateV2: numLeaves exceeds ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  const senderLeafIndex = requireNonNegativeInteger(
    raw.senderLeafIndex,
    'senderLeafIndex',
    'PathUpdateV2',
  );
  if (senderLeafIndex >= treeWidth || (senderLeafIndex & 1) !== 0) {
    throw new Error(
      "Invalid PathUpdateV2: 'senderLeafIndex' must identify a leaf in the tree",
    );
  }
  const rawNodes = snapshotBoundedArray(
    raw.nodes,
    MAX_V2_PATH_NODES,
    'Invalid PathUpdateV2: nodes',
    budget,
  );
  const rawTreeNodePublicKeys = snapshotBoundedArray(
    raw.treeNodePublicKeys,
    treeWidth,
    'Invalid PathUpdateV2: treeNodePublicKeys',
    budget,
  );
  if (rawTreeNodePublicKeys.length !== treeWidth) {
    throw new Error(
      `Invalid PathUpdateV2: treeNodePublicKeys must contain exactly ${treeWidth} entries`,
    );
  }

  const pathIndices = new Set<number>();
  const nodes: PathNodeUpdateV2[] = rawNodes.map((value, nodeOffset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPathKeyBundles'],
      `Invalid PathUpdateV2: node[${nodeOffset}]`,
    );
    const nodeIndex = requireNonNegativeInteger(
      node.nodeIndex,
      `node[${nodeOffset}].nodeIndex`,
      'PathUpdateV2',
    );
    if (
      nodeIndex >= treeWidth ||
      (nodeIndex & 1) === 0 ||
      pathIndices.has(nodeIndex)
    ) {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}] has an out-of-range, leaf, or duplicate nodeIndex`,
      );
    }
    pathIndices.add(nodeIndex);
    const rawBundles = snapshotBoundedArray(
      node.encryptedPathKeyBundles,
      numLeaves,
      `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles`,
      budget,
      `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles exceeds numLeaves`,
    );

    const recipientIndices = new Set<number>();
    const encryptedPathKeyBundles = rawBundles.map((value, bundleOffset) => {
      const bundle = snapshotPlainObject(
        value,
        ['recipientNodeIndex', 'ciphertext'],
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}]`,
      );
      const recipientNodeIndex = requireNonNegativeInteger(
        bundle.recipientNodeIndex,
        `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].recipientNodeIndex`,
        'PathUpdateV2',
      );
      if (recipientNodeIndex >= treeWidth) {
        throw new Error(
          `Invalid PathUpdateV2: bundle recipient ${recipientNodeIndex} is outside the tree`,
        );
      }
      if (recipientIndices.has(recipientNodeIndex)) {
        throw new Error(
          `Invalid PathUpdateV2: duplicate bundle recipient ${recipientNodeIndex} at node[${nodeOffset}]`,
        );
      }
      recipientIndices.add(recipientNodeIndex);
      const ciphertext = decodeV2Bytes(
        bundle.ciphertext,
        1,
        MAX_V2_BUNDLE_CIPHERTEXT_BYTES,
        `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].ciphertext`,
        budget,
      );
      return { recipientNodeIndex, ciphertext };
    });

    const publicKey = decodeV2Bytes(
      node.publicKey,
      65,
      65,
      `node[${nodeOffset}].publicKey`,
      budget,
    );
    return { nodeIndex, publicKey, encryptedPathKeyBundles };
  });

  const snapshotIndices = new Set<number>();
  const treeNodePublicKeys: WelcomeNodePublicKey[] =
    rawTreeNodePublicKeys.map((value, nodeOffset) => {
      const node = snapshotPlainObject(
        value,
        ['nodeIndex', 'publicKey'],
        `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}]`,
      );
      const nodeIndex = requireNonNegativeInteger(
        node.nodeIndex,
        `treeNodePublicKeys[${nodeOffset}].nodeIndex`,
        'PathUpdateV2',
      );
      if (nodeIndex >= treeWidth || snapshotIndices.has(nodeIndex)) {
        throw new Error(
          `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}] has an out-of-range or duplicate nodeIndex`,
        );
      }
      snapshotIndices.add(nodeIndex);
      const publicKey =
        node.publicKey === null
          ? null
          : decodeV2Bytes(
              node.publicKey,
              65,
              65,
              `treeNodePublicKeys[${nodeOffset}].publicKey`,
              budget,
            );
      return { nodeIndex, publicKey };
    });

  const senderLeafPublicKey = decodeV2Bytes(
    raw.senderLeafPublicKey,
    65,
    65,
    'senderLeafPublicKey',
    budget,
  );
  const parentTreeHash = decodeV2Bytes(
    raw.parentTreeHash,
    32,
    32,
    'parentTreeHash',
    budget,
  );
  const treeHash = decodeV2Bytes(raw.treeHash, 32, 32, 'treeHash', budget);

  validateV2TreeSemantics(
    numLeaves,
    senderLeafIndex,
    senderLeafPublicKey,
    nodes,
    treeNodePublicKeys,
  );

  return {
    version: 2,
    generation,
    parentTreeHash,
    numLeaves,
    senderLeafIndex,
    senderLeafPublicKey,
    nodes,
    treeNodePublicKeys,
    treeHash,
  };
}

function validateV2TreeSemantics(
  numLeaves: number,
  senderLeafIndex: number,
  senderLeafPublicKey: Uint8Array,
  nodes: readonly PathNodeUpdateV2[],
  treeNodePublicKeys: readonly WelcomeNodePublicKey[],
): void {
  const directPath = TreeMath.directPath(senderLeafIndex, numLeaves);
  if (
    nodes.length !== directPath.length ||
    nodes.some((node, offset) => node.nodeIndex !== directPath[offset])
  ) {
    throw new Error(
      'Invalid PathUpdateV2: nodes must equal the sender direct path in leaf-to-root order',
    );
  }

  const publicKeysByNode = new Map<number, Uint8Array | null>(
    treeNodePublicKeys.map((node) => [node.nodeIndex, node.publicKey]),
  );
  const snapshotSenderKey = publicKeysByNode.get(senderLeafIndex);
  if (
    snapshotSenderKey === undefined ||
    snapshotSenderKey === null ||
    !bytesEqual(snapshotSenderKey, senderLeafPublicKey)
  ) {
    throw new Error(
      'Invalid PathUpdateV2: senderLeafPublicKey does not match the tree snapshot',
    );
  }

  const copath = TreeMath.copath(senderLeafIndex, numLeaves);
  for (let offset = 0; offset < nodes.length; offset++) {
    const node = nodes[offset]!;
    const snapshotPathKey = publicKeysByNode.get(node.nodeIndex);
    if (
      snapshotPathKey === undefined ||
      snapshotPathKey === null ||
      !bytesEqual(snapshotPathKey, node.publicKey)
    ) {
      throw new Error(
        `Invalid PathUpdateV2: node[${offset}].publicKey does not match the tree snapshot`,
      );
    }

    const expectedRecipients = new Set(
      resolveSnapshotNode(copath[offset]!, numLeaves, publicKeysByNode),
    );
    if (
      node.encryptedPathKeyBundles.length !== expectedRecipients.size ||
      node.encryptedPathKeyBundles.some(
        (bundle) => !expectedRecipients.has(bundle.recipientNodeIndex),
      )
    ) {
      throw new Error(
        `Invalid PathUpdateV2: node[${offset}] bundle recipients do not match its copath resolution`,
      );
    }
  }
}

function resolveSnapshotNode(
  nodeIndex: number,
  numLeaves: number,
  publicKeysByNode: ReadonlyMap<number, Uint8Array | null>,
): number[] {
  const publicKey = publicKeysByNode.get(nodeIndex);
  if (publicKey === undefined) {
    throw new Error(
      `Invalid PathUpdateV2: tree snapshot is missing node ${nodeIndex}`,
    );
  }
  if (publicKey !== null) return [nodeIndex];
  if (TreeMath.isLeaf(nodeIndex)) return [];
  return [
    ...resolveSnapshotNode(
      TreeMath.left(nodeIndex),
      numLeaves,
      publicKeysByNode,
    ),
    ...resolveSnapshotNode(
      TreeMath.right(nodeIndex, numLeaves),
      numLeaves,
      publicKeysByNode,
    ),
  ];
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((byte, offset) => byte === right[offset])
  );
}

/**
 * Decode a base64 string with field-level error context. A malformed
 * peer payload that survives the per-field type checks above but
 * carries syntactically-invalid base64 in one of the `Uint8Array`
 * fields would otherwise throw a generic decoder error with no
 * indication of which field failed. Wrap each decode so the message
 * names the field, making protocol-level debugging tractable.
 */
function decodeBase64(value: string, fieldName: string): Uint8Array {
  try {
    return Base64.toUint8Array(value);
  } catch (err) {
    throw new Error(
      `path-update wire: invalid base64 for field ${fieldName}: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }
}
