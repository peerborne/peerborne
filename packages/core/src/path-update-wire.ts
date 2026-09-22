/** Strict parent-bound BeeKEM PathUpdate V2 serialization. */

import { Base64 } from 'js-base64';
import {
  MAX_BEEKEM_TREE_LEAVES,
  PathNodeUpdateV2,
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

/** Current wire shape for `beekemPathUpdateV2`. */
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
