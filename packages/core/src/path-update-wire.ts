/** Strict parent-bound BeeKEM PathUpdate V2 serialization. */

import { Base64 } from 'js-base64';
import {
  MAX_BEEKEM_TREE_LEAVES,
  PathNodeUpdateV2,
  PathUpdateV2,
  WelcomeNodePublicKey,
} from './beekem/types.js';
import * as TreeMath from './beekem/tree-math.js';
import { copyUnsharedUint8Array } from './utils.js';

const MAX_V2_PATH_NODES = 64;
const MAX_V2_BUNDLE_CIPHERTEXT_BYTES = 64 * (4096 + 8) + 4096;
const MAX_V2_AGGREGATE_DECODED_BYTES = 8 * 1024 * 1024;
const MAX_V2_AGGREGATE_WORK_ITEMS = 4 * MAX_BEEKEM_TREE_LEAVES;

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
  const budget = createV2DecodeBudget();
  const raw = snapshotPlainObject(
    update,
    [
      'version',
      'generation',
      'parentTreeHash',
      'numLeaves',
      'senderLeafIndex',
      'senderLeafPublicKey',
      'nodes',
      'treeNodePublicKeys',
      'treeHash',
    ],
    'Invalid PathUpdateV2',
  );
  if (raw.version !== 2) {
    throw new Error("Invalid PathUpdateV2: 'version' must be 2");
  }
  requirePositiveInteger(raw.generation, 'generation', 'PathUpdateV2');
  if ((raw.generation as number) > 0xffffffff) {
    throw new Error('Invalid PathUpdateV2: generation exceeds 2^32-1');
  }
  requirePositiveInteger(raw.numLeaves, 'numLeaves', 'PathUpdateV2');
  const numLeaves = raw.numLeaves as number;
  if (numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid PathUpdateV2: numLeaves exceeds ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  requireNonNegativeInteger(
    raw.senderLeafIndex,
    'senderLeafIndex',
    'PathUpdateV2',
  );
  const senderLeafIndex = raw.senderLeafIndex as number;
  if (senderLeafIndex >= treeWidth || (senderLeafIndex & 1) !== 0) {
    throw new Error(
      "Invalid PathUpdateV2: 'senderLeafIndex' must identify a leaf in the tree",
    );
  }
  if (!Array.isArray(raw.nodes)) {
    throw new Error(
      `Invalid PathUpdateV2: 'nodes' must be an array (got ${describe(raw.nodes)})`,
    );
  }
  const rawNodes = snapshotBoundedArray(
    raw.nodes,
    MAX_V2_PATH_NODES,
    'Invalid PathUpdateV2: nodes',
    budget,
  );
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      `Invalid PathUpdateV2: 'treeNodePublicKeys' must be an array (got ${describe(raw.treeNodePublicKeys)})`,
    );
  }
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
  const nodeSnapshots = rawNodes.map((value, nodeOffset) => {
    const node = snapshotPlainObject(
      value,
      [
        'nodeIndex',
        'publicKey',
        'encryptedPathKeyBundles',
      ],
      `Invalid PathUpdateV2: node[${nodeOffset}]`,
    );
    requireNonNegativeInteger(
      node.nodeIndex,
      `node[${nodeOffset}].nodeIndex`,
      'PathUpdateV2',
    );
    const nodeIndex = node.nodeIndex as number;
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
    if (!Array.isArray(node.encryptedPathKeyBundles)) {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles must be an array (got ${describe(node.encryptedPathKeyBundles)})`,
      );
    }
    const rawBundles = snapshotBoundedArray(
      node.encryptedPathKeyBundles,
      numLeaves,
      `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles`,
      budget,
      `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles exceeds numLeaves`,
    );
    const recipientIndices = new Set<number>();
    const bundles = rawBundles.map((value, bundleOffset) => {
      const bundle = snapshotPlainObject(
        value,
        ['recipientNodeIndex', 'ciphertext'],
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}]`,
      );
      requireNonNegativeInteger(
        bundle.recipientNodeIndex,
        `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].recipientNodeIndex`,
        'PathUpdateV2',
      );
      const recipientNodeIndex = bundle.recipientNodeIndex as number;
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
      return { recipientNodeIndex, ciphertext: bundle.ciphertext };
    });
    return {
      nodeIndex,
      publicKey: node.publicKey,
      encryptedPathKeyBundles: bundles,
    };
  });

  const snapshotIndices = new Set<number>();
  const treeNodeSnapshots = rawTreeNodePublicKeys.map((value, nodeOffset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey'],
      `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}]`,
    );
    requireNonNegativeInteger(
      node.nodeIndex,
      `treeNodePublicKeys[${nodeOffset}].nodeIndex`,
      'PathUpdateV2',
    );
    const nodeIndex = node.nodeIndex as number;
    if (nodeIndex >= treeWidth || snapshotIndices.has(nodeIndex)) {
      throw new Error(
        `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}] has an out-of-range or duplicate nodeIndex`,
      );
    }
    snapshotIndices.add(nodeIndex);
    return { nodeIndex, publicKey: node.publicKey };
  });

  const parentTreeHash = snapshotRuntimeBytes(
    raw.parentTreeHash,
    32,
    32,
    'parentTreeHash',
    budget,
  );
  const senderLeafPublicKey = snapshotRuntimeBytes(
    raw.senderLeafPublicKey,
    65,
    65,
    'senderLeafPublicKey',
    budget,
  );
  const detachedNodes = nodeSnapshots.map((node, nodeOffset) => ({
    nodeIndex: node.nodeIndex,
    publicKey: snapshotRuntimeBytes(
      node.publicKey,
      65,
      65,
      `node[${nodeOffset}].publicKey`,
      budget,
    ),
    encryptedPathKeyBundles: node.encryptedPathKeyBundles.map(
      (bundle, bundleOffset) => ({
        recipientNodeIndex: bundle.recipientNodeIndex,
        ciphertext: snapshotRuntimeBytes(
          bundle.ciphertext,
          1,
          MAX_V2_BUNDLE_CIPHERTEXT_BYTES,
          `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].ciphertext`,
          budget,
        ),
      }),
    ),
  }));
  const detachedTreeNodePublicKeys = treeNodeSnapshots.map(
    (node, nodeOffset) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null
          ? null
          : snapshotRuntimeBytes(
              node.publicKey,
              65,
              65,
              `treeNodePublicKeys[${nodeOffset}].publicKey`,
              budget,
            ),
    }),
  );
  const treeHash = snapshotRuntimeBytes(
    raw.treeHash,
    32,
    32,
    'treeHash',
    budget,
  );

  const wire: SerializedPathUpdateV2 = {
    version: raw.version,
    generation: raw.generation as number,
    parentTreeHash: Base64.fromUint8Array(parentTreeHash),
    numLeaves,
    senderLeafIndex,
    senderLeafPublicKey: Base64.fromUint8Array(senderLeafPublicKey),
    nodes: detachedNodes.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: Base64.fromUint8Array(node.publicKey),
      encryptedPathKeyBundles: node.encryptedPathKeyBundles.map(
        (bundle) => ({
          recipientNodeIndex: bundle.recipientNodeIndex,
          ciphertext: Base64.fromUint8Array(bundle.ciphertext),
        }),
      ),
    })),
    treeNodePublicKeys: detachedTreeNodePublicKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null
          ? null
          : Base64.fromUint8Array(node.publicKey),
    })),
    treeHash: Base64.fromUint8Array(treeHash),
  };
  // Keep the outbound boundary fail-closed even if runtime validation and the
  // canonical wire decoder evolve independently.
  deserializePathUpdateV2FromWire(wire);
  return wire;
}

/** Decode and structurally validate the explicit v2 wire representation. */
export function deserializePathUpdateV2FromWire(
  wire: unknown,
): PathUpdateV2 {
  const budget = createV2DecodeBudget();
  const raw = snapshotPlainObject(
    wire,
    [
      'version',
      'generation',
      'parentTreeHash',
      'numLeaves',
      'senderLeafIndex',
      'senderLeafPublicKey',
      'nodes',
      'treeNodePublicKeys',
      'treeHash',
    ],
    'Invalid PathUpdateV2',
  );
  if (raw.version !== 2) {
    throw new Error("Invalid PathUpdateV2: 'version' must be 2");
  }
  requirePositiveInteger(raw.generation, 'generation', 'PathUpdateV2');
  requirePositiveInteger(raw.numLeaves, 'numLeaves', 'PathUpdateV2');
  if ((raw.generation as number) > 0xffffffff) {
    throw new Error('Invalid PathUpdateV2: generation exceeds 2^32-1');
  }
  if (typeof raw.parentTreeHash !== 'string') {
    throw new Error(
      `Invalid PathUpdateV2: 'parentTreeHash' must be a base64 string (got ${describe(raw.parentTreeHash)})`,
    );
  }
  if ((raw.numLeaves as number) > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid PathUpdateV2: numLeaves exceeds ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  requireNonNegativeInteger(
    raw.senderLeafIndex,
    'senderLeafIndex',
    'PathUpdateV2',
  );
  const treeWidth = 2 * (raw.numLeaves as number) - 1;
  if (
    (raw.senderLeafIndex as number) >= treeWidth ||
    ((raw.senderLeafIndex as number) & 1) !== 0
  ) {
    throw new Error(
      "Invalid PathUpdateV2: 'senderLeafIndex' must identify a leaf in the tree",
    );
  }
  if (typeof raw.senderLeafPublicKey !== 'string') {
    throw new Error(
      `Invalid PathUpdateV2: 'senderLeafPublicKey' must be a base64 string (got ${describe(raw.senderLeafPublicKey)})`,
    );
  }
  if (!Array.isArray(raw.nodes)) {
    throw new Error(
      `Invalid PathUpdateV2: 'nodes' must be an array (got ${describe(raw.nodes)})`,
    );
  }
  const rawNodes = snapshotBoundedArray(
    raw.nodes,
    MAX_V2_PATH_NODES,
    'Invalid PathUpdateV2: nodes',
    budget,
  );
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      `Invalid PathUpdateV2: 'treeNodePublicKeys' must be an array (got ${describe(raw.treeNodePublicKeys)})`,
    );
  }
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
  if (typeof raw.treeHash !== 'string') {
    throw new Error(
      `Invalid PathUpdateV2: 'treeHash' must be a base64 string (got ${describe(raw.treeHash)})`,
    );
  }

  const pathIndices = new Set<number>();
  const nodes: PathNodeUpdateV2[] = rawNodes.map((value, nodeOffset) => {
    const node = snapshotPlainObject(
      value,
      [
        'nodeIndex',
        'publicKey',
        'encryptedPathKeyBundles',
      ],
      `Invalid PathUpdateV2: node[${nodeOffset}]`,
    );
    requireNonNegativeInteger(
      node.nodeIndex,
      `node[${nodeOffset}].nodeIndex`,
      'PathUpdateV2',
    );
    const nodeIndex = node.nodeIndex as number;
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
    if (typeof node.publicKey !== 'string') {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}].publicKey must be a base64 string (got ${describe(node.publicKey)})`,
      );
    }
    if (!Array.isArray(node.encryptedPathKeyBundles)) {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles must be an array (got ${describe(node.encryptedPathKeyBundles)})`,
      );
    }
    const rawBundles = snapshotBoundedArray(
      node.encryptedPathKeyBundles,
      raw.numLeaves as number,
      `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles`,
      budget,
      `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles exceeds numLeaves`,
    );

    const recipientIndices = new Set<number>();
    const encryptedPathKeyBundles = rawBundles.map(
      (value, bundleOffset) => {
        const bundle = snapshotPlainObject(
          value,
          ['recipientNodeIndex', 'ciphertext'],
          `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}]`,
        );
        requireNonNegativeInteger(
          bundle.recipientNodeIndex,
          `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].recipientNodeIndex`,
          'PathUpdateV2',
        );
        const recipientNodeIndex = bundle.recipientNodeIndex as number;
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
        if (typeof bundle.ciphertext !== 'string') {
          throw new Error(
            `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].ciphertext must be a base64 string (got ${describe(bundle.ciphertext)})`,
          );
        }
        const ciphertext = decodeCanonicalBase64(
          bundle.ciphertext,
          `node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].ciphertext`,
          MAX_V2_BUNDLE_CIPHERTEXT_BYTES,
          budget,
        );
        if (
          ciphertext.byteLength === 0 ||
          ciphertext.byteLength > MAX_V2_BUNDLE_CIPHERTEXT_BYTES
        ) {
          throw new Error(
            `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPathKeyBundles[${bundleOffset}].ciphertext has invalid size`,
          );
        }
        return { recipientNodeIndex, ciphertext };
      },
    );

    const publicKey = decodeCanonicalBase64(
      node.publicKey,
      `node[${nodeOffset}].publicKey`,
      65,
      budget,
    );
    if (publicKey.byteLength !== 65) {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}].publicKey must decode to 65 bytes`,
      );
    }
    return {
      nodeIndex,
      publicKey,
      encryptedPathKeyBundles,
    };
  });

  const snapshotIndices = new Set<number>();
  const treeNodePublicKeys: WelcomeNodePublicKey[] =
    rawTreeNodePublicKeys.map((value, nodeOffset) => {
      const node = snapshotPlainObject(
        value,
        ['nodeIndex', 'publicKey'],
        `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}]`,
      );
      requireNonNegativeInteger(
        node.nodeIndex,
        `treeNodePublicKeys[${nodeOffset}].nodeIndex`,
        'PathUpdateV2',
      );
      const nodeIndex = node.nodeIndex as number;
      if (nodeIndex >= treeWidth || snapshotIndices.has(nodeIndex)) {
        throw new Error(
          `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}] has an out-of-range or duplicate nodeIndex`,
        );
      }
      snapshotIndices.add(nodeIndex);
      if (node.publicKey !== null && typeof node.publicKey !== 'string') {
        throw new Error(
          `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}].publicKey must be a base64 string or null (got ${describe(node.publicKey)})`,
        );
      }
      const publicKey =
        node.publicKey === null
          ? null
          : decodeCanonicalBase64(
              node.publicKey,
              `treeNodePublicKeys[${nodeOffset}].publicKey`,
              65,
              budget,
            );
      if (publicKey !== null && publicKey.byteLength !== 65) {
        throw new Error(
          `Invalid PathUpdateV2: treeNodePublicKeys[${nodeOffset}].publicKey must decode to 65 bytes`,
        );
      }
      return { nodeIndex, publicKey };
    });

  const senderLeafPublicKey = decodeCanonicalBase64(
    raw.senderLeafPublicKey,
    'senderLeafPublicKey',
    65,
    budget,
  );
  const parentTreeHash = decodeCanonicalBase64(
    raw.parentTreeHash,
    'parentTreeHash',
    32,
    budget,
  );
  const treeHash = decodeCanonicalBase64(
    raw.treeHash,
    'treeHash',
    32,
    budget,
  );
  if (senderLeafPublicKey.byteLength !== 65) {
    throw new Error(
      'Invalid PathUpdateV2: senderLeafPublicKey must decode to 65 bytes',
    );
  }
  if (parentTreeHash.byteLength !== 32) {
    throw new Error(
      'Invalid PathUpdateV2: parentTreeHash must decode to 32 bytes',
    );
  }
  if (treeHash.byteLength !== 32) {
    throw new Error('Invalid PathUpdateV2: treeHash must decode to 32 bytes');
  }

  validateV2TreeSemantics(
    raw.numLeaves as number,
    raw.senderLeafIndex as number,
    senderLeafPublicKey,
    nodes,
    treeNodePublicKeys,
  );

  return {
    version: 2,
    generation: raw.generation as number,
    parentTreeHash,
    numLeaves: raw.numLeaves as number,
    senderLeafIndex: raw.senderLeafIndex as number,
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

interface V2DecodeBudget {
  decodedBytes: number;
  workItems: number;
}

function createV2DecodeBudget(): V2DecodeBudget {
  return { decodedBytes: 0, workItems: 0 };
}

function snapshotPlainObject(
  value: unknown,
  allowedKeys: readonly string[],
  context: string,
): Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new Error(`${context}: expected a plain object, got ${describe(value)}`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${context}: expected a plain object, got ${describe(value)}`);
  }
  const allowed = new Set(allowedKeys);
  const keys = Reflect.ownKeys(value);
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== 'string') {
      throw new Error(`${context}: unexpected symbol field`);
    }
    if (!allowed.has(key)) {
      throw new Error(`${context}: unexpected field '${key}'`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
      descriptor.enumerable !== true
    ) {
      throw new Error(`${context}: field '${key}' must be an own enumerable data property`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function snapshotBoundedArray(
  value: unknown[],
  maxLength: number,
  context: string,
  budget: V2DecodeBudget,
  maxLengthError = `${context} exceeds ${maxLength} entries`,
): unknown[] {
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    lengthDescriptor === undefined ||
    !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value') ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    (lengthDescriptor.value as number) < 0
  ) {
    throw new Error(`${context} must have an own non-negative integer length`);
  }
  const length = lengthDescriptor.value as number;
  if (length > maxLength) {
    throw new Error(maxLengthError);
  }
  reserveV2Work(budget, length, context);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1) {
    throw new Error(`${context} must be a dense array without extra properties`);
  }
  const snapshot = new Array<unknown>(length);
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
      descriptor.enumerable !== true
    ) {
      throw new Error(`${context}[${index}] must be an own enumerable data property`);
    }
    snapshot[index] = descriptor.value;
  }
  return snapshot;
}

function reserveV2Work(
  budget: V2DecodeBudget,
  count: number,
  context: string,
): void {
  if (count > MAX_V2_AGGREGATE_WORK_ITEMS - budget.workItems) {
    throw new Error(
      `Invalid PathUpdateV2: aggregate work budget exceeded at ${context}`,
    );
  }
  budget.workItems += count;
}

function reserveV2DecodedBytes(
  budget: V2DecodeBudget,
  encodedLength: number,
  fieldName: string,
): void {
  const decodedUpperBound = Math.ceil(encodedLength / 4) * 3;
  if (
    decodedUpperBound >
    MAX_V2_AGGREGATE_DECODED_BYTES - budget.decodedBytes
  ) {
    throw new Error(
      `Invalid PathUpdateV2: aggregate decoded-byte budget exceeded at '${fieldName}'`,
    );
  }
  budget.decodedBytes += decodedUpperBound;
}

function snapshotRuntimeBytes(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  fieldName: string,
  budget: V2DecodeBudget,
): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = copyUnsharedUint8Array(
      value,
      minimumLength,
      maximumLength,
      `PathUpdateV2.${fieldName}`,
    );
  } catch {
    throw new Error(
      `Invalid PathUpdateV2: '${fieldName}' must be an unshared Uint8Array from ${minimumLength} to ${maximumLength} bytes`,
    );
  }
  const encodedLength = Math.ceil(bytes.byteLength / 3) * 4;
  reserveV2DecodedBytes(budget, encodedLength, fieldName);
  return bytes;
}

function requireNonNegativeInteger(
  value: unknown,
  field: string,
  typeName: string,
): void {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new Error(
      `Invalid ${typeName}: '${field}' must be a non-negative safe integer (got ${describe(value)})`,
    );
  }
}

function requirePositiveInteger(
  value: unknown,
  field: string,
  typeName: string,
): void {
  requireNonNegativeInteger(value, field, typeName);
  if ((value as number) === 0) {
    throw new Error(`Invalid ${typeName}: '${field}' must be positive`);
  }
}

function decodeCanonicalBase64(
  value: string,
  fieldName: string,
  maxBytes?: number,
  budget?: V2DecodeBudget,
): Uint8Array {
  if (
    maxBytes !== undefined &&
    value.length > Math.ceil(maxBytes / 3) * 4 + 4
  ) {
    throw new Error(`Invalid PathUpdateV2: '${fieldName}' exceeds size limit`);
  }
  if (budget !== undefined) {
    reserveV2DecodedBytes(budget, value.length, fieldName);
  }
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new Error(
      `Invalid PathUpdateV2: '${fieldName}' must use canonical padded base64`,
    );
  }
  let decoded: Uint8Array;
  try {
    decoded = Base64.toUint8Array(value);
  } catch {
    throw new Error(`Invalid PathUpdateV2: ${fieldName} must use canonical padded base64`);
  }
  if (maxBytes !== undefined && decoded.byteLength > maxBytes) {
    throw new Error(`Invalid PathUpdateV2: '${fieldName}' exceeds size limit`);
  }
  if (Base64.fromUint8Array(decoded) !== value) {
    throw new Error(
      `Invalid PathUpdateV2: '${fieldName}' must use canonical padded base64`,
    );
  }
  return decoded;
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}
