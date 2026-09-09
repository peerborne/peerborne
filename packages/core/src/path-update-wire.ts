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

const MAX_V2_PATH_NODES = 64;
const MAX_V2_BUNDLE_CIPHERTEXT_BYTES = 64 * (4096 + 8) + 4096;
const MAX_V2_AGGREGATE_DECODED_BYTES = 8 * 1024 * 1024;
const MAX_V2_AGGREGATE_WORK_ITEMS = 4 * MAX_BEEKEM_TREE_LEAVES;

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

export interface SerializedPathNodeUpdateV2 extends SerializedPathNodeUpdate {
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

export function serializePathUpdateV2ForWire(
  update: PathUpdateV2,
): SerializedPathUpdateV2 {
  if (update.version !== 2) {
    throw new Error('Cannot serialize non-v2 PathUpdate as v2');
  }
  return {
    version: 2,
    generation: update.generation,
    parentTreeHash: Base64.fromUint8Array(update.parentTreeHash),
    numLeaves: update.numLeaves,
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: Base64.fromUint8Array(update.senderLeafPublicKey),
    nodes: update.nodes.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: Base64.fromUint8Array(node.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(node.encryptedPrivateKey),
      encryptedPathKeyBundles: node.encryptedPathKeyBundles.map((bundle) => ({
        recipientNodeIndex: bundle.recipientNodeIndex,
        ciphertext: Base64.fromUint8Array(bundle.ciphertext),
      })),
    })),
    treeNodePublicKeys: update.treeNodePublicKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null
          ? null
          : Base64.fromUint8Array(node.publicKey),
    })),
    treeHash: Base64.fromUint8Array(update.treeHash),
  };
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
        'encryptedPrivateKey',
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
    if (typeof node.encryptedPrivateKey !== 'string') {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPrivateKey must be a base64 string (got ${describe(node.encryptedPrivateKey)})`,
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
    const encryptedPrivateKey = decodeCanonicalBase64(
      node.encryptedPrivateKey,
      `node[${nodeOffset}].encryptedPrivateKey`,
      MAX_V2_BUNDLE_CIPHERTEXT_BYTES,
      budget,
    );
    if (encryptedPrivateKey.byteLength > MAX_V2_BUNDLE_CIPHERTEXT_BYTES) {
      throw new Error(
        `Invalid PathUpdateV2: node[${nodeOffset}].encryptedPrivateKey is too large`,
      );
    }
    return {
      nodeIndex,
      publicKey,
      encryptedPrivateKey,
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
  const decoded = decodeBase64(value, fieldName);
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
