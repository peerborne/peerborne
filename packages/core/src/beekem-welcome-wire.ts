/**
 * Wire serialization for BeeKEM `BeeKEMWelcome` payloads.
 *
 * The `BeeKEMWelcome` runtime shape (from `beekem/types.ts`) is a small
 * record of `Uint8Array`s plus a leaf index. This module is the JSON-safe
 * encoder/decoder pair so a Welcome can be carried inside the sealed
 * `eciesSealed` payload of a `CRDTSyncMessage` together with the keychain
 * delta (see `welcome-sealed-payload.ts`).
 *
 * The shape mirrors the structure used by `path-update-wire.ts`: each
 * `Uint8Array` field is base64-encoded so the result survives a
 * `JSON.stringify` round-trip without binary loss.
 */
import { Base64 } from 'js-base64';
import {
  BeeKEMWelcome,
  BeeKEMWelcomeV2,
  MAX_BEEKEM_TREE_LEAVES,
  PathNodeUpdate,
  WelcomeNodePublicKey,
} from './beekem/types.js';
import {
  MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
  MAX_V1_PATH_NODES,
  MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
} from './beekem/path-update-limits.js';
import * as TreeMath from './beekem/tree-math.js';
import { copyUnsharedUint8Array } from './utils.js';

const MAX_V2_PATH_KEYS = 64;
const MAX_V2_CIPHERTEXT_BYTES = 64 * (4096 + 8) + 4096;
const MAX_V2_AGGREGATE_DECODED_BYTES = 4 * 1024 * 1024;
const MAX_V2_AGGREGATE_WORK_ITEMS = 4 * MAX_BEEKEM_TREE_LEAVES;

/** JSON-safe encoding of `PathNodeUpdate` (mirrors path-update-wire). */
export interface SerializedWelcomePathNodeUpdate {
  nodeIndex: number;
  publicKey: string; // base64
  encryptedPrivateKey: string; // base64
}

/** JSON-safe encoding of `WelcomeNodePublicKey`. `publicKey` is `null` for blanked nodes. */
export interface SerializedWelcomeNodePublicKey {
  nodeIndex: number;
  publicKey: string | null; // base64 or null
}

/** JSON-safe encoding of `BeeKEMWelcome`. */
export interface SerializedBeeKEMWelcome {
  leafIndex: number;
  pathKeys: SerializedWelcomePathNodeUpdate[];
  treeNodePublicKeys: SerializedWelcomeNodePublicKey[];
  treeHash: string; // base64
}

export interface SerializedBeeKEMWelcomeV2
  extends SerializedBeeKEMWelcome {
  version: 2;
  generation: number;
  numLeaves: number;
}

/** Convert a runtime v1 `BeeKEMWelcome` to its JSON-safe wire form. */
export function serializeBeeKEMWelcomeForWire(
  welcome: BeeKEMWelcome,
): SerializedBeeKEMWelcome {
  if (typeof welcome === 'object' && welcome !== null) {
    for (const field of ['version', 'generation', 'numLeaves']) {
      if (Reflect.has(welcome, field)) {
        throw new Error(
          `Cannot serialize BeeKEMWelcome with v2-only field '${field}' as v1`,
        );
      }
    }
  }
  const detached = snapshotLegacyRuntimeWelcome(welcome);
  const wire: SerializedBeeKEMWelcome = {
    leafIndex: detached.leafIndex,
    pathKeys: detached.pathKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: Base64.fromUint8Array(node.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(node.encryptedPrivateKey),
    })),
    treeNodePublicKeys: detached.treeNodePublicKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null
          ? null
          : Base64.fromUint8Array(node.publicKey),
    })),
    treeHash: Base64.fromUint8Array(detached.treeHash),
  };
  deserializeBeeKEMWelcomeFromWire(wire);
  return wire;
}

function snapshotLegacyRuntimeWelcome(value: unknown): BeeKEMWelcome {
  const context = 'Invalid BeeKEMWelcome';
  const budget = createWelcomeDecodeBudget(context);
  const raw = snapshotPlainObject(
    value,
    ['leafIndex', 'pathKeys', 'treeNodePublicKeys', 'treeHash'],
    context,
  );
  if (
    typeof raw.leafIndex !== 'number' ||
    !Number.isSafeInteger(raw.leafIndex) ||
    raw.leafIndex < 0 ||
    !TreeMath.isLeaf(raw.leafIndex)
  ) {
    throw new Error(
      `${context}: 'leafIndex' must be an even non-negative safe integer`,
    );
  }
  const leafIndex = raw.leafIndex;
  const numLeaves = leafIndex / 2 + 1;
  if (numLeaves < 2) {
    throw new Error(`${context}: leafIndex must identify an appended member`);
  }
  if (numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `${context}: leafIndex exceeds the supported ${MAX_BEEKEM_TREE_LEAVES}-leaf tree bound`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  if (!Array.isArray(raw.pathKeys)) {
    throw new Error(`${context}: 'pathKeys' must be an array`);
  }
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(`${context}: 'treeNodePublicKeys' must be an array`);
  }
  const rawPathKeys = snapshotBoundedArray(
    raw.pathKeys,
    MAX_V1_PATH_NODES,
    `${context}: pathKeys`,
    budget,
    `${context}: pathKeys has invalid length`,
  );
  if (rawPathKeys.length === 0) {
    throw new Error(`${context}: pathKeys has invalid length`);
  }
  const rawTreeNodePublicKeys = snapshotBoundedArray(
    raw.treeNodePublicKeys,
    treeWidth - 2,
    `${context}: treeNodePublicKeys`,
    budget,
    `${context}: treeNodePublicKeys exceeds the supported tree width`,
  );

  const pathKeys = rawPathKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `${context}: pathKeys[${offset}]`,
    );
    if (
      typeof node.nodeIndex !== 'number' ||
      !Number.isSafeInteger(node.nodeIndex) ||
      node.nodeIndex < 0
    ) {
      throw new Error(
        `${context}: pathKeys[${offset}].nodeIndex must be a non-negative safe integer`,
      );
    }
    return {
      nodeIndex: node.nodeIndex,
      publicKey: snapshotRuntimeBytes(
        node.publicKey,
        65,
        65,
        `pathKeys[${offset}].publicKey`,
        budget,
        'BeeKEMWelcome',
      ),
      encryptedPrivateKey: snapshotRuntimeBytes(
        node.encryptedPrivateKey,
        MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
        MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
        `pathKeys[${offset}].encryptedPrivateKey`,
        budget,
        'BeeKEMWelcome',
      ),
    };
  });
  const treeNodePublicKeys = rawTreeNodePublicKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey'],
      `${context}: treeNodePublicKeys[${offset}]`,
    );
    if (
      typeof node.nodeIndex !== 'number' ||
      !Number.isSafeInteger(node.nodeIndex) ||
      node.nodeIndex < 0
    ) {
      throw new Error(
        `${context}: treeNodePublicKeys[${offset}].nodeIndex must be a non-negative safe integer`,
      );
    }
    if (node.publicKey === null) {
      return { nodeIndex: node.nodeIndex, publicKey: null };
    }
    return {
      nodeIndex: node.nodeIndex,
      publicKey: snapshotRuntimeBytes(
        node.publicKey,
        65,
        65,
        `treeNodePublicKeys[${offset}].publicKey`,
        budget,
        'BeeKEMWelcome',
      ),
    };
  });
  const treeHash = snapshotRuntimeBytes(
    raw.treeHash,
    32,
    32,
    'treeHash',
    budget,
    'BeeKEMWelcome',
  );

  validateLegacyWelcomeTopology(
    leafIndex,
    numLeaves,
    pathKeys,
    treeNodePublicKeys,
    context,
  );
  return { leafIndex, pathKeys, treeNodePublicKeys, treeHash };
}

function validateLegacyWelcomeTopology(
  leafIndex: number,
  numLeaves: number,
  pathKeys: readonly { nodeIndex: number }[],
  treeNodePublicKeys: readonly { nodeIndex: number }[],
  context: string,
): number[] {
  const treeWidth = 2 * numLeaves - 1;
  const directPath = TreeMath.directPath(leafIndex, numLeaves);
  if (pathKeys.length !== directPath.length) {
    throw new Error(`${context}: pathKeys must contain the complete direct path`);
  }
  const covered = new Set<number>([leafIndex]);
  for (let offset = 0; offset < pathKeys.length; offset++) {
    const nodeIndex = pathKeys[offset].nodeIndex;
    if (nodeIndex !== directPath[offset] || covered.has(nodeIndex)) {
      throw new Error(
        `${context}: pathKeys[${offset}] has an invalid, duplicate, or out-of-order nodeIndex`,
      );
    }
    covered.add(nodeIndex);
  }
  for (let offset = 0; offset < treeNodePublicKeys.length; offset++) {
    const nodeIndex = treeNodePublicKeys[offset].nodeIndex;
    if (nodeIndex >= treeWidth || covered.has(nodeIndex)) {
      throw new Error(
        `${context}: treeNodePublicKeys[${offset}] has an out-of-range or duplicate nodeIndex`,
      );
    }
    covered.add(nodeIndex);
  }
  return directPath;
}

export function serializeBeeKEMWelcomeV2ForWire(
  welcome: BeeKEMWelcomeV2,
): SerializedBeeKEMWelcomeV2 {
  const budget = createWelcomeDecodeBudget('Invalid BeeKEMWelcomeV2');
  const raw = snapshotPlainObject(
    welcome,
    [
      'version',
      'generation',
      'numLeaves',
      'leafIndex',
      'pathKeys',
      'treeNodePublicKeys',
      'treeHash',
    ],
    'Invalid BeeKEMWelcomeV2',
  );
  if (raw.version !== 2) {
    throw new Error("Invalid BeeKEMWelcomeV2: 'version' must be 2");
  }
  requirePositiveInteger(raw.generation, 'generation');
  if ((raw.generation as number) > 0xffffffff) {
    throw new Error('Invalid BeeKEMWelcomeV2: generation exceeds 2^32-1');
  }
  requirePositiveInteger(raw.numLeaves, 'numLeaves');
  const numLeaves = raw.numLeaves as number;
  if (numLeaves < 2 || numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: numLeaves must be from 2 to ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  requireNonNegativeInteger(raw.leafIndex, 'leafIndex');
  const leafIndex = raw.leafIndex as number;
  if (leafIndex !== TreeMath.leafToNodeIndex(numLeaves - 1)) {
    throw new Error(
      'Invalid BeeKEMWelcomeV2: leafIndex must be the appended rightmost leaf',
    );
  }
  if (!Array.isArray(raw.pathKeys)) {
    throw new Error("Invalid BeeKEMWelcomeV2: 'pathKeys' must be an array");
  }
  const rawPathKeys = snapshotBoundedArray(
    raw.pathKeys,
    MAX_V2_PATH_KEYS,
    'Invalid BeeKEMWelcomeV2: pathKeys',
    budget,
    'Invalid BeeKEMWelcomeV2: pathKeys has invalid length',
  );
  if (rawPathKeys.length === 0) {
    throw new Error('Invalid BeeKEMWelcomeV2: pathKeys has invalid length');
  }
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      "Invalid BeeKEMWelcomeV2: 'treeNodePublicKeys' must be an array",
    );
  }
  const rawTreeNodePublicKeys = snapshotBoundedArray(
    raw.treeNodePublicKeys,
    treeWidth - 2,
    'Invalid BeeKEMWelcomeV2: treeNodePublicKeys',
    budget,
    'Invalid BeeKEMWelcomeV2: treeNodePublicKeys exceeds tree width',
  );

  const directPath = TreeMath.directPath(leafIndex, numLeaves);
  const directPathIndices = new Set(directPath);
  const covered = new Set<number>([leafIndex]);
  let previousPathOffset = -1;
  const pathKeySnapshots = rawPathKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `Invalid BeeKEMWelcomeV2: pathKeys[${offset}]`,
    );
    requireNonNegativeInteger(node.nodeIndex, `pathKeys[${offset}].nodeIndex`);
    const nodeIndex = node.nodeIndex as number;
    const pathOffset = directPath.indexOf(nodeIndex);
    if (
      nodeIndex >= treeWidth ||
      pathOffset !== previousPathOffset + 1 ||
      covered.has(nodeIndex)
    ) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: pathKeys[${offset}] has an invalid, duplicate, out-of-order, or non-contiguous nodeIndex`,
      );
    }
    previousPathOffset = pathOffset;
    covered.add(nodeIndex);
    return {
      nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    };
  });
  if (pathKeySnapshots.at(-1)?.nodeIndex !== TreeMath.root(numLeaves)) {
    throw new Error('Invalid BeeKEMWelcomeV2: pathKeys must end at the root');
  }

  const treeNodeSnapshots = rawTreeNodePublicKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey'],
      `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}]`,
    );
    requireNonNegativeInteger(
      node.nodeIndex,
      `treeNodePublicKeys[${offset}].nodeIndex`,
    );
    const nodeIndex = node.nodeIndex as number;
    if (nodeIndex >= treeWidth || covered.has(nodeIndex)) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}] has an out-of-range or duplicate nodeIndex`,
      );
    }
    covered.add(nodeIndex);
    if (node.publicKey !== null && directPathIndices.has(nodeIndex)) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: omitted direct-path node ${nodeIndex} must be blank`,
      );
    }
    return { nodeIndex, publicKey: node.publicKey };
  });

  if (
    covered.size !== treeWidth ||
    Array.from({ length: treeWidth }, (_, index) => index).some(
      (index) => !covered.has(index),
    )
  ) {
    throw new Error(
      'Invalid BeeKEMWelcomeV2: pathKeys and treeNodePublicKeys must cover the complete tree exactly once',
    );
  }

  const detachedPathKeys = pathKeySnapshots.map((node, offset) => ({
    nodeIndex: node.nodeIndex,
    publicKey: snapshotRuntimeBytes(
      node.publicKey,
      65,
      65,
      `pathKeys[${offset}].publicKey`,
      budget,
    ),
    encryptedPrivateKey: snapshotRuntimeBytes(
      node.encryptedPrivateKey,
      1,
      MAX_V2_CIPHERTEXT_BYTES,
      `pathKeys[${offset}].encryptedPrivateKey`,
      budget,
    ),
  }));
  const detachedTreeNodePublicKeys = treeNodeSnapshots.map((node, offset) => ({
    nodeIndex: node.nodeIndex,
    publicKey:
      node.publicKey === null
        ? null
        : snapshotRuntimeBytes(
            node.publicKey,
            65,
            65,
            `treeNodePublicKeys[${offset}].publicKey`,
            budget,
          ),
  }));
  const treeHash = snapshotRuntimeBytes(
    raw.treeHash,
    32,
    32,
    'treeHash',
    budget,
  );

  const wire: SerializedBeeKEMWelcomeV2 = {
    version: raw.version,
    generation: raw.generation as number,
    numLeaves,
    leafIndex,
    pathKeys: detachedPathKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: Base64.fromUint8Array(node.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(node.encryptedPrivateKey),
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
  // SECURITY BOUNDARY: this exported encoder accepts structurally typed input
  // from JavaScript callers. The runtime snapshot above validates and detaches
  // every field before Base64 normalization; the independent strict decoder is
  // still the final outbound self-check for the canonical wire representation.
  deserializeBeeKEMWelcomeV2FromWire(wire);
  return wire;
}

/**
 * Decode a wire-format `SerializedBeeKEMWelcome` back into a runtime
 * `BeeKEMWelcome`. Surfaces a descriptive error for malformed inputs,
 * mirroring the validation posture used by `path-update-wire.ts`.
 */
export function deserializeBeeKEMWelcomeFromWire(
  wire: unknown,
): BeeKEMWelcome {
  const context = 'Invalid BeeKEMWelcome';
  const budget = createWelcomeDecodeBudget(context);
  const raw = snapshotPlainObject(
    wire,
    ['leafIndex', 'pathKeys', 'treeNodePublicKeys', 'treeHash'],
    context,
  );

  if (
    typeof raw.leafIndex !== 'number' ||
    !Number.isSafeInteger(raw.leafIndex) ||
    raw.leafIndex < 0 ||
    !TreeMath.isLeaf(raw.leafIndex)
  ) {
    throw new Error(
      `${context}: 'leafIndex' must be an even non-negative safe integer (got ${describe(
        raw.leafIndex,
      )})`,
    );
  }
  const leafIndex = raw.leafIndex;
  const numLeaves = leafIndex / 2 + 1;
  if (numLeaves < 2) {
    throw new Error(`${context}: leafIndex must identify an appended member`);
  }
  if (numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `${context}: leafIndex exceeds the supported ${MAX_BEEKEM_TREE_LEAVES}-leaf tree bound`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  if (!Array.isArray(raw.pathKeys)) {
    throw new Error(
      `Invalid BeeKEMWelcome: 'pathKeys' must be an array (got ${describe(
        raw.pathKeys,
      )})`,
    );
  }
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      `Invalid BeeKEMWelcome: 'treeNodePublicKeys' must be an array (got ${describe(
        raw.treeNodePublicKeys,
      )})`,
    );
  }
  if (typeof raw.treeHash !== 'string') {
    throw new Error(
      `Invalid BeeKEMWelcome: 'treeHash' must be a base64 string (got ${describe(
        raw.treeHash,
      )})`,
    );
  }
  const rawPathKeys = snapshotBoundedArray(
    raw.pathKeys,
    MAX_V1_PATH_NODES,
    `${context}: pathKeys`,
    budget,
    `${context}: pathKeys has invalid length`,
  );
  if (rawPathKeys.length === 0) {
    throw new Error(`${context}: pathKeys has invalid length`);
  }
  const rawTreeNodePublicKeys = snapshotBoundedArray(
    raw.treeNodePublicKeys,
    treeWidth - 2,
    `${context}: treeNodePublicKeys`,
    budget,
    `${context}: treeNodePublicKeys exceeds the supported tree width`,
  );

  const pathKeySnapshots = rawPathKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `${context}: pathKeys[${offset}]`,
    );
    if (
      typeof node.nodeIndex !== 'number' ||
      !Number.isSafeInteger(node.nodeIndex) ||
      node.nodeIndex < 0
    ) {
      throw new Error(
        `${context}: pathKeys[${offset}].nodeIndex must be a non-negative safe integer (got ${describe(
          node.nodeIndex,
        )})`,
      );
    }
    if (typeof node.publicKey !== 'string') {
      throw new Error(
        `${context}: pathKeys[${offset}].publicKey must be a base64 string (got ${describe(
          node.publicKey,
        )})`,
      );
    }
    if (typeof node.encryptedPrivateKey !== 'string') {
      throw new Error(
        `${context}: pathKeys[${offset}].encryptedPrivateKey must be a base64 string (got ${describe(
          node.encryptedPrivateKey,
        )})`,
      );
    }
    reserveEncodedField(
      node.publicKey,
      65,
      65,
      `pathKeys[${offset}].publicKey`,
      budget,
    );
    reserveEncodedField(
      node.encryptedPrivateKey,
      MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      `pathKeys[${offset}].encryptedPrivateKey`,
      budget,
    );
    return {
      nodeIndex: node.nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    };
  });
  const treeNodeSnapshots = rawTreeNodePublicKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey'],
      `${context}: treeNodePublicKeys[${offset}]`,
    );
    if (
      typeof node.nodeIndex !== 'number' ||
      !Number.isSafeInteger(node.nodeIndex) ||
      node.nodeIndex < 0
    ) {
      throw new Error(
        `${context}: treeNodePublicKeys[${offset}].nodeIndex must be a non-negative safe integer (got ${describe(
          node.nodeIndex,
        )})`,
      );
    }
    if (node.publicKey !== null && typeof node.publicKey !== 'string') {
      throw new Error(
        `${context}: treeNodePublicKeys[${offset}].publicKey must be a base64 string or null (got ${describe(
          node.publicKey,
        )})`,
      );
    }
    if (node.publicKey !== null) {
      reserveEncodedField(
        node.publicKey,
        65,
        65,
        `treeNodePublicKeys[${offset}].publicKey`,
        budget,
      );
    }
    return { nodeIndex: node.nodeIndex, publicKey: node.publicKey };
  });
  reserveEncodedField(raw.treeHash, 32, 32, 'treeHash', budget);

  validateLegacyWelcomeTopology(
    leafIndex,
    numLeaves,
    pathKeySnapshots,
    treeNodeSnapshots,
    context,
  );
  const pathKeys: PathNodeUpdate[] = pathKeySnapshots.map((node, offset) => {
    const nodeIndex = node.nodeIndex;
    const publicKey = decodeReservedCanonicalBase64(
      node.publicKey,
      `pathKeys[${offset}].publicKey`,
      65,
      65,
      context,
    );
    const encryptedPrivateKey = decodeReservedCanonicalBase64(
      node.encryptedPrivateKey,
      `pathKeys[${offset}].encryptedPrivateKey`,
      MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      context,
    );
    return { nodeIndex, publicKey, encryptedPrivateKey };
  });

  const treeNodePublicKeys: WelcomeNodePublicKey[] =
    treeNodeSnapshots.map((node, offset) => {
      const nodeIndex = node.nodeIndex;
      const publicKey =
        node.publicKey === null
          ? null
          : decodeReservedCanonicalBase64(
              node.publicKey,
              `treeNodePublicKeys[${offset}].publicKey`,
              65,
              65,
              context,
            );
      return { nodeIndex, publicKey };
    });

  const treeHash = decodeReservedCanonicalBase64(
    raw.treeHash,
    'treeHash',
    32,
    32,
    context,
  );

  return {
    leafIndex,
    pathKeys,
    treeNodePublicKeys,
    treeHash,
  };
}

export function deserializeBeeKEMWelcomeV2FromWire(
  wire: unknown,
): BeeKEMWelcomeV2 {
  const budget = createWelcomeDecodeBudget('Invalid BeeKEMWelcomeV2');
  const raw = snapshotPlainObject(
    wire,
    [
      'version',
      'generation',
      'numLeaves',
      'leafIndex',
      'pathKeys',
      'treeNodePublicKeys',
      'treeHash',
    ],
    'Invalid BeeKEMWelcomeV2',
  );
  if (raw.version !== 2) {
    throw new Error("Invalid BeeKEMWelcomeV2: 'version' must be 2");
  }
  requirePositiveInteger(raw.generation, 'generation');
  if ((raw.generation as number) > 0xffffffff) {
    throw new Error('Invalid BeeKEMWelcomeV2: generation exceeds 2^32-1');
  }
  requirePositiveInteger(raw.numLeaves, 'numLeaves');
  const numLeaves = raw.numLeaves as number;
  if (numLeaves < 2 || numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: numLeaves must be from 2 to ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  requireNonNegativeInteger(raw.leafIndex, 'leafIndex');
  const leafIndex = raw.leafIndex as number;
  if (leafIndex !== TreeMath.leafToNodeIndex(numLeaves - 1)) {
    throw new Error(
      'Invalid BeeKEMWelcomeV2: leafIndex must be the appended rightmost leaf',
    );
  }
  if (!Array.isArray(raw.pathKeys)) {
    throw new Error("Invalid BeeKEMWelcomeV2: 'pathKeys' must be an array");
  }
  const rawPathKeys = snapshotBoundedArray(
    raw.pathKeys,
    MAX_V2_PATH_KEYS,
    'Invalid BeeKEMWelcomeV2: pathKeys',
    budget,
    'Invalid BeeKEMWelcomeV2: pathKeys has invalid length',
  );
  if (rawPathKeys.length === 0) {
    throw new Error('Invalid BeeKEMWelcomeV2: pathKeys has invalid length');
  }
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      "Invalid BeeKEMWelcomeV2: 'treeNodePublicKeys' must be an array",
    );
  }
  const rawTreeNodePublicKeys = snapshotBoundedArray(
    raw.treeNodePublicKeys,
    treeWidth - 2,
    'Invalid BeeKEMWelcomeV2: treeNodePublicKeys',
    budget,
    'Invalid BeeKEMWelcomeV2: treeNodePublicKeys exceeds tree width',
  );
  if (typeof raw.treeHash !== 'string') {
    throw new Error("Invalid BeeKEMWelcomeV2: 'treeHash' must be base64");
  }

  const directPath = TreeMath.directPath(leafIndex, numLeaves);
  const directPathIndices = new Set(directPath);
  const covered = new Set<number>([leafIndex]);
  let previousPathOffset = -1;
  const pathKeys: PathNodeUpdate[] = rawPathKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `Invalid BeeKEMWelcomeV2: pathKeys[${offset}]`,
    );
    requireNonNegativeInteger(node.nodeIndex, `pathKeys[${offset}].nodeIndex`);
    const nodeIndex = node.nodeIndex as number;
    const pathOffset = directPath.indexOf(nodeIndex);
    if (
      nodeIndex >= treeWidth ||
      pathOffset !== previousPathOffset + 1 ||
      covered.has(nodeIndex)
    ) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: pathKeys[${offset}] has an invalid, duplicate, out-of-order, or non-contiguous nodeIndex`,
      );
    }
    previousPathOffset = pathOffset;
    covered.add(nodeIndex);
    if (
      typeof node.publicKey !== 'string' ||
      typeof node.encryptedPrivateKey !== 'string'
    ) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: pathKeys[${offset}] key fields must be base64 strings`,
      );
    }
    const publicKey = decodeCanonicalBase64(
      node.publicKey,
      `pathKeys[${offset}].publicKey`,
      65,
      budget,
    );
    const encryptedPrivateKey = decodeBoundedBase64(
      node.encryptedPrivateKey,
      `pathKeys[${offset}].encryptedPrivateKey`,
      MAX_V2_CIPHERTEXT_BYTES,
      budget,
    );
    if (publicKey.byteLength !== 65) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: pathKeys[${offset}].publicKey must decode to 65 bytes`,
      );
    }
    if (encryptedPrivateKey.byteLength === 0) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: pathKeys[${offset}].encryptedPrivateKey is empty`,
      );
    }
    return { nodeIndex, publicKey, encryptedPrivateKey };
  });
  if (pathKeys.at(-1)?.nodeIndex !== TreeMath.root(numLeaves)) {
    throw new Error('Invalid BeeKEMWelcomeV2: pathKeys must end at the root');
  }

  const treeNodePublicKeys: WelcomeNodePublicKey[] =
    rawTreeNodePublicKeys.map((value, offset) => {
      const node = snapshotPlainObject(
        value,
        ['nodeIndex', 'publicKey'],
        `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}]`,
      );
      requireNonNegativeInteger(
        node.nodeIndex,
        `treeNodePublicKeys[${offset}].nodeIndex`,
      );
      const nodeIndex = node.nodeIndex as number;
      if (nodeIndex >= treeWidth || covered.has(nodeIndex)) {
        throw new Error(
          `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}] has an out-of-range or duplicate nodeIndex`,
        );
      }
      covered.add(nodeIndex);
      if (node.publicKey !== null && typeof node.publicKey !== 'string') {
        throw new Error(
          `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}].publicKey must be base64 or null`,
        );
      }
      const publicKey =
        node.publicKey === null
          ? null
          : decodeCanonicalBase64(
              node.publicKey,
              `treeNodePublicKeys[${offset}].publicKey`,
              65,
              budget,
            );
      if (publicKey !== null && publicKey.byteLength !== 65) {
        throw new Error(
          `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}].publicKey must decode to 65 bytes`,
        );
      }
      if (directPathIndices.has(nodeIndex) && publicKey !== null) {
        throw new Error(
          `Invalid BeeKEMWelcomeV2: omitted direct-path node ${nodeIndex} must be blank`,
        );
      }
      return { nodeIndex, publicKey };
    });

  if (
    covered.size !== treeWidth ||
    Array.from({ length: treeWidth }, (_, index) => index).some(
      (index) => !covered.has(index),
    )
  ) {
    throw new Error(
      'Invalid BeeKEMWelcomeV2: pathKeys and treeNodePublicKeys must cover the complete tree exactly once',
    );
  }
  const treeHash = decodeCanonicalBase64(
    raw.treeHash,
    'treeHash',
    32,
    budget,
  );
  if (treeHash.byteLength !== 32) {
    throw new Error('Invalid BeeKEMWelcomeV2: treeHash must decode to 32 bytes');
  }

  return {
    version: 2,
    generation: raw.generation as number,
    numLeaves,
    leafIndex,
    pathKeys,
    treeNodePublicKeys,
    treeHash,
  };
}

interface WelcomeDecodeBudget {
  context: string;
  decodedBytes: number;
  workItems: number;
}

function createWelcomeDecodeBudget(context: string): WelcomeDecodeBudget {
  return { context, decodedBytes: 0, workItems: 0 };
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
  budget: WelcomeDecodeBudget,
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
  budget: WelcomeDecodeBudget,
  count: number,
  context: string,
): void {
  if (count > MAX_V2_AGGREGATE_WORK_ITEMS - budget.workItems) {
    throw new Error(
      `${budget.context}: aggregate work budget exceeded at ${context}`,
    );
  }
  budget.workItems += count;
}

function reserveV2DecodedBytes(
  budget: WelcomeDecodeBudget,
  encodedLength: number,
  fieldName: string,
): void {
  const decodedUpperBound = Math.ceil(encodedLength / 4) * 3;
  if (
    decodedUpperBound >
    MAX_V2_AGGREGATE_DECODED_BYTES - budget.decodedBytes
  ) {
    throw new Error(
      `${budget.context}: aggregate decoded-byte budget exceeded at ${fieldName}`,
    );
  }
  budget.decodedBytes += decodedUpperBound;
}

function snapshotRuntimeBytes(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  fieldName: string,
  budget: WelcomeDecodeBudget,
  valueContext = 'BeeKEMWelcomeV2',
): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = copyUnsharedUint8Array(
      value,
      minimumLength,
      maximumLength,
      `${valueContext}.${fieldName}`,
    );
  } catch {
    throw new Error(
      `${budget.context}: ${fieldName} must be an unshared Uint8Array from ${minimumLength} to ${maximumLength} bytes`,
    );
  }
  const encodedLength = Math.ceil(bytes.byteLength / 3) * 4;
  reserveV2DecodedBytes(budget, encodedLength, fieldName);
  return bytes;
}

function requireNonNegativeInteger(value: unknown, field: string): void {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: '${field}' must be a non-negative safe integer`,
    );
  }
}

function requirePositiveInteger(value: unknown, field: string): void {
  requireNonNegativeInteger(value, field);
  if ((value as number) === 0) {
    throw new Error(`Invalid BeeKEMWelcomeV2: '${field}' must be positive`);
  }
}

function reserveEncodedField(
  value: string,
  minimumBytes: number,
  maximumBytes: number,
  fieldName: string,
  budget: WelcomeDecodeBudget,
): void {
  if (value.length > Math.ceil(maximumBytes / 3) * 4) {
    throw new Error(
      `${budget.context}: ${fieldName} exceeds the encoded size limit`,
    );
  }
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new Error(
      `${budget.context}: ${fieldName} must use canonical padded base64`,
    );
  }
  const paddingBytes = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const decodedLength = (value.length / 4) * 3 - paddingBytes;
  if (decodedLength < minimumBytes || decodedLength > maximumBytes) {
    const expected =
      minimumBytes === maximumBytes
        ? `${minimumBytes} bytes`
        : `${minimumBytes} to ${maximumBytes} bytes`;
    throw new Error(
      `${budget.context}: ${fieldName} must decode to ${expected}`,
    );
  }
  reserveV2DecodedBytes(budget, value.length, fieldName);
}

function decodeReservedCanonicalBase64(
  value: string,
  fieldName: string,
  minimumBytes: number,
  maximumBytes: number,
  context: string,
): Uint8Array {
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new Error(
      `${context}: ${fieldName} must use canonical padded base64`,
    );
  }
  const decoded = decodeBase64(value, fieldName);
  if (
    decoded.byteLength < minimumBytes ||
    decoded.byteLength > maximumBytes
  ) {
    const expected =
      minimumBytes === maximumBytes
        ? `${minimumBytes} bytes`
        : `${minimumBytes} to ${maximumBytes} bytes`;
    throw new Error(`${context}: ${fieldName} must decode to ${expected}`);
  }
  if (Base64.fromUint8Array(decoded) !== value) {
    throw new Error(
      `${context}: ${fieldName} must use canonical padded base64`,
    );
  }
  return decoded;
}

function decodeBoundedBase64(
  value: string,
  fieldName: string,
  maxBytes: number,
  budget: WelcomeDecodeBudget,
): Uint8Array {
  if (value.length > Math.ceil(maxBytes / 3) * 4 + 4) {
    throw new Error(
      `${budget.context}: ${fieldName} exceeds the encoded size limit`,
    );
  }
  const decoded = decodeCanonicalBase64(value, fieldName, maxBytes, budget);
  if (decoded.byteLength > maxBytes) {
    throw new Error(
      `${budget.context}: ${fieldName} exceeds the decoded size limit`,
    );
  }
  return decoded;
}

function decodeCanonicalBase64(
  value: string,
  fieldName: string,
  maxBytes?: number,
  budget?: WelcomeDecodeBudget,
): Uint8Array {
  const context = budget?.context ?? 'Invalid BeeKEMWelcomeV2';
  if (
    maxBytes !== undefined &&
    value.length > Math.ceil(maxBytes / 3) * 4 + 4
  ) {
    throw new Error(
      `${context}: ${fieldName} exceeds the encoded size limit`,
    );
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
      `${context}: ${fieldName} must use canonical padded base64`,
    );
  }
  const decoded = decodeBase64(value, fieldName);
  if (maxBytes !== undefined && decoded.byteLength > maxBytes) {
    throw new Error(
      `${context}: ${fieldName} exceeds the decoded size limit`,
    );
  }
  if (Base64.fromUint8Array(decoded) !== value) {
    throw new Error(
      `${context}: ${fieldName} must use canonical padded base64`,
    );
  }
  return decoded;
}

function decodeBase64(value: string, fieldName: string): Uint8Array {
  try {
    return Base64.toUint8Array(value);
  } catch (err) {
    throw new Error(
      `BeeKEMWelcome wire: invalid base64 for field ${fieldName}: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}
