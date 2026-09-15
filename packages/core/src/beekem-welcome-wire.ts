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
import {
  copyRuntimeBytes,
  createV2DecodeBudget,
  decodeV2Bytes,
  describe,
  encodeRuntimeBytes,
  requireNonNegativeInteger,
  requirePositiveInteger,
  snapshotBoundedArray,
  snapshotPlainObject,
  V2DecodeBudget,
  V2WireCodec,
} from './wire-v2-validation.js';

const MAX_V2_PATH_KEYS = 64;
const MAX_V2_CIPHERTEXT_BYTES = 64 * (4096 + 8) + 4096;
const WELCOME_V2: V2WireCodec = {
  typeName: 'BeeKEMWelcomeV2',
  maxAggregateDecodedBytes: 4 * 1024 * 1024,
  maxAggregateWorkItems: 4 * MAX_BEEKEM_TREE_LEAVES,
};
const WELCOME_V1: V2WireCodec = {
  typeName: 'BeeKEMWelcome',
  maxAggregateDecodedBytes: 4 * 1024 * 1024,
  maxAggregateWorkItems: 4 * MAX_BEEKEM_TREE_LEAVES,
};
const WELCOME_V1_CONTEXT = 'Invalid BeeKEMWelcome';
const WELCOME_V1_FIELDS = [
  'leafIndex',
  'pathKeys',
  'treeNodePublicKeys',
  'treeHash',
] as const;
const WELCOME_V2_ONLY_FIELDS = ['version', 'generation', 'numLeaves'] as const;
const WELCOME_V2_FIELDS = [
  'version',
  'generation',
  'numLeaves',
  'leafIndex',
  'pathKeys',
  'treeNodePublicKeys',
  'treeHash',
] as const;

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

/**
 * Convert a runtime v1 Welcome to JSON-safe wire form.
 * Inputs must be plain records containing only the specified enumerable data
 * fields; metadata, accessors and class instances are rejected.
 */
export function serializeBeeKEMWelcomeForWire(
  welcome: BeeKEMWelcome,
): SerializedBeeKEMWelcome {
  const detached = snapshotPlainObject(
    welcome,
    [...WELCOME_V1_FIELDS, ...WELCOME_V2_ONLY_FIELDS],
    WELCOME_V1_CONTEXT,
  );
  for (const field of WELCOME_V2_ONLY_FIELDS) {
    if (detached[field] !== undefined) {
      throw new Error(
        `Cannot serialize BeeKEMWelcome with v2-only field '${field}' as v1`,
      );
    }
    delete detached[field];
  }
  const budget = createV2DecodeBudget(WELCOME_V1);
  const encode = (
    value: unknown,
    minimumLength: number,
    maximumLength: number,
    fieldName: string,
  ): string =>
    encodeRuntimeBytes(value, minimumLength, maximumLength, fieldName, budget);
  return snapshotLegacyWelcome(detached, budget, {
    treeHash: (value) => encode(value, 32, 32, 'treeHash'),
    publicKey: (value, fieldName) => encode(value, 65, 65, fieldName),
    encryptedPrivateKey: (value, fieldName) =>
      encode(
        value,
        MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
        MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
        fieldName,
      ),
  });
}

interface LegacyWelcomeFieldReaders<T> {
  treeHash(value: unknown): T;
  publicKey(value: unknown, fieldName: string): T;
  encryptedPrivateKey(value: unknown, fieldName: string): T;
}

interface LegacyWelcomeSnapshot<T> {
  leafIndex: number;
  pathKeys: { nodeIndex: number; publicKey: T; encryptedPrivateKey: T }[];
  treeNodePublicKeys: { nodeIndex: number; publicKey: T | null }[];
  treeHash: T;
}

/**
 * Detach a v1 Welcome, enforce its shape, bounds and fixed left-balanced
 * topology, and read each byte field through `readers`. The encoder and
 * decoder share this single structural validator.
 */
function snapshotLegacyWelcome<T>(
  value: unknown,
  budget: V2DecodeBudget,
  readers: LegacyWelcomeFieldReaders<T>,
): LegacyWelcomeSnapshot<T> {
  const context = WELCOME_V1_CONTEXT;
  const raw = snapshotPlainObject(value, WELCOME_V1_FIELDS, context);
  const leafIndex = requireNonNegativeInteger(
    raw.leafIndex,
    'leafIndex',
    WELCOME_V1.typeName,
  );
  if (!TreeMath.isLeaf(leafIndex)) {
    throw new Error(
      `${context}: 'leafIndex' must be an even non-negative safe integer`,
    );
  }
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
      `${context}: 'pathKeys' must be an array (got ${describe(raw.pathKeys)})`,
    );
  }
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      `${context}: 'treeNodePublicKeys' must be an array (got ${describe(
        raw.treeNodePublicKeys,
      )})`,
    );
  }
  const treeHash = readers.treeHash(raw.treeHash);
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

  const pathKeys = rawPathKeys.map((entry, offset) => {
    const field = `pathKeys[${offset}]`;
    const node = snapshotPlainObject(
      entry,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `${context}: ${field}`,
    );
    return {
      nodeIndex: requireNonNegativeInteger(
        node.nodeIndex,
        `${field}.nodeIndex`,
        WELCOME_V1.typeName,
      ),
      publicKey: readers.publicKey(node.publicKey, `${field}.publicKey`),
      encryptedPrivateKey: readers.encryptedPrivateKey(
        node.encryptedPrivateKey,
        `${field}.encryptedPrivateKey`,
      ),
    };
  });
  const treeNodePublicKeys = rawTreeNodePublicKeys.map((entry, offset) => {
    const field = `treeNodePublicKeys[${offset}]`;
    const node = snapshotPlainObject(
      entry,
      ['nodeIndex', 'publicKey'],
      `${context}: ${field}`,
    );
    return {
      nodeIndex: requireNonNegativeInteger(
        node.nodeIndex,
        `${field}.nodeIndex`,
        WELCOME_V1.typeName,
      ),
      publicKey:
        node.publicKey === null
          ? null
          : readers.publicKey(node.publicKey, `${field}.publicKey`),
    };
  });

  const directPath = TreeMath.directPath(leafIndex, numLeaves);
  if (pathKeys.length !== directPath.length) {
    throw new Error(
      `${context}: pathKeys must contain the complete direct path`,
    );
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
  return { leafIndex, pathKeys, treeNodePublicKeys, treeHash };
}

/**
 * Validate and detach a legacy runtime Welcome before applying it to a tree.
 *
 * Unlike the wire decoder, this boundary receives structurally typed values
 * directly from JavaScript callers. It enforces the same structure, bounds
 * and topology as the wire decoder, copies every byte field, and rejects v2
 * markers (own or inherited) rather than silently discarding their
 * transition metadata.
 *
 * @internal
 */
export function snapshotBeeKEMWelcomeForProcessing(value: unknown): {
  welcome: BeeKEMWelcome;
  numLeaves: number;
} {
  if (typeof value === 'object' && value !== null) {
    for (const field of WELCOME_V2_ONLY_FIELDS) {
      if (Reflect.has(value, field)) {
        throw new Error(
          `${WELCOME_V1_CONTEXT}: unexpected field '${field}' (v2-only)`,
        );
      }
    }
  }
  const budget = createV2DecodeBudget(WELCOME_V1);
  const copy =
    (minimumLength: number, maximumLength: number) =>
    (value: unknown, fieldName: string): Uint8Array =>
      copyRuntimeBytes(value, minimumLength, maximumLength, fieldName, budget);
  const welcome = snapshotLegacyWelcome(value, budget, {
    treeHash: (value) => copy(32, 32)(value, 'treeHash'),
    publicKey: copy(65, 65),
    encryptedPrivateKey: copy(
      MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
    ),
  });
  return { welcome, numLeaves: welcome.leafIndex / 2 + 1 };
}

export function serializeBeeKEMWelcomeV2ForWire(
  welcome: BeeKEMWelcomeV2,
): SerializedBeeKEMWelcomeV2 {
  // Snapshot and encode only; `deserializeBeeKEMWelcomeV2FromWire` is the
  // single structural validator for the result.
  const budget = createV2DecodeBudget(WELCOME_V2);
  const raw = snapshotPlainObject(
    welcome,
    WELCOME_V2_FIELDS,
    'Invalid BeeKEMWelcomeV2',
  );
  const numLeaves = requirePositiveInteger(
    raw.numLeaves,
    'numLeaves',
    'BeeKEMWelcomeV2',
  );
  if (numLeaves < 2 || numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: numLeaves must be from 2 to ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  const pathKeys = snapshotBoundedArray(
    raw.pathKeys,
    MAX_V2_PATH_KEYS,
    'Invalid BeeKEMWelcomeV2: pathKeys',
    budget,
    'Invalid BeeKEMWelcomeV2: pathKeys has invalid length',
  ).map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `Invalid BeeKEMWelcomeV2: pathKeys[${offset}]`,
    );
    return {
      nodeIndex: node.nodeIndex as number,
      publicKey: encodeRuntimeBytes(
        node.publicKey,
        65,
        65,
        `pathKeys[${offset}].publicKey`,
        budget,
      ),
      encryptedPrivateKey: encodeRuntimeBytes(
        node.encryptedPrivateKey,
        1,
        MAX_V2_CIPHERTEXT_BYTES,
        `pathKeys[${offset}].encryptedPrivateKey`,
        budget,
      ),
    };
  });
  const treeNodePublicKeys: SerializedWelcomeNodePublicKey[] =
    snapshotBoundedArray(
      raw.treeNodePublicKeys,
      treeWidth - 2,
      'Invalid BeeKEMWelcomeV2: treeNodePublicKeys',
      budget,
      'Invalid BeeKEMWelcomeV2: treeNodePublicKeys exceeds tree width',
    ).map((value, offset) => {
      const node = snapshotPlainObject(
        value,
        ['nodeIndex', 'publicKey'],
        `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}]`,
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
                `treeNodePublicKeys[${offset}].publicKey`,
                budget,
              ),
      };
    });

  // Runtime BeeKEM trees may omit blank slots; V2 wire snapshots are complete.
  const covered = new Set<unknown>([
    raw.leafIndex,
    ...pathKeys.map((node) => node.nodeIndex),
    ...treeNodePublicKeys.map((node) => node.nodeIndex),
  ]);
  for (let nodeIndex = 0; nodeIndex < treeWidth; nodeIndex++) {
    if (!covered.has(nodeIndex)) {
      treeNodePublicKeys.push({ nodeIndex, publicKey: null });
    }
  }

  const wire: SerializedBeeKEMWelcomeV2 = {
    version: raw.version as 2,
    generation: raw.generation as number,
    numLeaves,
    leafIndex: raw.leafIndex as number,
    pathKeys,
    treeNodePublicKeys,
    treeHash: encodeRuntimeBytes(raw.treeHash, 32, 32, 'treeHash', budget),
  };
  deserializeBeeKEMWelcomeV2FromWire(wire);
  return wire;
}

/**
 * Decode a wire-format `SerializedBeeKEMWelcome` back into a runtime
 * `BeeKEMWelcome`. Shape, topology and every encoded field length are
 * validated before any base64 is decoded.
 */
export function deserializeBeeKEMWelcomeFromWire(wire: unknown): BeeKEMWelcome {
  const budget = createV2DecodeBudget(WELCOME_V1);
  const preflight =
    (maximumLength: number) =>
    (value: unknown, fieldName: string): LegacyEncodedField => {
      if (typeof value !== 'string') {
        throw new Error(
          `${WELCOME_V1_CONTEXT}: '${fieldName}' must be a base64 string (got ${describe(value)})`,
        );
      }
      if (value.length > Math.ceil(maximumLength / 3) * 4) {
        throw new Error(
          `${WELCOME_V1_CONTEXT}: ${fieldName} exceeds the encoded size limit`,
        );
      }
      return { value, fieldName };
    };
  const snapshot = snapshotLegacyWelcome(wire, budget, {
    treeHash: (value) => preflight(32)(value, 'treeHash'),
    publicKey: preflight(65),
    encryptedPrivateKey: preflight(MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES),
  });
  const decode = (
    field: LegacyEncodedField,
    minimumLength: number,
    maximumLength: number,
  ): Uint8Array =>
    decodeV2Bytes(
      field.value,
      minimumLength,
      maximumLength,
      field.fieldName,
      budget,
    );
  return {
    leafIndex: snapshot.leafIndex,
    pathKeys: snapshot.pathKeys.map((node): PathNodeUpdate => ({
      nodeIndex: node.nodeIndex,
      publicKey: decode(node.publicKey, 65, 65),
      encryptedPrivateKey: decode(
        node.encryptedPrivateKey,
        MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
        MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      ),
    })),
    treeNodePublicKeys: snapshot.treeNodePublicKeys.map(
      (node): WelcomeNodePublicKey => ({
        nodeIndex: node.nodeIndex,
        publicKey:
          node.publicKey === null ? null : decode(node.publicKey, 65, 65),
      }),
    ),
    treeHash: decode(snapshot.treeHash, 32, 32),
  };
}

interface LegacyEncodedField {
  value: string;
  fieldName: string;
}

export function deserializeBeeKEMWelcomeV2FromWire(
  wire: unknown,
): BeeKEMWelcomeV2 {
  const budget = createV2DecodeBudget(WELCOME_V2);
  const raw = snapshotPlainObject(
    wire,
    WELCOME_V2_FIELDS,
    'Invalid BeeKEMWelcomeV2',
  );
  if (raw.version !== 2) {
    throw new Error("Invalid BeeKEMWelcomeV2: 'version' must be 2");
  }
  const generation = requirePositiveInteger(
    raw.generation,
    'generation',
    'BeeKEMWelcomeV2',
  );
  if (generation > 0xffffffff) {
    throw new Error('Invalid BeeKEMWelcomeV2: generation exceeds 2^32-1');
  }
  const numLeaves = requirePositiveInteger(
    raw.numLeaves,
    'numLeaves',
    'BeeKEMWelcomeV2',
  );
  if (numLeaves < 2 || numLeaves > MAX_BEEKEM_TREE_LEAVES) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: numLeaves must be from 2 to ${MAX_BEEKEM_TREE_LEAVES}`,
    );
  }
  const treeWidth = 2 * numLeaves - 1;
  const leafIndex = requireNonNegativeInteger(
    raw.leafIndex,
    'leafIndex',
    'BeeKEMWelcomeV2',
  );
  if (leafIndex !== TreeMath.leafToNodeIndex(numLeaves - 1)) {
    throw new Error(
      'Invalid BeeKEMWelcomeV2: leafIndex must be the appended rightmost leaf',
    );
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
  const pathKeys: PathNodeUpdate[] = rawPathKeys.map((value, offset) => {
    const node = snapshotPlainObject(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `Invalid BeeKEMWelcomeV2: pathKeys[${offset}]`,
    );
    const nodeIndex = requireNonNegativeInteger(
      node.nodeIndex,
      `pathKeys[${offset}].nodeIndex`,
      'BeeKEMWelcomeV2',
    );
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
    const publicKey = decodeV2Bytes(
      node.publicKey,
      65,
      65,
      `pathKeys[${offset}].publicKey`,
      budget,
    );
    const encryptedPrivateKey = decodeV2Bytes(
      node.encryptedPrivateKey,
      1,
      MAX_V2_CIPHERTEXT_BYTES,
      `pathKeys[${offset}].encryptedPrivateKey`,
      budget,
    );
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
      const nodeIndex = requireNonNegativeInteger(
        node.nodeIndex,
        `treeNodePublicKeys[${offset}].nodeIndex`,
        'BeeKEMWelcomeV2',
      );
      if (nodeIndex >= treeWidth || covered.has(nodeIndex)) {
        throw new Error(
          `Invalid BeeKEMWelcomeV2: treeNodePublicKeys[${offset}] has an out-of-range or duplicate nodeIndex`,
        );
      }
      covered.add(nodeIndex);
      const publicKey =
        node.publicKey === null
          ? null
          : decodeV2Bytes(
              node.publicKey,
              65,
              65,
              `treeNodePublicKeys[${offset}].publicKey`,
              budget,
            );
      if (directPathIndices.has(nodeIndex) && publicKey !== null) {
        throw new Error(
          `Invalid BeeKEMWelcomeV2: omitted direct-path node ${nodeIndex} must be blank`,
        );
      }
      return { nodeIndex, publicKey };
    });

  // Every index is in [0, treeWidth) and unique, so the count alone proves
  // complete coverage.
  if (covered.size !== treeWidth) {
    throw new Error(
      'Invalid BeeKEMWelcomeV2: pathKeys and treeNodePublicKeys must cover the complete tree exactly once',
    );
  }
  const treeHash = decodeV2Bytes(raw.treeHash, 32, 32, 'treeHash', budget);

  return {
    version: 2,
    generation,
    numLeaves,
    leafIndex,
    pathKeys,
    treeNodePublicKeys,
    treeHash,
  };
}
