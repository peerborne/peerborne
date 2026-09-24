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

const MAX_V2_PATH_KEYS = 64;
const MAX_V2_CIPHERTEXT_BYTES = 64 * (4096 + 8) + 4096;
const WELCOME_V2: V2WireCodec = {
  typeName: 'BeeKEMWelcomeV2',
  maxAggregateDecodedBytes: 4 * 1024 * 1024,
  maxAggregateWorkItems: 4 * MAX_BEEKEM_TREE_LEAVES,
};
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

function serializeBeeKEMWelcomeBase(
  welcome: BeeKEMWelcome,
): SerializedBeeKEMWelcome {
  return {
    leafIndex: welcome.leafIndex,
    pathKeys: welcome.pathKeys.map((n) => ({
      nodeIndex: n.nodeIndex,
      publicKey: Base64.fromUint8Array(n.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(n.encryptedPrivateKey),
    })),
    treeNodePublicKeys: welcome.treeNodePublicKeys.map((e) => ({
      nodeIndex: e.nodeIndex,
      publicKey:
        e.publicKey === null ? null : Base64.fromUint8Array(e.publicKey),
    })),
    treeHash: Base64.fromUint8Array(welcome.treeHash),
  };
}

/** Convert a runtime v1 `BeeKEMWelcome` to its JSON-safe wire form. */
export function serializeBeeKEMWelcomeForWire(
  welcome: BeeKEMWelcome,
): SerializedBeeKEMWelcome {
  for (const field of ['version', 'generation', 'numLeaves']) {
    const descriptor = Object.getOwnPropertyDescriptor(welcome, field);
    if (
      descriptor !== undefined &&
      !('value' in descriptor && descriptor.value === undefined)
    ) {
      throw new Error(
        `Cannot serialize BeeKEMWelcome with v2-only field '${field}' as v1`,
      );
    }
  }
  return serializeBeeKEMWelcomeBase(welcome);
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
 * `BeeKEMWelcome`. Surfaces a descriptive error for malformed inputs,
 * mirroring the validation posture used by `path-update-wire.ts`.
 */
export function deserializeBeeKEMWelcomeFromWire(
  wire: unknown,
): BeeKEMWelcome {
  if (typeof wire !== 'object' || wire === null || Array.isArray(wire)) {
    throw new Error(
      `Invalid BeeKEMWelcome: expected a plain object, got ${describe(wire)}`,
    );
  }
  const raw = wire as Record<string, unknown>;

  for (const field of ['version', 'generation', 'numLeaves']) {
    if (Object.prototype.hasOwnProperty.call(raw, field)) {
      throw new Error(
        `Invalid BeeKEMWelcome v1: v2-only field '${field}' is not allowed`,
      );
    }
  }

  if (
    typeof raw.leafIndex !== 'number' ||
    !Number.isInteger(raw.leafIndex) ||
    raw.leafIndex < 0
  ) {
    throw new Error(
      `Invalid BeeKEMWelcome: 'leafIndex' must be a non-negative integer (got ${describe(
        raw.leafIndex,
      )})`,
    );
  }
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
  const pathKeys: PathNodeUpdate[] = raw.pathKeys.map((n, i) => {
    if (typeof n !== 'object' || n === null || Array.isArray(n)) {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}] must be a plain object, got ${describe(n)}`,
      );
    }
    const nn = n as Record<string, unknown>;
    if (
      typeof nn.nodeIndex !== 'number' ||
      !Number.isInteger(nn.nodeIndex) ||
      nn.nodeIndex < 0
    ) {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}].nodeIndex must be a non-negative integer (got ${describe(
          nn.nodeIndex,
        )})`,
      );
    }
    if (typeof nn.publicKey !== 'string') {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}].publicKey must be a base64 string (got ${describe(
          nn.publicKey,
        )})`,
      );
    }
    if (typeof nn.encryptedPrivateKey !== 'string') {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}].encryptedPrivateKey must be a base64 string (got ${describe(
          nn.encryptedPrivateKey,
        )})`,
      );
    }
    return {
      nodeIndex: nn.nodeIndex,
      publicKey: decodeBase64(nn.publicKey, `pathKeys[${i}].publicKey`),
      encryptedPrivateKey: decodeBase64(
        nn.encryptedPrivateKey,
        `pathKeys[${i}].encryptedPrivateKey`,
      ),
    };
  });

  const treeNodePublicKeys: WelcomeNodePublicKey[] = raw.treeNodePublicKeys.map(
    (n, i) => {
      if (typeof n !== 'object' || n === null || Array.isArray(n)) {
        throw new Error(
          `Invalid BeeKEMWelcome: treeNodePublicKeys[${i}] must be a plain object, got ${describe(
            n,
          )}`,
        );
      }
      const nn = n as Record<string, unknown>;
      if (
        typeof nn.nodeIndex !== 'number' ||
        !Number.isInteger(nn.nodeIndex) ||
        nn.nodeIndex < 0
      ) {
        throw new Error(
          `Invalid BeeKEMWelcome: treeNodePublicKeys[${i}].nodeIndex must be a non-negative integer (got ${describe(
            nn.nodeIndex,
          )})`,
        );
      }
      if (nn.publicKey === null) {
        return { nodeIndex: nn.nodeIndex, publicKey: null };
      }
      if (typeof nn.publicKey !== 'string') {
        throw new Error(
          `Invalid BeeKEMWelcome: treeNodePublicKeys[${i}].publicKey must be a base64 string or null (got ${describe(
            nn.publicKey,
          )})`,
        );
      }
      return {
        nodeIndex: nn.nodeIndex,
        publicKey: decodeBase64(
          nn.publicKey,
          `treeNodePublicKeys[${i}].publicKey`,
        ),
      };
    },
  );

  return {
    leafIndex: raw.leafIndex,
    pathKeys,
    treeNodePublicKeys,
    treeHash: decodeBase64(raw.treeHash, 'treeHash'),
  };
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
