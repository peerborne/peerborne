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
    if (Reflect.has(welcome, field)) {
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
  const wire: SerializedBeeKEMWelcomeV2 = {
    version: 2,
    generation: welcome.generation,
    numLeaves: welcome.numLeaves,
    ...serializeBeeKEMWelcomeBase(welcome),
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
  const budget = createV2DecodeBudget();
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
      pathOffset <= previousPathOffset ||
      covered.has(nodeIndex)
    ) {
      throw new Error(
        `Invalid BeeKEMWelcomeV2: pathKeys[${offset}] has an invalid, duplicate, or out-of-order nodeIndex`,
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
      `Invalid BeeKEMWelcomeV2: aggregate work budget exceeded at ${context}`,
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
      `Invalid BeeKEMWelcomeV2: aggregate decoded-byte budget exceeded at ${fieldName}`,
    );
  }
  budget.decodedBytes += decodedUpperBound;
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

function decodeBoundedBase64(
  value: string,
  fieldName: string,
  maxBytes: number,
  budget: V2DecodeBudget,
): Uint8Array {
  if (value.length > Math.ceil(maxBytes / 3) * 4 + 4) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: ${fieldName} exceeds the encoded size limit`,
    );
  }
  const decoded = decodeCanonicalBase64(value, fieldName, maxBytes, budget);
  if (decoded.byteLength > maxBytes) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: ${fieldName} exceeds the decoded size limit`,
    );
  }
  return decoded;
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
    throw new Error(
      `Invalid BeeKEMWelcomeV2: ${fieldName} exceeds the encoded size limit`,
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
      `Invalid BeeKEMWelcomeV2: ${fieldName} must use canonical padded base64`,
    );
  }
  const decoded = decodeBase64(value, fieldName);
  if (maxBytes !== undefined && decoded.byteLength > maxBytes) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: ${fieldName} exceeds the decoded size limit`,
    );
  }
  if (Base64.fromUint8Array(decoded) !== value) {
    throw new Error(
      `Invalid BeeKEMWelcomeV2: ${fieldName} must use canonical padded base64`,
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
