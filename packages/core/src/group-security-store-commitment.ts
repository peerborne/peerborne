import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
  isEncryptedGroupState,
  isEncryptedKeyPackageState,
} from './group-security-provider.js';
import {
  cloneGroupStateStoreKey,
  validateGroupStateStoreSnapshotSemantics,
} from './group-state-store.js';
import type {
  GroupStateForkEvidence,
  GroupStateOutboxEntry,
  GroupStatePendingKeyPackageRequest,
  GroupStateReplayEntry,
  GroupStateStoreKey,
  GroupStateStoreSnapshot,
} from './group-state-store.js';

const DOMAIN = asciiBytes('peerborne/group-security-store-snapshot/v2\0');
const MAX_ENTRIES = 65_536;
const MAX_PENDING_ENTRIES = 32;
const MAX_CONSUMED_ENTRIES = 4096;
const MAX_KEY_PACKAGE_REFERENCE_BYTES = 512;
const MAX_SHORT_BYTES = 0xffff;
const MAX_PROTOCOL_ID_BYTES = 128;
const MAX_GROUP_ID_BYTES = 1024;
const MAX_HASH_BYTES = 128;
const MAX_KEY_PACKAGE_PAYLOAD_BYTES = 4 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = 64 * 1024 * 1024;
const MAX_PROTECTOR_ALGORITHM_BYTES = 128;
const MAX_PROTECTOR_KEY_ID_BYTES = 256;
// These formulas mirror the provider envelope's complete serialized maxima.
// The aggregate limit includes framing, so simultaneous component maxima are
// intentionally rejected rather than expanding the 128 MiB safety ceiling.
const MAX_ENCRYPTED_STATE_BYTES =
  8 +
  2 +
  2 +
  MAX_PROTOCOL_ID_BYTES +
  2 +
  2 +
  MAX_GROUP_ID_BYTES +
  8 +
  2 +
  MAX_HASH_BYTES +
  2 +
  MAX_HASH_BYTES +
  2 +
  MAX_PROTECTOR_ALGORITHM_BYTES +
  2 +
  MAX_PROTECTOR_KEY_ID_BYTES +
  2 +
  MAX_SHORT_BYTES +
  4 +
  MAX_CIPHERTEXT_BYTES;
const MAX_ENCRYPTED_KEY_PACKAGE_BYTES =
  8 +
  2 +
  2 +
  MAX_PROTOCOL_ID_BYTES +
  2 +
  2 +
  MAX_GROUP_ID_BYTES +
  2 +
  MAX_KEY_PACKAGE_REFERENCE_BYTES +
  4 +
  MAX_KEY_PACKAGE_PAYLOAD_BYTES +
  2 +
  MAX_PROTECTOR_ALGORITHM_BYTES +
  2 +
  MAX_PROTECTOR_KEY_ID_BYTES +
  2 +
  MAX_SHORT_BYTES +
  4 +
  MAX_CIPHERTEXT_BYTES;
const MAX_PENDING_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_OUTBOX_PAYLOAD_BYTES = 16 * 1024 * 1024;
const MAX_CONTROL_RECORD_BYTES = 4 * 1024 * 1024;
const MAX_CANONICAL_SNAPSHOT_BYTES = 128 * 1024 * 1024;
const FIXED_ID_BYTES = 32;
const MAX_U64 = (1n << 64n) - 1n;

const encryptedGroupStateSerialize = EncryptedGroupState.prototype.serialize;
const encryptedGroupStateDeserialize = EncryptedGroupState.deserialize;
const encryptedKeyPackageStateSerialize =
  EncryptedKeyPackageState.prototype.serialize;
const encryptedKeyPackageGetter = intrinsicGetter(
  EncryptedKeyPackageState.prototype,
  'keyPackage',
);
const encryptedKeyPackageStateDeserialize =
  EncryptedKeyPackageState.deserialize;
const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const typedArrayByteLengthGetter = intrinsicGetter(
  typedArrayPrototype,
  'byteLength',
);
const typedArrayBufferGetter = intrinsicGetter(
  typedArrayPrototype,
  'buffer',
);
const typedArrayTagGetter = intrinsicGetter(
  typedArrayPrototype,
  Symbol.toStringTag,
);
const uint8ArraySet = Uint8Array.prototype.set;
const sharedArrayBufferByteLengthGetter =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )?.get;

export const GROUP_SECURITY_STORE_COMMITMENT_LENGTH = 32;

/**
 * Canonically commit every security-relevant byte in a durable store snapshot.
 * Array iteration order is ignored; duplicate identities and ambiguous object
 * shapes fail closed. The complete encoding is built synchronously before the
 * digest begins, so caller mutation during Web Crypto cannot change the vote.
 */
export async function groupSecurityStoreSnapshotCommitment(
  snapshot: GroupStateStoreSnapshot,
  key: GroupStateStoreKey,
): Promise<Uint8Array> {
  const encoded = canonicalGroupSecurityStoreSnapshot(snapshot, key);
  const subtle = globalThis.crypto?.subtle;
  const digest = subtle?.digest;
  if (typeof digest !== 'function') {
    throw new Error('Web Crypto SHA-256 digest is unavailable');
  }
  return new Uint8Array(
    (await Reflect.apply(digest, subtle, [
      'SHA-256',
      encoded as BufferSource,
    ])) as ArrayBuffer,
  );
}

/** Strictly validate and detach one complete bounded store snapshot. */
export function validateAndCloneGroupStateStoreSnapshot(
  snapshot: GroupStateStoreSnapshot,
  key: GroupStateStoreKey,
): GroupStateStoreSnapshot {
  return canonicalSnapshot(snapshot, key).snapshot;
}

/** Canonical binary input for the external rollback-anchor commitment. */
export function canonicalGroupSecurityStoreSnapshot(
  snapshotValue: GroupStateStoreSnapshot,
  key: GroupStateStoreKey,
): Uint8Array {
  return canonicalSnapshot(snapshotValue, key).encoded;
}

function canonicalSnapshot(
  snapshotValue: GroupStateStoreSnapshot,
  key: GroupStateStoreKey,
): {
  readonly encoded: Uint8Array;
  readonly snapshot: GroupStateStoreSnapshot;
} {
  const stableKey = cloneGroupStateStoreKey(key);
  const budget = new ByteBudget(
    MAX_CANONICAL_SNAPSHOT_BYTES,
    'canonical group-state snapshot',
  );
  budget.claim(DOMAIN.byteLength + 8);
  const record = snapshotObject(snapshotValue);
  const revision = safeInteger(
    dataProperty(record, 'revision'),
    'store revision',
    1,
  );

  const encryptedStateValue = optionalDataProperty(record, 'encryptedState');
  budget.claim(1);
  let encryptedState: Uint8Array | undefined;
  if (encryptedStateValue !== undefined) {
    encryptedState = canonicalEncryptedGroupState(
      encryptedStateValue,
      'serialized encrypted group state',
      budget,
    );
  }

  budget.claim(4);
  const pending = canonicalPending(
    dataProperty(record, 'pendingKeyPackages'),
    budget,
  );
  budget.claim(4);
  const consumed = canonicalConsumed(
    dataProperty(record, 'consumedKeyPackageRefs'),
    budget,
  );
  budget.claim(4);
  const pendingRequests = canonicalPendingRequests(
    dataProperty(record, 'pendingKeyPackageRequests'),
    budget,
  );
  budget.claim(4);
  const outbox = canonicalOutbox(dataProperty(record, 'outbox'), budget);
  budget.claim(4);
  const replay = canonicalReplay(dataProperty(record, 'replay'), budget);
  budget.claim(1);
  const fork = canonicalFork(
    optionalDataProperty(record, 'forkEvidence'),
    budget,
  );

  const parts: Uint8Array[] = [DOMAIN, u64(BigInt(revision))];
  if (encryptedState === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    parts.push(
      new Uint8Array([1]),
      u32(encryptedState.byteLength),
      encryptedState,
    );
  }
  parts.push(u32(pending.length));
  for (const entry of pending) {
    parts.push(
      u16(entry.reference.byteLength),
      entry.reference,
      u32(entry.serialized.byteLength),
      entry.serialized,
    );
  }
  parts.push(u32(pendingRequests.length));
  for (const request of pendingRequests) {
    parts.push(
      request.operationId,
      request.requestCommitment,
      u16(request.keyPackageReference.byteLength),
      request.keyPackageReference,
    );
  }
  parts.push(u32(consumed.length));
  for (const reference of consumed) {
    parts.push(u16(reference.byteLength), reference);
  }
  parts.push(u32(outbox.length));
  const textEncoder = new TextEncoder();
  for (const entry of outbox) {
    const kind = textEncoder.encode(entry.kind);
    parts.push(
      entry.id,
      u16(kind.byteLength),
      kind,
      u64(entry.epoch),
      u64(BigInt(entry.createdAt)),
      u32(entry.payload.byteLength),
      entry.payload,
    );
  }
  parts.push(u32(replay.length));
  for (const entry of replay) {
    parts.push(entry.recordId);
    if (entry.operationId === undefined) {
      parts.push(new Uint8Array([0]));
    } else {
      parts.push(
        new Uint8Array([1]),
        u32(entry.operationId.byteLength),
        entry.operationId,
      );
    }
    parts.push(
      u64(entry.epoch),
      u32(entry.controlRecord.byteLength),
      entry.controlRecord,
    );
  }
  if (fork === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    parts.push(
      new Uint8Array([1]),
      u32(fork.encoded.byteLength),
      fork.encoded,
    );
  }
  const encoded = concat(parts);
  if (encoded.byteLength !== budget.used) {
    throw new Error('canonical group-state snapshot accounting mismatch');
  }
  const snapshot: GroupStateStoreSnapshot = {
    revision,
    encryptedState:
      encryptedState === undefined
        ? undefined
        : Reflect.apply(
            encryptedGroupStateDeserialize,
            EncryptedGroupState,
            [encryptedState],
          ) as EncryptedGroupState,
    pendingKeyPackages: pending.map(
      (entry) =>
        Reflect.apply(
          encryptedKeyPackageStateDeserialize,
          EncryptedKeyPackageState,
          [entry.serialized],
        ) as EncryptedKeyPackageState,
    ),
    pendingKeyPackageRequests: pendingRequests.map((request) => ({
      operationId: copyBytes(request.operationId),
      requestCommitment: copyBytes(request.requestCommitment),
      keyPackageReference: copyBytes(request.keyPackageReference),
    })),
    consumedKeyPackageRefs: consumed.map(copyBytes),
    outbox: outbox.map((entry) => ({
      ...entry,
      id: copyBytes(entry.id),
      payload: copyBytes(entry.payload),
    })),
    replay: replay.map((entry) => ({
      ...entry,
      recordId: copyBytes(entry.recordId),
      operationId:
        entry.operationId === undefined
          ? undefined
          : copyBytes(entry.operationId),
      controlRecord: copyBytes(entry.controlRecord),
    })),
    forkEvidence:
      fork === undefined ? undefined : cloneForkEvidence(fork.evidence),
  };
  validateGroupStateStoreSnapshotSemantics(snapshot, stableKey);
  return { encoded, snapshot };
}

interface CanonicalPending {
  readonly reference: Uint8Array;
  readonly serialized: Uint8Array;
}

function canonicalPending(
  value: unknown,
  budget: ByteBudget,
): CanonicalPending[] {
  const entries = strictArray(value, 'pending KeyPackages', MAX_PENDING_ENTRIES);
  const pendingBudget = new ByteBudget(
    MAX_PENDING_TOTAL_BYTES,
    'pending KeyPackage bytes',
  );
  const canonical: CanonicalPending[] = [];
  for (let index = 0; index < entries.length; index++) {
    const { state, serialized } = canonicalEncryptedKeyPackageState(
      entries[index],
      `pending KeyPackage ${index}`,
      budget,
      pendingBudget,
    );
    const keyPackage = Reflect.apply(
      encryptedKeyPackageGetter,
      state,
      [],
    ) as EncryptedKeyPackageState['keyPackage'];
    const reference = boundedBytes(
      keyPackage.reference,
      `pending KeyPackage ${index} reference`,
      1,
      MAX_KEY_PACKAGE_REFERENCE_BYTES,
      budget,
      2,
    );
    canonical.push({ reference, serialized });
  }
  canonical.sort((left, right) => compareBytes(left.reference, right.reference));
  return canonical;
}

function canonicalPendingRequests(
  value: unknown,
  budget: ByteBudget,
): GroupStatePendingKeyPackageRequest[] {
  const snapshots = strictArray(
    value,
    'pending KeyPackage requests',
    MAX_PENDING_ENTRIES,
  ).map((entry, index) => {
    const request = exactObject(
      entry,
      ['operationId', 'requestCommitment', 'keyPackageReference'],
      `pending KeyPackage request ${index}`,
    );
    const operationId = boundedBytes(
      dataProperty(request, 'operationId'),
      `pending KeyPackage request ${index} operationId`,
      FIXED_ID_BYTES,
      FIXED_ID_BYTES,
      budget,
    );
    const requestCommitment = boundedBytes(
      dataProperty(request, 'requestCommitment'),
      `pending KeyPackage request ${index} commitment`,
      FIXED_ID_BYTES,
      FIXED_ID_BYTES,
      budget,
    );
    const keyPackageReference = boundedBytes(
      dataProperty(request, 'keyPackageReference'),
      `pending KeyPackage request ${index} reference`,
      1,
      MAX_KEY_PACKAGE_REFERENCE_BYTES,
      budget,
      2,
    );
    return { operationId, requestCommitment, keyPackageReference };
  });
  snapshots.sort((left, right) =>
    compareBytes(left.operationId, right.operationId),
  );
  return snapshots;
}

function canonicalConsumed(
  value: unknown,
  budget: ByteBudget,
): Uint8Array[] {
  const values = strictArray(
    value,
    'consumed KeyPackage references',
    MAX_CONSUMED_ENTRIES,
  );
  const entries: Uint8Array[] = [];
  for (let index = 0; index < values.length; index++) {
    entries.push(
      boundedBytes(
        values[index],
        `consumed KeyPackage reference ${index}`,
        1,
        MAX_KEY_PACKAGE_REFERENCE_BYTES,
        budget,
        2,
      ),
    );
  }
  entries.sort(compareBytes);
  return entries;
}

function canonicalOutbox(
  value: unknown,
  budget: ByteBudget,
): GroupStateOutboxEntry[] {
  const snapshots = strictArray(value, 'outbox', MAX_ENTRIES).map(
    (entry, index) => snapshotOutbox(entry, index, budget),
  );
  const entries = snapshots.map((entry) => ({
    id: copyByteView(entry.id),
    kind: entry.kind,
    epoch: entry.epoch,
    payload: copyByteView(entry.payload),
    createdAt: entry.createdAt,
  }));
  entries.sort((left, right) => compareBytes(left.id, right.id));
  return entries;
}

interface OutboxSnapshot {
  readonly id: ByteView;
  readonly kind: string;
  readonly epoch: bigint;
  readonly payload: ByteView;
  readonly createdAt: number;
}

function snapshotOutbox(
  value: unknown,
  index: number,
  budget: ByteBudget,
): OutboxSnapshot {
  const entry = exactObject(
    value,
    ['id', 'kind', 'epoch', 'payload', 'createdAt'],
    `outbox entry ${index}`,
  );
  const kind = dataProperty(entry, 'kind');
  if (
    typeof kind !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(kind)
  ) {
    throw new Error(`outbox entry ${index} kind is invalid`);
  }
  const id = byteView(
    dataProperty(entry, 'id'),
    `outbox entry ${index} id`,
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const payload = byteView(
    dataProperty(entry, 'payload'),
    `outbox entry ${index} payload`,
    1,
    MAX_OUTBOX_PAYLOAD_BYTES,
  );
  const epoch = u64Value(
    dataProperty(entry, 'epoch'),
    `outbox entry ${index} epoch`,
  );
  const createdAt = safeInteger(
    dataProperty(entry, 'createdAt'),
    `outbox entry ${index} createdAt`,
    0,
  );
  budget.claim(
    id.byteLength + 2 + kind.length + 8 + 8 + 4 + payload.byteLength,
  );
  return { id, kind, epoch, payload, createdAt };
}

function canonicalReplay(
  value: unknown,
  budget: ByteBudget,
): GroupStateReplayEntry[] {
  const snapshots = strictArray(value, 'replay', MAX_ENTRIES).map(
    (entry, index) => snapshotReplay(entry, index, budget),
  );
  const entries = snapshots.map((entry) => ({
    recordId: copyByteView(entry.recordId),
    operationId:
      entry.operationId === undefined
        ? undefined
        : copyByteView(entry.operationId),
    epoch: entry.epoch,
    controlRecord: copyByteView(entry.controlRecord),
  }));
  entries.sort((left, right) => compareBytes(left.recordId, right.recordId));
  return entries;
}

interface ReplaySnapshot {
  readonly recordId: ByteView;
  readonly operationId?: ByteView;
  readonly epoch: bigint;
  readonly controlRecord: ByteView;
}

function snapshotReplay(
  value: unknown,
  index: number,
  budget: ByteBudget,
): ReplaySnapshot {
  const entry = snapshotDataObject(
    value,
    ['recordId', 'operationId', 'epoch', 'controlRecord'],
    ['recordId', 'epoch', 'controlRecord'],
    `replay entry ${index}`,
  );
  const operationId = optionalDataProperty(entry, 'operationId');
  const recordId = byteView(
    dataProperty(entry, 'recordId'),
    `replay entry ${index} recordId`,
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const operationIdView =
    operationId === undefined
      ? undefined
      : byteView(
          operationId,
          `replay entry ${index} operationId`,
          FIXED_ID_BYTES,
          FIXED_ID_BYTES,
        );
  const controlRecord = byteView(
    dataProperty(entry, 'controlRecord'),
    `replay entry ${index} controlRecord`,
    1,
    MAX_CONTROL_RECORD_BYTES,
  );
  const epoch = u64Value(
    dataProperty(entry, 'epoch'),
    `replay entry ${index} epoch`,
  );
  budget.claim(
    recordId.byteLength +
      1 +
      (operationIdView === undefined ? 0 : 4 + operationIdView.byteLength) +
      8 +
      4 +
      controlRecord.byteLength,
  );
  return {
    recordId,
    operationId: operationIdView,
    epoch,
    controlRecord,
  };
}

interface CanonicalFork {
  readonly evidence: GroupStateForkEvidence;
  readonly encoded: Uint8Array;
}

function canonicalFork(
  value: unknown,
  budget: ByteBudget,
): CanonicalFork | undefined {
  if (value === undefined) return undefined;
  const evidence = exactObject(
    value,
    [
      'epoch',
      'parentRecordId',
      'firstRecordId',
      'firstControlRecord',
      'secondRecordId',
      'secondControlRecord',
    ],
    'fork evidence',
  );
  const parentRecordId = byteView(
    dataProperty(evidence, 'parentRecordId'),
    'fork parentRecordId',
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const firstRecordId = byteView(
    dataProperty(evidence, 'firstRecordId'),
    'fork firstRecordId',
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const firstControlRecord = byteView(
    dataProperty(evidence, 'firstControlRecord'),
    'fork firstControlRecord',
    1,
    MAX_CONTROL_RECORD_BYTES,
  );
  const secondRecordId = byteView(
    dataProperty(evidence, 'secondRecordId'),
    'fork secondRecordId',
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const secondControlRecord = byteView(
    dataProperty(evidence, 'secondControlRecord'),
    'fork secondControlRecord',
    1,
    MAX_CONTROL_RECORD_BYTES,
  );
  budget.claim(
    4 +
      8 +
      parentRecordId.byteLength +
      firstRecordId.byteLength +
      4 +
      firstControlRecord.byteLength +
      secondRecordId.byteLength +
      4 +
      secondControlRecord.byteLength,
  );
  const cloned: GroupStateForkEvidence = {
    epoch: u64Value(dataProperty(evidence, 'epoch'), 'fork evidence epoch'),
    parentRecordId: copyByteView(parentRecordId),
    firstRecordId: copyByteView(firstRecordId),
    firstControlRecord: copyByteView(firstControlRecord),
    secondRecordId: copyByteView(secondRecordId),
    secondControlRecord: copyByteView(secondControlRecord),
  };
  const ordered =
    compareBytes(cloned.firstRecordId, cloned.secondRecordId) <= 0
      ? [
          [cloned.firstRecordId, cloned.firstControlRecord],
          [cloned.secondRecordId, cloned.secondControlRecord],
        ]
      : [
          [cloned.secondRecordId, cloned.secondControlRecord],
          [cloned.firstRecordId, cloned.firstControlRecord],
        ];
  const normalized: GroupStateForkEvidence = {
    epoch: cloned.epoch,
    parentRecordId: cloned.parentRecordId,
    firstRecordId: ordered[0][0],
    firstControlRecord: ordered[0][1],
    secondRecordId: ordered[1][0],
    secondControlRecord: ordered[1][1],
  };
  return {
    evidence: normalized,
    encoded: concat([
      u64(normalized.epoch),
      normalized.parentRecordId,
      normalized.firstRecordId,
      bytes32(normalized.firstControlRecord),
      normalized.secondRecordId,
      bytes32(normalized.secondControlRecord),
    ]),
  };
}

function snapshotObject(value: unknown): Record<PropertyKey, unknown> {
  return snapshotDataObject(
    value,
    [
      'revision',
      'encryptedState',
      'pendingKeyPackages',
      'pendingKeyPackageRequests',
      'consumedKeyPackageRefs',
      'outbox',
      'replay',
      'forkEvidence',
    ],
    [
      'revision',
      'pendingKeyPackages',
      'pendingKeyPackageRequests',
      'consumedKeyPackageRefs',
      'outbox',
      'replay',
    ],
    'group-state snapshot',
  );
}

function exactObject(
  value: unknown,
  keys: ReadonlyArray<string>,
  field: string,
): Record<PropertyKey, unknown> {
  return snapshotDataObject(value, keys, keys, field);
}

function snapshotDataObject(
  value: unknown,
  allowed: ReadonlyArray<string>,
  required: ReadonlyArray<string>,
  field: string,
): Record<PropertyKey, unknown> {
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype =
      value !== null && typeof value === 'object'
        ? Object.getPrototypeOf(value)
        : null;
    keys =
      value !== null && typeof value === 'object' ? Reflect.ownKeys(value) : [];
  } catch {
    throw new Error(`${field} must be a plain data object`);
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    (prototype !== Object.prototype && prototype !== null)
  ) {
    throw new Error(`${field} must be a plain object`);
  }
  if (
    keys.some((key) => typeof key !== 'string' || !allowed.includes(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    throw new Error(`${field} has unexpected or missing fields`);
  }
  const snapshot = Object.create(null) as Record<PropertyKey, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${String(key)} must be an enumerable own data property`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function dataProperty(
  object: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !('value' in descriptor)
  ) {
    throw new Error(`${key} must be an enumerable own data property`);
  }
  return descriptor.value;
}

function optionalDataProperty(
  object: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  return Object.prototype.hasOwnProperty.call(object, key)
    ? dataProperty(object, key)
    : undefined;
}

function strictArray(
  value: unknown,
  field: string,
  maximum: number,
): unknown[] {
  let isArray: boolean;
  let prototype: object | null;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = Array.isArray(value);
    prototype = isArray ? Object.getPrototypeOf(value) : null;
    lengthDescriptor = isArray
      ? Object.getOwnPropertyDescriptor(value, 'length')
      : undefined;
  } catch {
    throw new Error(`${field} must be a bounded plain array`);
  }
  if (
    !isArray ||
    prototype !== Array.prototype ||
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > maximum
  ) {
    throw new Error(`${field} must be a bounded plain array`);
  }
  const length = lengthDescriptor.value as number;
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value as object);
  } catch {
    throw new Error(`${field} must be a bounded plain array`);
  }
  if (keys.length !== length + 1 || !keys.includes('length')) {
    throw new Error(`${field} must not be sparse or contain extra properties`);
  }
  const result = new Array<unknown>(length);
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${field} must contain only own data properties`);
    }
    result[index] = descriptor.value;
  }
  return result;
}

function boundedBytes(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
  budget?: ByteBudget,
  framingBytes = 0,
): Uint8Array {
  const view = byteView(value, field, minimum, maximum);
  budget?.claim(framingBytes + view.byteLength);
  return copyByteView(view);
}

function canonicalEncryptedGroupState(
  value: unknown,
  field: string,
  budget: ByteBudget,
): Uint8Array {
  if (!isEncryptedGroupState(value)) {
    throw new Error('store encryptedState is not a branded EncryptedGroupState');
  }
  const serializedValue = Reflect.apply(
    encryptedGroupStateSerialize,
    value,
    [],
  ) as unknown;
  const serialized = byteView(
    serializedValue,
    field,
    1,
    MAX_ENCRYPTED_STATE_BYTES,
  );
  budget.claim(4 + serialized.byteLength);
  const snapshot = copyByteView(serialized);
  const reconstructed = Reflect.apply(
    encryptedGroupStateDeserialize,
    EncryptedGroupState,
    [snapshot],
  ) as EncryptedGroupState;
  const canonicalValue = Reflect.apply(
    encryptedGroupStateSerialize,
    reconstructed,
    [],
  ) as unknown;
  const canonical = byteView(
    canonicalValue,
    `${field} canonical form`,
    1,
    MAX_ENCRYPTED_STATE_BYTES,
  );
  if (!equalBytes(snapshot, canonical.value)) {
    throw new Error(`${field} is not canonically serialized`);
  }
  return snapshot;
}

function canonicalEncryptedKeyPackageState(
  value: unknown,
  field: string,
  budget: ByteBudget,
  pendingBudget: ByteBudget,
): { readonly state: EncryptedKeyPackageState; readonly serialized: Uint8Array } {
  if (!isEncryptedKeyPackageState(value)) {
    throw new Error(`${field} is not branded encrypted state`);
  }
  const serializedValue = Reflect.apply(
    encryptedKeyPackageStateSerialize,
    value,
    [],
  ) as unknown;
  const serialized = byteView(
    serializedValue,
    field,
    1,
    MAX_ENCRYPTED_KEY_PACKAGE_BYTES,
  );
  pendingBudget.claim(serialized.byteLength);
  budget.claim(4 + serialized.byteLength);
  const snapshot = copyByteView(serialized);
  const reconstructed = Reflect.apply(
    encryptedKeyPackageStateDeserialize,
    EncryptedKeyPackageState,
    [snapshot],
  ) as EncryptedKeyPackageState;
  const canonicalValue = Reflect.apply(
    encryptedKeyPackageStateSerialize,
    reconstructed,
    [],
  ) as unknown;
  const canonical = byteView(
    canonicalValue,
    `${field} canonical form`,
    1,
    MAX_ENCRYPTED_KEY_PACKAGE_BYTES,
  );
  if (!equalBytes(snapshot, canonical.value)) {
    throw new Error(`${field} is not canonically serialized`);
  }
  return { state: reconstructed, serialized: snapshot };
}

interface ByteView {
  readonly value: Uint8Array;
  readonly byteLength: number;
}

function byteView(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): ByteView {
  let tag: unknown;
  let byteLength: unknown;
  let buffer: unknown;
  try {
    tag = Reflect.apply(typedArrayTagGetter, value, []);
    byteLength = Reflect.apply(typedArrayByteLengthGetter, value, []);
    buffer = Reflect.apply(typedArrayBufferGetter, value, []);
  } catch {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  if (
    tag !== 'Uint8Array' ||
    typeof byteLength !== 'number' ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < minimum ||
    byteLength > maximum ||
    isSharedBuffer(buffer)
  ) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  return { value: value as Uint8Array, byteLength };
}

function copyByteView(view: ByteView): Uint8Array {
  const copy = new Uint8Array(view.byteLength);
  Reflect.apply(uint8ArraySet, copy, [view.value, 0]);
  return copy;
}

function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

function cloneForkEvidence(
  evidence: GroupStateForkEvidence,
): GroupStateForkEvidence {
  return {
    epoch: evidence.epoch,
    parentRecordId: copyBytes(evidence.parentRecordId),
    firstRecordId: copyBytes(evidence.firstRecordId),
    firstControlRecord: copyBytes(evidence.firstControlRecord),
    secondRecordId: copyBytes(evidence.secondRecordId),
    secondControlRecord: copyBytes(evidence.secondControlRecord),
  };
}

class ByteBudget {
  private usedValue = 0;

  constructor(
    private readonly maximum: number,
    private readonly field: string,
  ) {}

  get used(): number {
    return this.usedValue;
  }

  claim(byteLength: number): void {
    if (
      !Number.isSafeInteger(byteLength) ||
      byteLength < 0 ||
      byteLength > this.maximum - this.usedValue
    ) {
      throw new Error(`${this.field} exceeds its byte bound`);
    }
    this.usedValue += byteLength;
  }
}

function intrinsicGetter(
  prototype: object,
  key: PropertyKey,
): (this: unknown) => unknown {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (getter === undefined) {
    throw new Error(`missing Uint8Array intrinsic ${String(key)}`);
  }
  return getter;
}

function safeInteger(
  value: unknown,
  field: string,
  minimum: number,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum
  ) {
    throw new Error(`${field} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function u64Value(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
  return value;
}

function bytes32(value: Uint8Array): Uint8Array {
  if (value.byteLength > 0xffffffff) {
    throw new Error('value does not fit in u32');
  }
  return concat([u32(value.byteLength), value]);
}

function u16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('value does not fit in u16');
  }
  const output = new Uint8Array(2);
  new DataView(output.buffer).setUint16(0, value, false);
  return output;
}

function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('value does not fit in u32');
  }
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

function u64(value: bigint): Uint8Array {
  if (value < 0n || value > MAX_U64) {
    throw new Error('value does not fit in u64');
  }
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, value, false);
  return output;
}

function asciiBytes(value: string): Uint8Array {
  const output = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code > 0x7f) throw new Error('commitment domain must be ASCII');
    output[index] = code;
  }
  return output;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let different = 0;
  for (let index = 0; index < left.byteLength; index++) {
    different |= left[index] ^ right[index];
  }
  return different === 0;
}

function isSharedBuffer(value: unknown): boolean {
  if (sharedArrayBufferByteLengthGetter === undefined) return false;
  try {
    Reflect.apply(sharedArrayBufferByteLengthGetter, value, []);
    return true;
  } catch {
    return false;
  }
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  if (total > MAX_CANONICAL_SNAPSHOT_BYTES) {
    throw new Error('canonical group-state snapshot exceeds its byte bound');
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}
