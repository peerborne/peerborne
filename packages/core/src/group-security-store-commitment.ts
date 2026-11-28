import {
  compareBytes,
  concatBytes,
  equalBytes,
  setBytes,
  totalByteLength,
  unsharedUint8ArrayByteLength,
} from './internal/bytes.js';
import {
  optionalOwnDataProperty,
  ownDataProperty,
  requireIntrinsicGetter,
} from './internal/data-property.js';
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
import {
  asciiBytes,
  encodeU16,
  encodeU32,
  encodeU64,
  lengthPrefixed32,
  requireU64,
} from './internal/big-endian.js';
import { isCanonicalIdentifier } from './internal/protocol-identifier.js';
import {
  snapshotPlainDataArray,
  snapshotPlainDataObject,
} from './internal/plain-data.js';

let textEncoder: TextEncoder | undefined;

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
const encryptedGroupStateSerialize = EncryptedGroupState.prototype.serialize;
const encryptedGroupStateDeserialize = EncryptedGroupState.deserialize;
const encryptedKeyPackageStateSerialize =
  EncryptedKeyPackageState.prototype.serialize;
const encryptedKeyPackageGetter = requireIntrinsicGetter(
  EncryptedKeyPackageState.prototype,
  'keyPackage',
  'EncryptedKeyPackageState.keyPackage',
);
const encryptedKeyPackageStateDeserialize =
  EncryptedKeyPackageState.deserialize;

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
    ownDataProperty(record, 'revision'),
    'store revision',
    1,
  );

  const encryptedStateValue = optionalOwnDataProperty(record, 'encryptedState');
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
    ownDataProperty(record, 'pendingKeyPackages'),
    budget,
  );
  budget.claim(4);
  const consumed = canonicalConsumed(
    ownDataProperty(record, 'consumedKeyPackageRefs'),
    budget,
  );
  budget.claim(4);
  const pendingRequests = canonicalPendingRequests(
    ownDataProperty(record, 'pendingKeyPackageRequests'),
    budget,
  );
  budget.claim(4);
  const outbox = canonicalOutbox(ownDataProperty(record, 'outbox'), budget);
  budget.claim(4);
  const replay = canonicalReplay(ownDataProperty(record, 'replay'), budget);
  budget.claim(1);
  const fork = canonicalFork(
    optionalOwnDataProperty(record, 'forkEvidence'),
    budget,
  );

  const parts: Uint8Array[] = [DOMAIN, encodeU64(BigInt(revision))];
  if (encryptedState === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    parts.push(
      new Uint8Array([1]),
      encodeU32(encryptedState.byteLength),
      encryptedState,
    );
  }
  parts.push(encodeU32(pending.length));
  for (const entry of pending) {
    parts.push(
      encodeU16(entry.reference.byteLength),
      entry.reference,
      encodeU32(entry.serialized.byteLength),
      entry.serialized,
    );
  }
  parts.push(encodeU32(pendingRequests.length));
  for (const request of pendingRequests) {
    parts.push(
      request.operationId,
      request.requestCommitment,
      encodeU16(request.keyPackageReference.byteLength),
      request.keyPackageReference,
    );
  }
  parts.push(encodeU32(consumed.length));
  for (const reference of consumed) {
    parts.push(encodeU16(reference.byteLength), reference);
  }
  parts.push(encodeU32(outbox.length));
  for (const entry of outbox) {
    const kind = (textEncoder ??= new TextEncoder()).encode(entry.kind);
    parts.push(
      entry.id,
      encodeU16(kind.byteLength),
      kind,
      encodeU64(entry.epoch),
      encodeU64(BigInt(entry.createdAt)),
      encodeU32(entry.payload.byteLength),
      entry.payload,
    );
  }
  parts.push(encodeU32(replay.length));
  for (const entry of replay) {
    parts.push(entry.recordId);
    if (entry.operationId === undefined) {
      parts.push(new Uint8Array([0]));
    } else {
      parts.push(
        new Uint8Array([1]),
        encodeU32(entry.operationId.byteLength),
        entry.operationId,
      );
    }
    parts.push(
      encodeU64(entry.epoch),
      encodeU32(entry.controlRecord.byteLength),
      entry.controlRecord,
    );
  }
  if (fork === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    parts.push(new Uint8Array([1]), encodeU32(fork.encoded.byteLength), fork.encoded);
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
        : (Reflect.apply(encryptedGroupStateDeserialize, EncryptedGroupState, [
            encryptedState,
          ]) as EncryptedGroupState),
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
  const entries = snapshotPlainDataArray(
    value,
    'pending KeyPackages',
    MAX_PENDING_ENTRIES,
  );
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
  canonical.sort((left, right) =>
    compareBytes(left.reference, right.reference),
  );
  return canonical;
}

function canonicalPendingRequests(
  value: unknown,
  budget: ByteBudget,
): GroupStatePendingKeyPackageRequest[] {
  const snapshots = snapshotPlainDataArray(
    value,
    'pending KeyPackage requests',
    MAX_PENDING_ENTRIES,
  ).map((entry, index) => {
    const request = snapshotPlainDataObject(
      entry,
      ['operationId', 'requestCommitment', 'keyPackageReference'],
      `pending KeyPackage request ${index}`,
    );
    const operationId = boundedBytes(
      ownDataProperty(request, 'operationId'),
      `pending KeyPackage request ${index} operationId`,
      FIXED_ID_BYTES,
      FIXED_ID_BYTES,
      budget,
    );
    const requestCommitment = boundedBytes(
      ownDataProperty(request, 'requestCommitment'),
      `pending KeyPackage request ${index} commitment`,
      FIXED_ID_BYTES,
      FIXED_ID_BYTES,
      budget,
    );
    const keyPackageReference = boundedBytes(
      ownDataProperty(request, 'keyPackageReference'),
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

function canonicalConsumed(value: unknown, budget: ByteBudget): Uint8Array[] {
  const values = snapshotPlainDataArray(
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
  const snapshots = snapshotPlainDataArray(value, 'outbox', MAX_ENTRIES).map(
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
  const entry = snapshotPlainDataObject(
    value,
    ['id', 'kind', 'epoch', 'payload', 'createdAt'],
    `outbox entry ${index}`,
  );
  const kind = ownDataProperty(entry, 'kind');
  if (!isCanonicalIdentifier(kind)) {
    throw new Error(`outbox entry ${index} kind is invalid`);
  }
  const id = byteView(
    ownDataProperty(entry, 'id'),
    `outbox entry ${index} id`,
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const payload = byteView(
    ownDataProperty(entry, 'payload'),
    `outbox entry ${index} payload`,
    1,
    MAX_OUTBOX_PAYLOAD_BYTES,
  );
  const epoch = requireU64(
    ownDataProperty(entry, 'epoch'),
    `outbox entry ${index} epoch`,
  );
  const createdAt = safeInteger(
    ownDataProperty(entry, 'createdAt'),
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
  const snapshots = snapshotPlainDataArray(value, 'replay', MAX_ENTRIES).map(
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
  const entry = snapshotPlainDataObject(
    value,
    ['recordId', 'operationId', 'epoch', 'controlRecord'],
    `replay entry ${index}`,
    ['recordId', 'epoch', 'controlRecord'],
  );
  const operationId = optionalOwnDataProperty(entry, 'operationId');
  const recordId = byteView(
    ownDataProperty(entry, 'recordId'),
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
    ownDataProperty(entry, 'controlRecord'),
    `replay entry ${index} controlRecord`,
    1,
    MAX_CONTROL_RECORD_BYTES,
  );
  const epoch = requireU64(
    ownDataProperty(entry, 'epoch'),
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
  const evidence = snapshotPlainDataObject(
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
    ownDataProperty(evidence, 'parentRecordId'),
    'fork parentRecordId',
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const firstRecordId = byteView(
    ownDataProperty(evidence, 'firstRecordId'),
    'fork firstRecordId',
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const firstControlRecord = byteView(
    ownDataProperty(evidence, 'firstControlRecord'),
    'fork firstControlRecord',
    1,
    MAX_CONTROL_RECORD_BYTES,
  );
  const secondRecordId = byteView(
    ownDataProperty(evidence, 'secondRecordId'),
    'fork secondRecordId',
    FIXED_ID_BYTES,
    FIXED_ID_BYTES,
  );
  const secondControlRecord = byteView(
    ownDataProperty(evidence, 'secondControlRecord'),
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
    epoch: requireU64(ownDataProperty(evidence, 'epoch'), 'fork evidence epoch'),
    parentRecordId: copyByteView(parentRecordId),
    firstRecordId: copyByteView(firstRecordId),
    firstControlRecord: copyByteView(firstControlRecord),
    secondRecordId: copyByteView(secondRecordId),
    secondControlRecord: copyByteView(secondControlRecord),
  };
  if (equalBytes(cloned.firstRecordId, cloned.secondRecordId)) {
    throw new Error('fork record IDs must be distinct');
  }
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
      encodeU64(normalized.epoch),
      normalized.parentRecordId,
      normalized.firstRecordId,
      lengthPrefixed32(normalized.firstControlRecord),
      normalized.secondRecordId,
      lengthPrefixed32(normalized.secondControlRecord),
    ]),
  };
}

function snapshotObject(value: unknown): Record<PropertyKey, unknown> {
  return snapshotPlainDataObject(
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
    'group-state snapshot',
    [
      'revision',
      'pendingKeyPackages',
      'pendingKeyPackageRequests',
      'consumedKeyPackageRefs',
      'outbox',
      'replay',
    ],
  );
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
    throw new Error(
      'store encryptedState is not a branded EncryptedGroupState',
    );
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
): {
  readonly state: EncryptedKeyPackageState;
  readonly serialized: Uint8Array;
} {
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
  return {
    value: value as Uint8Array,
    byteLength: unsharedUint8ArrayByteLength(value, minimum, maximum, field),
  };
}

function copyByteView(view: ByteView): Uint8Array {
  const copy = new Uint8Array(view.byteLength);
  setBytes(copy, view.value);
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

function safeInteger(value: unknown, field: string, minimum: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum
  ) {
    throw new Error(`${field} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  if (totalByteLength(parts) > MAX_CANONICAL_SNAPSHOT_BYTES) {
    throw new Error('canonical group-state snapshot exceeds its byte bound');
  }
  return concatBytes(parts);
}
