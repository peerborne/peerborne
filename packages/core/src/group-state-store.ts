import { trackQueuedOperation } from './queued-operation.js';
import {
  adjustStoreBytes,
  nextStoreRevision,
  classifyStoreCommitBaseline,
} from './policy/store-budget.js';
import {
  insertPendingPackage,
  removePendingPackage,
  insertConsumptionMarker,
  bindOperationToRecord,
} from './policy/package-partition.js';
import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
  GroupKeyPackage,
  GroupSecurityProtocol,
  GroupSecurityPublicState,
  isEncryptedGroupState,
  isEncryptedKeyPackageState,
} from './group-security-provider.js';
import {
  byteLengthOf,
  compareBytes,
  copyUnsharedUint8Array,
  equalBytes,
  optionalEqualBytes,
} from './internal/bytes.js';
import { bytesToHex } from './internal/hex.js';
import { requireU64 } from './internal/big-endian.js';
import {
  optionalOwnDataProperty,
  ownDataProperty,
  requireIntrinsicGetter,
} from './internal/data-property.js';
import { snapshotPlainDataObject } from './internal/plain-data.js';
import {
  isCanonicalIdentifier,
  sameProtocol,
  snapshotCanonicalProtocol,
} from './internal/protocol-identifier.js';

export const GROUP_STATE_STORE_ID_LENGTH = 32;
export const MAX_CONSUMED_KEY_PACKAGE_MARKERS = 4096;
export const MAX_PENDING_KEY_PACKAGE_ENTRIES = 32;
export const MAX_PENDING_KEY_PACKAGE_BYTES = 64 * 1024 * 1024;
/** Conservative framed size ceiling for one committed store snapshot. */
export const MAX_GROUP_STATE_STORE_COMMITTED_BYTES = 128 * 1024 * 1024;

const MAX_OUTBOX_PAYLOAD_BYTES = 16 * 1024 * 1024;
const MAX_CONTROL_RECORD_BYTES = 4 * 1024 * 1024;
const MAX_KEY_PACKAGE_REFERENCE_BYTES = 512;
const MAX_GROUP_STATE_METADATA_ENTRIES = 65_536;
const COMMITTED_STATE_FIXED_OVERHEAD = 1024;

// Lengths belong only to internally decoded envelopes with immutable private fields.
const clonedEnvelopeLengths = new WeakMap<object, number>();
const serializeEncryptedGroupState = EncryptedGroupState.prototype.serialize;
const deserializeEncryptedGroupState = EncryptedGroupState.deserialize;
const encryptedGroupStateValue = requireIntrinsicGetter(
  EncryptedGroupState.prototype,
  'state',
  'EncryptedGroupState.state',
);
const serializeEncryptedKeyPackageState =
  EncryptedKeyPackageState.prototype.serialize;
const deserializeEncryptedKeyPackageState =
  EncryptedKeyPackageState.deserialize;
const encryptedKeyPackageValue = requireIntrinsicGetter(
  EncryptedKeyPackageState.prototype,
  'keyPackage',
  'EncryptedKeyPackageState.keyPackage',
);

for (const [name, method] of [
  ['EncryptedGroupState.serialize', serializeEncryptedGroupState],
  ['EncryptedGroupState.deserialize', deserializeEncryptedGroupState],
  ['EncryptedKeyPackageState.serialize', serializeEncryptedKeyPackageState],
  ['EncryptedKeyPackageState.deserialize', deserializeEncryptedKeyPackageState],
] as const) {
  if (typeof method !== 'function') {
    throw new Error(`group-state-store requires callable ${name}`);
  }
}

export interface GroupStateStoreKey {
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
}

export interface GroupStateOutboxEntry {
  readonly id: Uint8Array;
  readonly kind: string;
  readonly epoch: bigint;
  /** Encoded network delivery; plaintext private provider state is forbidden. */
  readonly payload: Uint8Array;
  readonly createdAt: number;
}

export interface GroupStateReplayEntry {
  readonly recordId: Uint8Array;
  readonly operationId?: Uint8Array;
  readonly epoch: bigint;
  /** Strictly serialized authenticated control record, never private state. */
  readonly controlRecord: Uint8Array;
}

/** Durable idempotency binding for one pending KeyPackage request. */
export interface GroupStatePendingKeyPackageRequest {
  readonly operationId: Uint8Array;
  readonly requestCommitment: Uint8Array;
  readonly keyPackageReference: Uint8Array;
}

/** Durable, canonical evidence that two signed controls share one parent. */
export interface GroupStateForkEvidence {
  readonly epoch: bigint;
  readonly parentRecordId: Uint8Array;
  readonly firstRecordId: Uint8Array;
  readonly firstControlRecord: Uint8Array;
  readonly secondRecordId: Uint8Array;
  readonly secondControlRecord: Uint8Array;
}

export interface GroupStateStoreSnapshot {
  /** Committed per-key revision. Snapshots always have revision >= 1. */
  readonly revision: number;
  readonly encryptedState?: EncryptedGroupState;
  /** Ciphertext-only one-time packages which have not joined a group. */
  readonly pendingKeyPackages: ReadonlyArray<EncryptedKeyPackageState>;
  /** Stable request bindings used to resume ambiguous KeyPackage writes. */
  readonly pendingKeyPackageRequests: ReadonlyArray<GroupStatePendingKeyPackageRequest>;
  /** Irreversible replay tombstones; private package ciphertext is discarded. */
  readonly consumedKeyPackageRefs: ReadonlyArray<Uint8Array>;
  readonly outbox: ReadonlyArray<GroupStateOutboxEntry>;
  readonly replay: ReadonlyArray<GroupStateReplayEntry>;
  readonly forkEvidence?: GroupStateForkEvidence;
}

export interface GroupStateStoreTransaction {
  readonly baseRevision: number;
  readonly encryptedState: EncryptedGroupState | undefined;
  readonly pendingKeyPackages: ReadonlyArray<EncryptedKeyPackageState>;
  readonly pendingKeyPackageRequests: ReadonlyArray<GroupStatePendingKeyPackageRequest>;
  readonly consumedKeyPackageRefs: ReadonlyArray<Uint8Array>;
  readonly outbox: ReadonlyArray<GroupStateOutboxEntry>;
  readonly replay: ReadonlyArray<GroupStateReplayEntry>;
  readonly forkEvidence: GroupStateForkEvidence | undefined;
  setEncryptedState(state: EncryptedGroupState): void;
  /** Returns a strict serialized clone, never the store's live envelope. */
  getPendingKeyPackage(
    reference: Uint8Array,
  ): EncryptedKeyPackageState | undefined;
  /** Inserts an encrypted package; an identical existing envelope is a no-op. */
  putPendingKeyPackage(state: EncryptedKeyPackageState): boolean;
  getPendingKeyPackageRequest(
    operationId: Uint8Array,
  ): GroupStatePendingKeyPackageRequest | undefined;
  /** Binds one operation and request commitment to an existing pending state. */
  bindPendingKeyPackageRequest(
    request: GroupStatePendingKeyPackageRequest,
  ): boolean;
  hasConsumedKeyPackage(reference: Uint8Array): boolean;
  /**
   * Atomically moves a pending package to consumed and returns a strict clone.
   * Its pending request binding is removed in the same transaction. Missing,
   * previously consumed, conflicting, and over-capacity references fail
   * closed. Consumed references cannot be removed or made pending again.
   */
  consumePendingKeyPackage(reference: Uint8Array): EncryptedKeyPackageState;
  enqueueOutbox(entry: GroupStateOutboxEntry): boolean;
  removeOutbox(id: Uint8Array): boolean;
  hasReplayRecord(recordId: Uint8Array): boolean;
  markReplay(entry: GroupStateReplayEntry): boolean;
  removeReplay(recordId: Uint8Array): boolean;
  markFork(evidence: GroupStateForkEvidence): boolean;
}

/**
 * Atomic persistence boundary for encrypted provider state, one-time
 * KeyPackages, durable delivery, and replay metadata.
 *
 * Implementations must serialize transactions independently for each canonical
 * store key. An absent key has logical revision 0 and `load` represents it as
 * `undefined`; a transaction over an absent key therefore observes
 * `baseRevision === 0`. Every successful transaction, including a no-op,
 * commits exactly `baseRevision + 1`. A callback rejection, thrown exception,
 * validation failure, or revision overflow leaves both the prior revision and
 * all prior data unchanged.
 *
 * Count retention for outbox and control-record replay metadata is enforced by
 * the coordinator. Consumed KeyPackage markers are bounded by the store and
 * fail closed at capacity so a consumed reference is never made reusable by
 * eviction.
 */
export interface DurableGroupStateStore {
  load(key: GroupStateStoreKey): Promise<GroupStateStoreSnapshot | undefined>;
  transaction<T>(
    key: GroupStateStoreKey,
    operation: (transaction: GroupStateStoreTransaction) => T | Promise<T>,
  ): Promise<T>;
}

interface MutableState {
  revision: number;
  encryptedState?: EncryptedGroupState;
  pendingKeyPackages: Map<string, EncryptedKeyPackageState>;
  pendingKeyPackageRequests: Map<string, GroupStatePendingKeyPackageRequest>;
  consumedKeyPackageRefs: Map<string, Uint8Array>;
  outbox: Map<string, GroupStateOutboxEntry>;
  replay: Map<string, GroupStateReplayEntry>;
  operationToRecord: Map<string, string>;
  forkEvidence?: GroupStateForkEvidence;
}

/** In-memory reference implementation with transactional rollback semantics. */
export class InMemoryGroupStateStore implements DurableGroupStateStore {
  private readonly groups = new Map<string, MutableState>();
  private readonly tails = new Map<string, Promise<void>>();

  constructor(
    private readonly maximumCommittedBytes = MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
  ) {
    if (
      !Number.isSafeInteger(maximumCommittedBytes) ||
      maximumCommittedBytes < COMMITTED_STATE_FIXED_OVERHEAD ||
      maximumCommittedBytes > MAX_GROUP_STATE_STORE_COMMITTED_BYTES
    ) {
      throw new Error('invalid group-state store committed-byte limit');
    }
  }

  async load(
    key: GroupStateStoreKey,
  ): Promise<GroupStateStoreSnapshot | undefined> {
    const stableKey = validateAndCloneStoreKey(key);
    const encodedKey = encodeStoreKey(stableKey);
    await (this.tails.get(encodedKey) ?? Promise.resolve());
    const value = this.groups.get(encodedKey);
    return value === undefined ? undefined : snapshot(value);
  }

  transaction<T>(
    key: GroupStateStoreKey,
    operation: (transaction: GroupStateStoreTransaction) => T | Promise<T>,
  ): Promise<T> {
    const stableKey = validateAndCloneStoreKey(key);
    const encodedKey = encodeStoreKey(stableKey);
    const previous = this.tails.get(encodedKey) ?? Promise.resolve();
    const run = previous.then(async () => {
      const current = this.groups.get(encodedKey) ?? emptyState();
      const working = cloneMutableState(current);
      const transaction = new MemoryTransaction(
        stableKey,
        working,
        this.maximumCommittedBytes,
      );
      try {
        const result = await operation(transaction);
        validateMemoryTransactionBeforeCommit(transaction);
        const revision = nextStoreRevision(current.revision);
        if (revision === -1) {
          throw new Error('group-state store revision limit reached');
        }
        working.revision = revision;
        this.groups.set(encodedKey, cloneMutableState(working));
        return result;
      } finally {
        closeMemoryTransaction(transaction);
      }
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
  }
}

class MemoryTransaction implements GroupStateStoreTransaction {
  #active = true;
  #committedBytes: number;
  readonly #key: GroupStateStoreKey;
  readonly #working: MutableState;
  readonly #maximumCommittedBytes: number;
  readonly #baseRevision: number;
  readonly #baseEpoch: bigint | undefined;

  constructor(
    key: GroupStateStoreKey,
    working: MutableState,
    maximumCommittedBytes: number,
  ) {
    this.#key = key;
    this.#working = working;
    this.#maximumCommittedBytes = maximumCommittedBytes;
    this.#baseRevision = working.revision;
    this.#baseEpoch =
      working.encryptedState === undefined
        ? undefined
        : getEncryptedGroupStateValue(working.encryptedState).epoch;
    this.#committedBytes = committedStateBytes(working, maximumCommittedBytes);
  }

  static validateBeforeCommit(transaction: MemoryTransaction): void {
    transaction.#validateBeforeCommit();
  }

  static close(transaction: MemoryTransaction): void {
    transaction.#active = false;
  }

  get baseRevision(): number {
    this.#assertActive();
    return this.#baseRevision;
  }

  get encryptedState(): EncryptedGroupState | undefined {
    this.#assertActive();
    return this.#working.encryptedState === undefined
      ? undefined
      : cloneEncryptedState(this.#working.encryptedState);
  }

  get pendingKeyPackages(): ReadonlyArray<EncryptedKeyPackageState> {
    this.#assertActive();
    return Array.from(
      this.#working.pendingKeyPackages.values(),
      cloneEncryptedKeyPackageState,
    );
  }

  get pendingKeyPackageRequests(): ReadonlyArray<GroupStatePendingKeyPackageRequest> {
    this.#assertActive();
    return Array.from(
      this.#working.pendingKeyPackageRequests.values(),
      clonePendingKeyPackageRequest,
    );
  }

  get consumedKeyPackageRefs(): ReadonlyArray<Uint8Array> {
    this.#assertActive();
    return Array.from(
      this.#working.consumedKeyPackageRefs.values(),
      (reference) => cloneKeyPackageReference(reference),
    );
  }

  get outbox(): ReadonlyArray<GroupStateOutboxEntry> {
    this.#assertActive();
    return Array.from(this.#working.outbox.values(), cloneOutboxEntry);
  }

  get replay(): ReadonlyArray<GroupStateReplayEntry> {
    this.#assertActive();
    return Array.from(this.#working.replay.values(), cloneReplayEntry);
  }

  get forkEvidence(): GroupStateForkEvidence | undefined {
    this.#assertActive();
    return this.#working.forkEvidence === undefined
      ? undefined
      : cloneForkEvidence(this.#working.forkEvidence);
  }

  setEncryptedState(state: EncryptedGroupState): void {
    this.#assertActive();
    const snapshot = validateAndCloneEncryptedGroupState(state, this.#key);
    const publicState = getEncryptedGroupStateValue(snapshot);
    if (!sameProtocol(publicState.protocol, this.#key.protocol)) {
      throw new Error('encrypted state protocol does not match store key');
    }
    if (!equalBytes(publicState.groupId, this.#key.groupId)) {
      throw new Error('encrypted state groupId does not match store key');
    }
    const previousEpoch =
      this.#working.encryptedState === undefined
        ? undefined
        : getEncryptedGroupStateValue(this.#working.encryptedState).epoch;
    if (previousEpoch !== undefined && publicState.epoch < previousEpoch) {
      throw new Error('encrypted group-state rollback rejected');
    }
    this.#adjustCommittedBytes(
      encryptedStateCommittedBytes(snapshot) -
        (this.#working.encryptedState === undefined
          ? 0
          : encryptedStateCommittedBytes(this.#working.encryptedState)),
    );
    this.#working.encryptedState = snapshot;
  }

  getPendingKeyPackage(
    reference: Uint8Array,
  ): EncryptedKeyPackageState | undefined {
    this.#assertActive();
    const stableReference = cloneKeyPackageReference(reference);
    const state = this.#working.pendingKeyPackages.get(bytesToHex(stableReference));
    return state === undefined
      ? undefined
      : cloneEncryptedKeyPackageState(state);
  }

  putPendingKeyPackage(state: EncryptedKeyPackageState): boolean {
    this.#assertActive();
    const snapshot = validateAndCloneEncryptedKeyPackageState(state, this.#key);
    const reference = getEncryptedKeyPackageValue(snapshot).reference;
    const encodedReference = bytesToHex(reference);
    if (this.#working.consumedKeyPackageRefs.has(encodedReference)) {
      throw new Error('KeyPackage reference has already been consumed');
    }
    const existing = this.#working.pendingKeyPackages.get(encodedReference);
    if (existing !== undefined) {
      if (!sameEncryptedKeyPackageState(existing, snapshot)) {
        throw new Error(
          'KeyPackage reference already exists with different encrypted content',
        );
      }
      return false;
    }
    if (
      this.#working.pendingKeyPackages.size >= MAX_PENDING_KEY_PACKAGE_ENTRIES
    ) {
      throw new Error('pending KeyPackage entry limit reached');
    }
    const projectedBytes =
      pendingKeyPackageBytes(this.#working.pendingKeyPackages.values()) +
      encryptedKeyPackageSerializedLength(snapshot);
    if (projectedBytes > MAX_PENDING_KEY_PACKAGE_BYTES) {
      throw new Error('pending KeyPackage byte limit reached');
    }
    this.#adjustCommittedBytes(pendingEntryCommittedBytes(snapshot));
    this.#working.pendingKeyPackages = insertPendingPackage(
      this.#working.pendingKeyPackages,
      this.#working.consumedKeyPackageRefs,
      encodedReference,
      snapshot,
    );
    return true;
  }

  getPendingKeyPackageRequest(
    operationId: Uint8Array,
  ): GroupStatePendingKeyPackageRequest | undefined {
    this.#assertActive();
    const stableOperationId = cloneFixedId(
      operationId,
      'pending KeyPackage operationId',
    );
    const request = this.#working.pendingKeyPackageRequests.get(
      bytesToHex(stableOperationId),
    );
    return request === undefined
      ? undefined
      : clonePendingKeyPackageRequest(request);
  }

  bindPendingKeyPackageRequest(
    request: GroupStatePendingKeyPackageRequest,
  ): boolean {
    this.#assertActive();
    const stableRequest = validateAndClonePendingKeyPackageRequest(request);
    const encodedOperationId = bytesToHex(stableRequest.operationId);
    const encodedReference = bytesToHex(stableRequest.keyPackageReference);
    const existing =
      this.#working.pendingKeyPackageRequests.get(encodedOperationId);
    if (existing !== undefined) {
      if (!samePendingKeyPackageRequest(existing, stableRequest)) {
        throw new Error(
          'pending KeyPackage operationId has a different request binding',
        );
      }
      return false;
    }
    if (!this.#working.pendingKeyPackages.has(encodedReference)) {
      throw new Error(
        'pending KeyPackage request references missing encrypted state',
      );
    }
    for (const current of this.#working.pendingKeyPackageRequests.values()) {
      if (
        equalBytes(
          current.keyPackageReference,
          stableRequest.keyPackageReference,
        )
      ) {
        throw new Error(
          'pending KeyPackage reference belongs to another operationId',
        );
      }
    }
    if (
      this.#working.pendingKeyPackageRequests.size >=
      MAX_PENDING_KEY_PACKAGE_ENTRIES
    ) {
      throw new Error('pending KeyPackage request limit reached');
    }
    this.#adjustCommittedBytes(pendingRequestCommittedBytes(stableRequest));
    this.#working.pendingKeyPackageRequests.set(
      encodedOperationId,
      stableRequest,
    );
    return true;
  }

  hasConsumedKeyPackage(reference: Uint8Array): boolean {
    this.#assertActive();
    const stableReference = cloneKeyPackageReference(reference);
    return this.#working.consumedKeyPackageRefs.has(bytesToHex(stableReference));
  }

  consumePendingKeyPackage(reference: Uint8Array): EncryptedKeyPackageState {
    this.#assertActive();
    const stableReference = cloneKeyPackageReference(reference);
    const encodedReference = bytesToHex(stableReference);
    if (this.#working.consumedKeyPackageRefs.has(encodedReference)) {
      throw new Error('KeyPackage reference has already been consumed');
    }
    const pending = this.#working.pendingKeyPackages.get(encodedReference);
    if (pending === undefined) {
      throw new Error('KeyPackage reference is not pending');
    }
    if (
      this.#working.consumedKeyPackageRefs.size >=
      MAX_CONSUMED_KEY_PACKAGE_MARKERS
    ) {
      throw new Error('consumed KeyPackage marker limit reached');
    }
    this.#adjustCommittedBytes(
      byteLengthOf(stableReference) +
        2 -
        pendingEntryCommittedBytes(pending),
    );
    for (const [operationId, request] of this.#working
      .pendingKeyPackageRequests) {
      if (equalBytes(request.keyPackageReference, stableReference)) {
        this.#adjustCommittedBytes(-pendingRequestCommittedBytes(request));
        this.#working.pendingKeyPackageRequests.delete(operationId);
      }
    }
    const pendingPackages = removePendingPackage(
      this.#working.pendingKeyPackages,
      encodedReference,
    );
    const consumedReferences = insertConsumptionMarker(
      this.#working.consumedKeyPackageRefs,
      encodedReference,
      stableReference,
    );
    this.#working.pendingKeyPackages = pendingPackages;
    this.#working.consumedKeyPackageRefs = consumedReferences;
    return cloneEncryptedKeyPackageState(pending);
  }

  enqueueOutbox(entry: GroupStateOutboxEntry): boolean {
    this.#assertActive();
    const stableEntry = validateAndCloneOutboxEntry(entry);
    const id = bytesToHex(stableEntry.id);
    const existing = this.#working.outbox.get(id);
    if (existing !== undefined) {
      if (!sameOutboxEntry(existing, stableEntry)) {
        throw new Error('outbox id already exists with different content');
      }
      return false;
    }
    if (this.#working.outbox.size >= MAX_GROUP_STATE_METADATA_ENTRIES) {
      throw new Error('outbox entry limit reached');
    }
    this.#adjustCommittedBytes(outboxEntryCommittedBytes(stableEntry));
    this.#working.outbox.set(id, stableEntry);
    return true;
  }

  removeOutbox(id: Uint8Array): boolean {
    this.#assertActive();
    const stableId = cloneFixedId(id, 'outbox id');
    const encodedId = bytesToHex(stableId);
    const existing = this.#working.outbox.get(encodedId);
    if (existing === undefined) return false;
    this.#adjustCommittedBytes(-outboxEntryCommittedBytes(existing));
    this.#working.outbox.delete(encodedId);
    return true;
  }

  hasReplayRecord(recordId: Uint8Array): boolean {
    this.#assertActive();
    const stableRecordId = cloneFixedId(recordId, 'replay recordId');
    return this.#working.replay.has(bytesToHex(stableRecordId));
  }

  markReplay(entry: GroupStateReplayEntry): boolean {
    this.#assertActive();
    const stableEntry = validateAndCloneReplayEntry(entry);
    const recordId = bytesToHex(stableEntry.recordId);
    const existing = this.#working.replay.get(recordId);
    if (existing !== undefined) {
      if (!sameReplayEntry(existing, stableEntry)) {
        throw new Error('replay recordId has different metadata');
      }
      return false;
    }
    if (this.#working.replay.size >= MAX_GROUP_STATE_METADATA_ENTRIES) {
      throw new Error('replay entry limit reached');
    }
    let operationId: string | undefined;
    if (stableEntry.operationId !== undefined) {
      operationId = bytesToHex(stableEntry.operationId);
      const priorRecord = this.#working.operationToRecord.get(operationId);
      if (priorRecord !== undefined && priorRecord !== recordId) {
        throw new Error('operationId belongs to a different replay recordId');
      }
    }
    this.#adjustCommittedBytes(replayEntryCommittedBytes(stableEntry));
    if (operationId !== undefined) {
      this.#working.operationToRecord = bindOperationToRecord(
        this.#working.operationToRecord,
        operationId,
        recordId,
      );
    }
    this.#working.replay.set(recordId, stableEntry);
    return true;
  }

  removeReplay(recordId: Uint8Array): boolean {
    this.#assertActive();
    const stableRecordId = cloneFixedId(recordId, 'replay recordId');
    const recordHex = bytesToHex(stableRecordId);
    const existing = this.#working.replay.get(recordHex);
    if (existing === undefined) return false;
    this.#adjustCommittedBytes(-replayEntryCommittedBytes(existing));
    this.#working.replay.delete(recordHex);
    if (existing.operationId !== undefined) {
      const operationHex = bytesToHex(existing.operationId);
      if (this.#working.operationToRecord.get(operationHex) === recordHex) {
        this.#working.operationToRecord.delete(operationHex);
      }
    }
    return true;
  }

  markFork(evidence: GroupStateForkEvidence): boolean {
    this.#assertActive();
    const normalized = normalizeForkEvidence(evidence);
    if (this.#working.forkEvidence !== undefined) {
      if (!sameForkEvidence(this.#working.forkEvidence, normalized)) {
        throw new Error('group already has different fork evidence');
      }
      return false;
    }
    this.#adjustCommittedBytes(forkEvidenceCommittedBytes(normalized));
    this.#working.forkEvidence = normalized;
    return true;
  }

  #validateBeforeCommit(): void {
    this.#assertActive();
    const finalEpoch =
      this.#working.encryptedState === undefined
        ? undefined
        : getEncryptedGroupStateValue(this.#working.encryptedState).epoch;
    const baseline = classifyStoreCommitBaseline(
      this.#baseRevision,
      this.#working.revision,
      this.#baseEpoch !== undefined,
      finalEpoch !== undefined,
      this.#baseEpoch ?? 0n,
      finalEpoch ?? 0n,
    );
    if (baseline === 'revision')
      throw new Error('group-state transaction baseline revision changed');
    if (baseline === 'rollback') {
      throw new Error('encrypted group-state rollback rejected at commit');
    }
    const recomputedCommittedBytes = committedStateBytes(
      this.#working,
      this.#maximumCommittedBytes,
    );
    if (recomputedCommittedBytes !== this.#committedBytes) {
      throw new Error('group-state store committed-byte accounting mismatch');
    }
    if (
      this.#working.consumedKeyPackageRefs.size >
      MAX_CONSUMED_KEY_PACKAGE_MARKERS
    ) {
      throw new Error('consumed KeyPackage marker limit exceeded');
    }
    if (
      this.#working.outbox.size > MAX_GROUP_STATE_METADATA_ENTRIES ||
      this.#working.replay.size > MAX_GROUP_STATE_METADATA_ENTRIES
    ) {
      throw new Error('group-state metadata entry limit exceeded');
    }
    if (
      this.#working.pendingKeyPackages.size > MAX_PENDING_KEY_PACKAGE_ENTRIES ||
      this.#working.pendingKeyPackageRequests.size >
        MAX_PENDING_KEY_PACKAGE_ENTRIES ||
      pendingKeyPackageBytes(this.#working.pendingKeyPackages.values()) >
        MAX_PENDING_KEY_PACKAGE_BYTES
    ) {
      throw new Error('pending KeyPackage retention limit exceeded');
    }
    for (const [encodedReference, state] of this.#working.pendingKeyPackages) {
      const validated = validateAndCloneEncryptedKeyPackageState(
        state,
        this.#key,
      );
      if (
        bytesToHex(getEncryptedKeyPackageValue(validated).reference) !==
        encodedReference
      ) {
        throw new Error('pending KeyPackage map key does not match reference');
      }
    }
    for (const [encodedOperationId, request] of this.#working
      .pendingKeyPackageRequests) {
      const validated = validateAndClonePendingKeyPackageRequest(request);
      if (bytesToHex(validated.operationId) !== encodedOperationId) {
        throw new Error(
          'pending KeyPackage request map key does not match operationId',
        );
      }
    }
    for (const [encodedReference, reference] of this.#working
      .consumedKeyPackageRefs) {
      cloneKeyPackageReference(reference);
      if (bytesToHex(reference) !== encodedReference) {
        throw new Error('consumed KeyPackage map key does not match reference');
      }
    }
    validateGroupStateStoreSnapshotSemantics(
      snapshot(this.#working),
      this.#key,
    );
  }

  #assertActive(): void {
    if (!this.#active) {
      throw new Error('group-state transaction is no longer active');
    }
  }

  #adjustCommittedBytes(delta: number): void {
    const next = adjustStoreBytes(
      this.#committedBytes,
      delta,
      COMMITTED_STATE_FIXED_OVERHEAD,
      this.#maximumCommittedBytes,
    );
    if (!Number.isSafeInteger(next) || next === -1) {
      throw new Error('group-state store committed-byte limit reached');
    }
    this.#committedBytes = next;
  }
}

const validateMemoryTransactionBeforeCommit =
  MemoryTransaction.validateBeforeCommit;
const closeMemoryTransaction = MemoryTransaction.close;

function emptyState(): MutableState {
  return {
    revision: 0,
    pendingKeyPackages: new Map(),
    pendingKeyPackageRequests: new Map(),
    consumedKeyPackageRefs: new Map(),
    outbox: new Map(),
    replay: new Map(),
    operationToRecord: new Map(),
  };
}

function cloneMutableState(state: MutableState): MutableState {
  return {
    revision: state.revision,
    encryptedState:
      state.encryptedState === undefined
        ? undefined
        : cloneEncryptedState(state.encryptedState),
    pendingKeyPackages: new Map(
      Array.from(state.pendingKeyPackages, ([reference, keyPackageState]) => [
        reference,
        cloneEncryptedKeyPackageState(keyPackageState),
      ]),
    ),
    pendingKeyPackageRequests: new Map(
      Array.from(state.pendingKeyPackageRequests, ([operationId, request]) => [
        operationId,
        clonePendingKeyPackageRequest(request),
      ]),
    ),
    consumedKeyPackageRefs: new Map(
      Array.from(state.consumedKeyPackageRefs, ([encoded, reference]) => [
        encoded,
        copyUnsharedUint8Array(
          reference,
          1,
          MAX_KEY_PACKAGE_REFERENCE_BYTES,
          'consumed KeyPackage reference',
        ),
      ]),
    ),
    outbox: new Map(
      Array.from(state.outbox, ([id, entry]) => [id, cloneOutboxEntry(entry)]),
    ),
    replay: new Map(
      Array.from(state.replay, ([id, entry]) => [id, cloneReplayEntry(entry)]),
    ),
    operationToRecord: new Map(state.operationToRecord),
    forkEvidence:
      state.forkEvidence === undefined
        ? undefined
        : cloneForkEvidence(state.forkEvidence),
  };
}

function snapshot(state: MutableState): GroupStateStoreSnapshot {
  return {
    revision: state.revision,
    encryptedState:
      state.encryptedState === undefined
        ? undefined
        : cloneEncryptedState(state.encryptedState),
    pendingKeyPackages: Array.from(
      state.pendingKeyPackages.values(),
      cloneEncryptedKeyPackageState,
    ),
    pendingKeyPackageRequests: Array.from(
      state.pendingKeyPackageRequests.values(),
      clonePendingKeyPackageRequest,
    ),
    consumedKeyPackageRefs: Array.from(
      state.consumedKeyPackageRefs.values(),
      (reference) =>
        copyUnsharedUint8Array(
          reference,
          1,
          MAX_KEY_PACKAGE_REFERENCE_BYTES,
          'consumed KeyPackage reference',
        ),
    ),
    outbox: Array.from(state.outbox.values(), cloneOutboxEntry),
    replay: Array.from(state.replay.values(), cloneReplayEntry),
    forkEvidence:
      state.forkEvidence === undefined
        ? undefined
        : cloneForkEvidence(state.forkEvidence),
  };
}

/** @internal Shared semantic validation for stores and snapshot commitments. */
export function validateGroupStateStoreSnapshotSemantics(
  snapshotValue: GroupStateStoreSnapshot,
  keyValue: GroupStateStoreKey,
): void {
  const key = validateAndCloneStoreKey(keyValue);
  const encryptedState =
    snapshotValue.encryptedState === undefined
      ? undefined
      : validateAndCloneEncryptedGroupState(snapshotValue.encryptedState, key);
  const epoch =
    encryptedState === undefined
      ? undefined
      : getEncryptedGroupStateValue(encryptedState).epoch;

  if (
    snapshotValue.pendingKeyPackages.length > MAX_PENDING_KEY_PACKAGE_ENTRIES ||
    snapshotValue.pendingKeyPackageRequests.length >
      MAX_PENDING_KEY_PACKAGE_ENTRIES ||
    snapshotValue.consumedKeyPackageRefs.length >
      MAX_CONSUMED_KEY_PACKAGE_MARKERS ||
    snapshotValue.outbox.length > MAX_GROUP_STATE_METADATA_ENTRIES ||
    snapshotValue.replay.length > MAX_GROUP_STATE_METADATA_ENTRIES
  ) {
    throw new Error('group-state snapshot entry limit exceeded');
  }

  const pendingReferences = new Set<string>();
  for (const pending of snapshotValue.pendingKeyPackages) {
    const validated = validateAndCloneEncryptedKeyPackageState(pending, key);
    const encodedReference = bytesToHex(
      getEncryptedKeyPackageValue(validated).reference,
    );
    if (pendingReferences.has(encodedReference)) {
      throw new Error('pending KeyPackage reference is duplicated');
    }
    pendingReferences.add(encodedReference);
  }

  const pendingOperationIds = new Set<string>();
  const requestedReferences = new Set<string>();
  for (const requestValue of snapshotValue.pendingKeyPackageRequests) {
    const request = validateAndClonePendingKeyPackageRequest(requestValue);
    const encodedOperationId = bytesToHex(request.operationId);
    if (pendingOperationIds.has(encodedOperationId)) {
      throw new Error('pending KeyPackage request operationId is duplicated');
    }
    pendingOperationIds.add(encodedOperationId);
    const encodedReference = bytesToHex(request.keyPackageReference);
    if (!pendingReferences.has(encodedReference)) {
      throw new Error('pending KeyPackage request references missing state');
    }
    if (requestedReferences.has(encodedReference)) {
      throw new Error(
        'pending KeyPackage reference has multiple operation bindings',
      );
    }
    requestedReferences.add(encodedReference);
  }
  if (
    requestedReferences.size !== pendingReferences.size ||
    [...pendingReferences].some(
      (encodedReference) => !requestedReferences.has(encodedReference),
    )
  ) {
    throw new Error(
      'every pending KeyPackage must have exactly one request binding ' +
        `(pending=${pendingReferences.size}, bound=${requestedReferences.size})`,
    );
  }

  const consumedReferences = new Set<string>();
  for (const referenceValue of snapshotValue.consumedKeyPackageRefs) {
    const encodedReference = bytesToHex(cloneKeyPackageReference(referenceValue));
    if (consumedReferences.has(encodedReference)) {
      throw new Error('consumed KeyPackage reference is duplicated');
    }
    if (pendingReferences.has(encodedReference)) {
      throw new Error('KeyPackage cannot be both pending and consumed');
    }
    consumedReferences.add(encodedReference);
  }

  const outboxIds = new Set<string>();
  for (const entryValue of snapshotValue.outbox) {
    const entry = validateAndCloneOutboxEntry(entryValue);
    const encodedId = bytesToHex(entry.id);
    if (outboxIds.has(encodedId)) {
      throw new Error('outbox id is duplicated');
    }
    outboxIds.add(encodedId);
    if (epoch !== undefined && entry.epoch > epoch) {
      throw new Error('outbox epoch is newer than encrypted state');
    }
  }

  const replayIds = new Set<string>();
  const replayOperationIds = new Set<string>();
  for (const entryValue of snapshotValue.replay) {
    const entry = validateAndCloneReplayEntry(entryValue);
    const encodedId = bytesToHex(entry.recordId);
    if (replayIds.has(encodedId)) {
      throw new Error('replay recordId is duplicated');
    }
    replayIds.add(encodedId);
    if (entry.operationId !== undefined) {
      const encodedOperationId = bytesToHex(entry.operationId);
      if (replayOperationIds.has(encodedOperationId)) {
        throw new Error('replay operationId is duplicated');
      }
      replayOperationIds.add(encodedOperationId);
    }
    if (epoch !== undefined && entry.epoch > epoch) {
      throw new Error('replay epoch is newer than encrypted state');
    }
  }

  const forkEvidence =
    snapshotValue.forkEvidence === undefined
      ? undefined
      : validateAndCloneForkEvidence(snapshotValue.forkEvidence);
  if (epoch === undefined) {
    if (
      consumedReferences.size > 0 ||
      outboxIds.size > 0 ||
      replayIds.size > 0 ||
      forkEvidence !== undefined
    ) {
      throw new Error(
        'consumed/replay metadata cannot commit without encrypted group state',
      );
    }
  } else if (forkEvidence !== undefined && forkEvidence.epoch > epoch) {
    throw new Error('fork evidence is newer than encrypted state');
  }
}

function cloneEncryptedState(state: EncryptedGroupState): EncryptedGroupState {
  const bytes = serializedEncryptedGroupState(state);
  const snapshot = deserializeEncryptedGroupState.call(
    EncryptedGroupState,
    bytes,
  );
  clonedEnvelopeLengths.set(snapshot, byteLengthOf(bytes));
  return snapshot;
}

function cloneEncryptedKeyPackageState(
  state: EncryptedKeyPackageState,
): EncryptedKeyPackageState {
  const bytes = serializedEncryptedKeyPackageState(state);
  const snapshot = deserializeEncryptedKeyPackageState.call(
    EncryptedKeyPackageState,
    bytes,
  );
  clonedEnvelopeLengths.set(snapshot, byteLengthOf(bytes));
  return snapshot;
}

function validateAndCloneEncryptedGroupState(
  state: EncryptedGroupState,
  key: GroupStateStoreKey,
): EncryptedGroupState {
  if (!isEncryptedGroupState(state)) {
    throw new Error(
      'group-state store accepts only EncryptedGroupState; plaintext private state is forbidden',
    );
  }
  const snapshot = cloneEncryptedState(state);
  const publicState = getEncryptedGroupStateValue(snapshot);
  if (!sameProtocol(publicState.protocol, key.protocol)) {
    throw new Error('encrypted state protocol does not match store key');
  }
  if (!equalBytes(publicState.groupId, key.groupId)) {
    throw new Error('encrypted state groupId does not match store key');
  }
  return snapshot;
}

function validateAndCloneEncryptedKeyPackageState(
  state: EncryptedKeyPackageState,
  key: GroupStateStoreKey,
): EncryptedKeyPackageState {
  if (!isEncryptedKeyPackageState(state)) {
    throw new Error(
      'group-state store accepts only EncryptedKeyPackageState; plaintext private KeyPackage state is forbidden',
    );
  }
  const snapshot = cloneEncryptedKeyPackageState(state);
  const keyPackage = getEncryptedKeyPackageValue(snapshot);
  if (!sameProtocol(keyPackage.protocol, key.protocol)) {
    throw new Error('encrypted KeyPackage protocol does not match store key');
  }
  cloneKeyPackageReference(keyPackage.reference);
  if (!equalBytes(keyPackage.groupId, key.groupId)) {
    throw new Error('encrypted KeyPackage groupId does not match store key');
  }
  return snapshot;
}

function sameEncryptedKeyPackageState(
  first: EncryptedKeyPackageState,
  second: EncryptedKeyPackageState,
): boolean {
  return equalBytes(
    serializedEncryptedKeyPackageState(first),
    serializedEncryptedKeyPackageState(second),
  );
}

function pendingKeyPackageBytes(
  states: Iterable<EncryptedKeyPackageState>,
): number {
  let total = 0;
  for (const state of states) {
    total += encryptedKeyPackageSerializedLength(state);
    if (total > MAX_PENDING_KEY_PACKAGE_BYTES) return total;
  }
  return total;
}

function serializedEncryptedGroupState(state: EncryptedGroupState): Uint8Array {
  if (!isEncryptedGroupState(state)) {
    throw new Error(
      'group-state store accepts only EncryptedGroupState; plaintext private state is forbidden',
    );
  }
  return copyUnsharedUint8Array(
    serializeEncryptedGroupState.call(state),
    1,
    MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
    'serialized encrypted group state',
  );
}

function serializedEncryptedKeyPackageState(
  state: EncryptedKeyPackageState,
): Uint8Array {
  if (!isEncryptedKeyPackageState(state)) {
    throw new Error(
      'group-state store accepts only EncryptedKeyPackageState; plaintext private KeyPackage state is forbidden',
    );
  }
  return copyUnsharedUint8Array(
    serializeEncryptedKeyPackageState.call(state),
    1,
    MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
    'serialized encrypted KeyPackage state',
  );
}

function getEncryptedGroupStateValue(
  state: EncryptedGroupState,
): GroupSecurityPublicState {
  return encryptedGroupStateValue.call(state) as GroupSecurityPublicState;
}

function getEncryptedKeyPackageValue(
  state: EncryptedKeyPackageState,
): GroupKeyPackage {
  return encryptedKeyPackageValue.call(state) as GroupKeyPackage;
}

/** @internal Strictly detach one canonical store key. */
export function cloneGroupStateStoreKey(
  key: GroupStateStoreKey,
): GroupStateStoreKey {
  const record = snapshotPlainDataObject(
    key,
    ['protocol', 'groupId'],
    'store key',
    ['protocol', 'groupId'],
  );
  const protocol = snapshotCanonicalProtocol(
    ownDataProperty(record, 'protocol'),
    'protocol',
  );
  const groupId = copyUnsharedUint8Array(
    ownDataProperty(record, 'groupId'),
    1,
    1024,
    'groupId',
  );
  return {
    protocol,
    groupId,
  };
}

const validateAndCloneStoreKey = cloneGroupStateStoreKey;

function cloneOutboxEntry(entry: GroupStateOutboxEntry): GroupStateOutboxEntry {
  return validateAndCloneOutboxEntry(entry);
}

function cloneReplayEntry(entry: GroupStateReplayEntry): GroupStateReplayEntry {
  return validateAndCloneReplayEntry(entry);
}

function clonePendingKeyPackageRequest(
  request: GroupStatePendingKeyPackageRequest,
): GroupStatePendingKeyPackageRequest {
  return validateAndClonePendingKeyPackageRequest(request);
}

function cloneForkEvidence(
  evidence: GroupStateForkEvidence,
): GroupStateForkEvidence {
  return validateAndCloneForkEvidence(evidence);
}

function validateAndCloneOutboxEntry(
  value: GroupStateOutboxEntry,
): GroupStateOutboxEntry {
  const entry = snapshotPlainDataObject(
    value,
    ['id', 'kind', 'epoch', 'payload', 'createdAt'],
    'outbox entry',
    ['id', 'kind', 'epoch', 'payload', 'createdAt'],
  );
  const kind = ownDataProperty(entry, 'kind');
  const epoch = ownDataProperty(entry, 'epoch');
  const createdAt = ownDataProperty(entry, 'createdAt');
  if (!isCanonicalIdentifier(kind)) {
    throw new Error('invalid outbox kind');
  }
  requireU64(epoch, 'outbox epoch');
  if (!Number.isSafeInteger(createdAt) || (createdAt as number) < 0) {
    throw new Error('outbox createdAt must be a non-negative safe integer');
  }
  return {
    id: cloneFixedId(ownDataProperty(entry, 'id'), 'outbox id'),
    kind,
    epoch: epoch as bigint,
    payload: copyUnsharedUint8Array(
      ownDataProperty(entry, 'payload'),
      1,
      MAX_OUTBOX_PAYLOAD_BYTES,
      'outbox payload',
    ),
    createdAt: createdAt as number,
  };
}

function validateAndCloneReplayEntry(
  value: GroupStateReplayEntry,
): GroupStateReplayEntry {
  const entry = snapshotPlainDataObject(
    value,
    ['recordId', 'operationId', 'epoch', 'controlRecord'],
    'replay entry',
    ['recordId', 'epoch', 'controlRecord'],
  );
  const operationId = optionalOwnDataProperty(entry, 'operationId');
  const epoch = ownDataProperty(entry, 'epoch');
  requireU64(epoch, 'replay epoch');
  return {
    recordId: cloneFixedId(ownDataProperty(entry, 'recordId'), 'replay recordId'),
    operationId:
      operationId === undefined
        ? undefined
        : cloneFixedId(operationId, 'replay operationId'),
    epoch: epoch as bigint,
    controlRecord: copyUnsharedUint8Array(
      ownDataProperty(entry, 'controlRecord'),
      1,
      MAX_CONTROL_RECORD_BYTES,
      'replay controlRecord',
    ),
  };
}

function validateAndClonePendingKeyPackageRequest(
  value: GroupStatePendingKeyPackageRequest,
): GroupStatePendingKeyPackageRequest {
  const request = snapshotPlainDataObject(
    value,
    ['operationId', 'requestCommitment', 'keyPackageReference'],
    'pending KeyPackage request',
    ['operationId', 'requestCommitment', 'keyPackageReference'],
  );
  return {
    operationId: cloneFixedId(
      ownDataProperty(request, 'operationId'),
      'pending KeyPackage operationId',
    ),
    requestCommitment: cloneFixedId(
      ownDataProperty(request, 'requestCommitment'),
      'pending KeyPackage request commitment',
    ),
    keyPackageReference: cloneKeyPackageReference(
      ownDataProperty(request, 'keyPackageReference') as Uint8Array,
    ),
  };
}

function samePendingKeyPackageRequest(
  first: GroupStatePendingKeyPackageRequest,
  second: GroupStatePendingKeyPackageRequest,
): boolean {
  return (
    equalBytes(first.operationId, second.operationId) &&
    equalBytes(first.requestCommitment, second.requestCommitment) &&
    equalBytes(first.keyPackageReference, second.keyPackageReference)
  );
}

function validateAndCloneForkEvidence(
  value: GroupStateForkEvidence,
): GroupStateForkEvidence {
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
    [
      'epoch',
      'parentRecordId',
      'firstRecordId',
      'firstControlRecord',
      'secondRecordId',
      'secondControlRecord',
    ],
  );
  const epoch = ownDataProperty(evidence, 'epoch');
  requireU64(epoch, 'fork epoch');
  const cloned: GroupStateForkEvidence = {
    epoch: epoch as bigint,
    parentRecordId: cloneFixedId(
      ownDataProperty(evidence, 'parentRecordId'),
      'fork parentRecordId',
    ),
    firstRecordId: cloneFixedId(
      ownDataProperty(evidence, 'firstRecordId'),
      'fork firstRecordId',
    ),
    firstControlRecord: copyUnsharedUint8Array(
      ownDataProperty(evidence, 'firstControlRecord'),
      1,
      MAX_CONTROL_RECORD_BYTES,
      'fork firstControlRecord',
    ),
    secondRecordId: cloneFixedId(
      ownDataProperty(evidence, 'secondRecordId'),
      'fork secondRecordId',
    ),
    secondControlRecord: copyUnsharedUint8Array(
      ownDataProperty(evidence, 'secondControlRecord'),
      1,
      MAX_CONTROL_RECORD_BYTES,
      'fork secondControlRecord',
    ),
  };
  if (equalBytes(cloned.firstRecordId, cloned.secondRecordId)) {
    throw new Error('fork record IDs must differ');
  }
  return cloned;
}

function normalizeForkEvidence(
  evidence: GroupStateForkEvidence,
): GroupStateForkEvidence {
  const cloned = validateAndCloneForkEvidence(evidence);
  const firstComesFirst =
    compareBytes(cloned.firstRecordId, cloned.secondRecordId) < 0;
  return firstComesFirst
    ? cloned
    : {
        epoch: cloned.epoch,
        parentRecordId: cloned.parentRecordId,
        firstRecordId: cloned.secondRecordId,
        firstControlRecord: cloned.secondControlRecord,
        secondRecordId: cloned.firstRecordId,
        secondControlRecord: cloned.firstControlRecord,
      };
}

function sameForkEvidence(
  first: GroupStateForkEvidence,
  second: GroupStateForkEvidence,
): boolean {
  const a = normalizeForkEvidence(first);
  const b = normalizeForkEvidence(second);
  return (
    a.epoch === b.epoch &&
    equalBytes(a.parentRecordId, b.parentRecordId) &&
    equalBytes(a.firstRecordId, b.firstRecordId) &&
    equalBytes(a.firstControlRecord, b.firstControlRecord) &&
    equalBytes(a.secondRecordId, b.secondRecordId) &&
    equalBytes(a.secondControlRecord, b.secondControlRecord)
  );
}

function committedStateBytes(state: MutableState, maximum: number): number {
  let total = COMMITTED_STATE_FIXED_OVERHEAD;
  if (state.encryptedState !== undefined) {
    total = addCommittedBytes(
      total,
      encryptedStateCommittedBytes(state.encryptedState),
      maximum,
    );
  }
  for (const pending of state.pendingKeyPackages.values()) {
    total = addCommittedBytes(
      total,
      pendingEntryCommittedBytes(pending),
      maximum,
    );
  }
  for (const request of state.pendingKeyPackageRequests.values()) {
    total = addCommittedBytes(
      total,
      pendingRequestCommittedBytes(request),
      maximum,
    );
  }
  for (const reference of state.consumedKeyPackageRefs.values()) {
    total = addCommittedBytes(
      total,
      byteLengthOf(reference) + 2,
      maximum,
    );
  }
  for (const entry of state.outbox.values()) {
    total = addCommittedBytes(total, outboxEntryCommittedBytes(entry), maximum);
  }
  for (const entry of state.replay.values()) {
    total = addCommittedBytes(total, replayEntryCommittedBytes(entry), maximum);
  }
  if (state.forkEvidence !== undefined) {
    total = addCommittedBytes(
      total,
      forkEvidenceCommittedBytes(state.forkEvidence),
      maximum,
    );
  }
  return total;
}

function addCommittedBytes(
  total: number,
  addition: number,
  maximum: number,
): number {
  const next = adjustStoreBytes(total, addition, 0, maximum);
  if (!Number.isSafeInteger(next) || next === -1) {
    throw new Error('group-state store committed-byte limit reached');
  }
  return next;
}

function encryptedStateCommittedBytes(state: EncryptedGroupState): number {
  return (
    (clonedEnvelopeLengths.get(state) ??
      byteLengthOf(serializedEncryptedGroupState(state))) + 4
  );
}

function encryptedKeyPackageSerializedLength(
  state: EncryptedKeyPackageState,
): number {
  return (
    clonedEnvelopeLengths.get(state) ??
    byteLengthOf(serializedEncryptedKeyPackageState(state))
  );
}

function pendingEntryCommittedBytes(state: EncryptedKeyPackageState): number {
  const reference = getEncryptedKeyPackageValue(state).reference;
  return (
    encryptedKeyPackageSerializedLength(state) +
    byteLengthOf(reference) +
    6
  );
}

function pendingRequestCommittedBytes(
  request: GroupStatePendingKeyPackageRequest,
): number {
  return (
    2 * GROUP_STATE_STORE_ID_LENGTH +
    2 +
    byteLengthOf(request.keyPackageReference)
  );
}

function outboxEntryCommittedBytes(entry: GroupStateOutboxEntry): number {
  return (
    GROUP_STATE_STORE_ID_LENGTH +
    2 +
    entry.kind.length +
    8 +
    8 +
    4 +
    byteLengthOf(entry.payload)
  );
}

function replayEntryCommittedBytes(entry: GroupStateReplayEntry): number {
  return (
    GROUP_STATE_STORE_ID_LENGTH +
    1 +
    (entry.operationId === undefined
      ? 0
      : 4 + byteLengthOf(entry.operationId)) +
    8 +
    4 +
    byteLengthOf(entry.controlRecord)
  );
}

function forkEvidenceCommittedBytes(evidence: GroupStateForkEvidence): number {
  return (
    1 +
    4 +
    8 +
    3 * GROUP_STATE_STORE_ID_LENGTH +
    4 +
    byteLengthOf(evidence.firstControlRecord) +
    4 +
    byteLengthOf(evidence.secondControlRecord)
  );
}

function cloneFixedId(value: unknown, field: string): Uint8Array {
  return copyUnsharedUint8Array(
    value,
    GROUP_STATE_STORE_ID_LENGTH,
    GROUP_STATE_STORE_ID_LENGTH,
    field,
  );
}

function cloneKeyPackageReference(reference: unknown): Uint8Array {
  return copyUnsharedUint8Array(
    reference,
    1,
    MAX_KEY_PACKAGE_REFERENCE_BYTES,
    'KeyPackage reference',
  );
}

function sameOutboxEntry(
  a: GroupStateOutboxEntry,
  b: GroupStateOutboxEntry,
): boolean {
  return (
    a.kind === b.kind &&
    a.epoch === b.epoch &&
    a.createdAt === b.createdAt &&
    equalBytes(a.id, b.id) &&
    equalBytes(a.payload, b.payload)
  );
}

function sameReplayEntry(
  a: GroupStateReplayEntry,
  b: GroupStateReplayEntry,
): boolean {
  return (
    a.epoch === b.epoch &&
    equalBytes(a.recordId, b.recordId) &&
    optionalEqualBytes(a.operationId, b.operationId) &&
    equalBytes(a.controlRecord, b.controlRecord)
  );
}

function encodeStoreKey(key: GroupStateStoreKey): string {
  return `${key.protocol.id}:${key.protocol.version}:${bytesToHex(key.groupId)}`;
}
