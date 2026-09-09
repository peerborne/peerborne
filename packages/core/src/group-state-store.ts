import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
  GroupKeyPackage,
  GroupSecurityProtocol,
  GroupSecurityPublicState,
  isEncryptedGroupState,
  isEncryptedKeyPackageState,
} from './group-security-provider.js';

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
const MAX_U64 = (1n << 64n) - 1n;
const COMMITTED_STATE_FIXED_OVERHEAD = 1024;

const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)!.get!;
const typedArrayBuffer = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)!.get!;
const typedArrayTag = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)!.get!;
const uint8ArraySet = Uint8Array.prototype.set;
const arrayJoin = Array.prototype.join;
const HEX_BYTE_LOOKUP = Object.freeze(
  Array.from({ length: 256 }, (_, value) =>
    value.toString(16).padStart(2, '0'),
  ),
);
const sharedArrayBufferByteLength =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )!.get!;
const serializeEncryptedGroupState = EncryptedGroupState.prototype.serialize;
const deserializeEncryptedGroupState = EncryptedGroupState.deserialize;
const encryptedGroupStateValue = Object.getOwnPropertyDescriptor(
  EncryptedGroupState.prototype,
  'state',
)!.get!;
const serializeEncryptedKeyPackageState =
  EncryptedKeyPackageState.prototype.serialize;
const deserializeEncryptedKeyPackageState =
  EncryptedKeyPackageState.deserialize;
const encryptedKeyPackageValue = Object.getOwnPropertyDescriptor(
  EncryptedKeyPackageState.prototype,
  'keyPackage',
)!.get!;

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
    operation: (
      transaction: GroupStateStoreTransaction,
    ) => T | Promise<T>,
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
    private readonly maximumCommittedBytes =
      MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
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
    operation: (
      transaction: GroupStateStoreTransaction,
    ) => T | Promise<T>,
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
        transaction.validateBeforeCommit();
        if (current.revision === Number.MAX_SAFE_INTEGER) {
          throw new Error('group-state store revision limit reached');
        }
        working.revision = current.revision + 1;
        this.groups.set(encodedKey, cloneMutableState(working));
        return result;
      } finally {
        transaction.close();
      }
    });
    this.tails.set(
      encodedKey,
      run.then(
        () => undefined,
        () => undefined,
      ),
    );
    return run;
  }
}

class MemoryTransaction implements GroupStateStoreTransaction {
  private active = true;
  private committedBytes: number;

  constructor(
    private readonly key: GroupStateStoreKey,
    private readonly working: MutableState,
    private readonly maximumCommittedBytes: number,
  ) {
    this.committedBytes = committedStateBytes(
      working,
      maximumCommittedBytes,
    );
  }

  get baseRevision(): number {
    this.assertActive();
    return this.working.revision;
  }

  get encryptedState(): EncryptedGroupState | undefined {
    this.assertActive();
    return this.working.encryptedState === undefined
      ? undefined
      : cloneEncryptedState(this.working.encryptedState);
  }

  get pendingKeyPackages(): ReadonlyArray<EncryptedKeyPackageState> {
    this.assertActive();
    return Array.from(
      this.working.pendingKeyPackages.values(),
      cloneEncryptedKeyPackageState,
    );
  }

  get pendingKeyPackageRequests(): ReadonlyArray<GroupStatePendingKeyPackageRequest> {
    this.assertActive();
    return Array.from(
      this.working.pendingKeyPackageRequests.values(),
      clonePendingKeyPackageRequest,
    );
  }

  get consumedKeyPackageRefs(): ReadonlyArray<Uint8Array> {
    this.assertActive();
    return Array.from(
      this.working.consumedKeyPackageRefs.values(),
      (reference) => cloneKeyPackageReference(reference),
    );
  }

  get outbox(): ReadonlyArray<GroupStateOutboxEntry> {
    this.assertActive();
    return Array.from(this.working.outbox.values(), cloneOutboxEntry);
  }

  get replay(): ReadonlyArray<GroupStateReplayEntry> {
    this.assertActive();
    return Array.from(this.working.replay.values(), cloneReplayEntry);
  }

  get forkEvidence(): GroupStateForkEvidence | undefined {
    this.assertActive();
    return this.working.forkEvidence === undefined
      ? undefined
      : cloneForkEvidence(this.working.forkEvidence);
  }

  setEncryptedState(state: EncryptedGroupState): void {
    this.assertActive();
    const snapshot = validateAndCloneEncryptedGroupState(state, this.key);
    const publicState = getEncryptedGroupStateValue(snapshot);
    if (!sameProtocol(publicState.protocol, this.key.protocol)) {
      throw new Error('encrypted state protocol does not match store key');
    }
    if (!equalBytes(publicState.groupId, this.key.groupId)) {
      throw new Error('encrypted state groupId does not match store key');
    }
    const previousEpoch =
      this.working.encryptedState === undefined
        ? undefined
        : getEncryptedGroupStateValue(this.working.encryptedState).epoch;
    if (previousEpoch !== undefined && publicState.epoch < previousEpoch) {
      throw new Error('encrypted group-state rollback rejected');
    }
    this.adjustCommittedBytes(
      encryptedStateCommittedBytes(snapshot) -
        (this.working.encryptedState === undefined
          ? 0
          : encryptedStateCommittedBytes(this.working.encryptedState)),
    );
    this.working.encryptedState = snapshot;
  }

  getPendingKeyPackage(
    reference: Uint8Array,
  ): EncryptedKeyPackageState | undefined {
    this.assertActive();
    const stableReference = cloneKeyPackageReference(reference);
    const state = this.working.pendingKeyPackages.get(toHex(stableReference));
    return state === undefined
      ? undefined
      : cloneEncryptedKeyPackageState(state);
  }

  putPendingKeyPackage(state: EncryptedKeyPackageState): boolean {
    this.assertActive();
    const snapshot = validateAndCloneEncryptedKeyPackageState(state, this.key);
    const reference = getEncryptedKeyPackageValue(snapshot).reference;
    const encodedReference = toHex(reference);
    if (this.working.consumedKeyPackageRefs.has(encodedReference)) {
      throw new Error('KeyPackage reference has already been consumed');
    }
    const existing = this.working.pendingKeyPackages.get(encodedReference);
    if (existing !== undefined) {
      if (!sameEncryptedKeyPackageState(existing, snapshot)) {
        throw new Error(
          'KeyPackage reference already exists with different encrypted content',
        );
      }
      return false;
    }
    if (
      this.working.pendingKeyPackages.size >=
      MAX_PENDING_KEY_PACKAGE_ENTRIES
    ) {
      throw new Error('pending KeyPackage entry limit reached');
    }
    const projectedBytes =
      pendingKeyPackageBytes(this.working.pendingKeyPackages.values()) +
      intrinsicByteLength(serializedEncryptedKeyPackageState(snapshot));
    if (projectedBytes > MAX_PENDING_KEY_PACKAGE_BYTES) {
      throw new Error('pending KeyPackage byte limit reached');
    }
    this.adjustCommittedBytes(pendingEntryCommittedBytes(snapshot));
    this.working.pendingKeyPackages.set(encodedReference, snapshot);
    return true;
  }

  getPendingKeyPackageRequest(
    operationId: Uint8Array,
  ): GroupStatePendingKeyPackageRequest | undefined {
    this.assertActive();
    const stableOperationId = cloneFixedId(
      operationId,
      'pending KeyPackage operationId',
    );
    const request = this.working.pendingKeyPackageRequests.get(
      toHex(stableOperationId),
    );
    return request === undefined
      ? undefined
      : clonePendingKeyPackageRequest(request);
  }

  bindPendingKeyPackageRequest(
    request: GroupStatePendingKeyPackageRequest,
  ): boolean {
    this.assertActive();
    const stableRequest = validateAndClonePendingKeyPackageRequest(request);
    const encodedOperationId = toHex(stableRequest.operationId);
    const encodedReference = toHex(stableRequest.keyPackageReference);
    const existing = this.working.pendingKeyPackageRequests.get(
      encodedOperationId,
    );
    if (existing !== undefined) {
      if (!samePendingKeyPackageRequest(existing, stableRequest)) {
        throw new Error(
          'pending KeyPackage operationId has a different request binding',
        );
      }
      return false;
    }
    if (!this.working.pendingKeyPackages.has(encodedReference)) {
      throw new Error(
        'pending KeyPackage request references missing encrypted state',
      );
    }
    for (const current of this.working.pendingKeyPackageRequests.values()) {
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
      this.working.pendingKeyPackageRequests.size >=
      MAX_PENDING_KEY_PACKAGE_ENTRIES
    ) {
      throw new Error('pending KeyPackage request limit reached');
    }
    this.adjustCommittedBytes(
      pendingRequestCommittedBytes(stableRequest),
    );
    this.working.pendingKeyPackageRequests.set(
      encodedOperationId,
      stableRequest,
    );
    return true;
  }

  hasConsumedKeyPackage(reference: Uint8Array): boolean {
    this.assertActive();
    const stableReference = cloneKeyPackageReference(reference);
    return this.working.consumedKeyPackageRefs.has(toHex(stableReference));
  }

  consumePendingKeyPackage(
    reference: Uint8Array,
  ): EncryptedKeyPackageState {
    this.assertActive();
    const stableReference = cloneKeyPackageReference(reference);
    const encodedReference = toHex(stableReference);
    if (this.working.consumedKeyPackageRefs.has(encodedReference)) {
      throw new Error('KeyPackage reference has already been consumed');
    }
    const pending = this.working.pendingKeyPackages.get(encodedReference);
    if (pending === undefined) {
      throw new Error('KeyPackage reference is not pending');
    }
    if (
      this.working.consumedKeyPackageRefs.size >=
      MAX_CONSUMED_KEY_PACKAGE_MARKERS
    ) {
      throw new Error('consumed KeyPackage marker limit reached');
    }
    this.adjustCommittedBytes(
      intrinsicByteLength(stableReference) + 2 -
        pendingEntryCommittedBytes(pending),
    );
    for (const [operationId, request] of
      this.working.pendingKeyPackageRequests) {
      if (equalBytes(request.keyPackageReference, stableReference)) {
        this.adjustCommittedBytes(-pendingRequestCommittedBytes(request));
        this.working.pendingKeyPackageRequests.delete(operationId);
      }
    }
    this.working.pendingKeyPackages.delete(encodedReference);
    this.working.consumedKeyPackageRefs.set(
      encodedReference,
      stableReference,
    );
    return cloneEncryptedKeyPackageState(pending);
  }

  enqueueOutbox(entry: GroupStateOutboxEntry): boolean {
    this.assertActive();
    const stableEntry = validateAndCloneOutboxEntry(entry);
    const id = toHex(stableEntry.id);
    const existing = this.working.outbox.get(id);
    if (existing !== undefined) {
      if (!sameOutboxEntry(existing, stableEntry)) {
        throw new Error('outbox id already exists with different content');
      }
      return false;
    }
    if (this.working.outbox.size >= MAX_GROUP_STATE_METADATA_ENTRIES) {
      throw new Error('outbox entry limit reached');
    }
    this.adjustCommittedBytes(outboxEntryCommittedBytes(stableEntry));
    this.working.outbox.set(id, stableEntry);
    return true;
  }

  removeOutbox(id: Uint8Array): boolean {
    this.assertActive();
    const stableId = cloneFixedId(id, 'outbox id');
    const encodedId = toHex(stableId);
    const existing = this.working.outbox.get(encodedId);
    if (existing === undefined) return false;
    this.adjustCommittedBytes(-outboxEntryCommittedBytes(existing));
    this.working.outbox.delete(encodedId);
    return true;
  }

  hasReplayRecord(recordId: Uint8Array): boolean {
    this.assertActive();
    const stableRecordId = cloneFixedId(recordId, 'replay recordId');
    return this.working.replay.has(toHex(stableRecordId));
  }

  markReplay(entry: GroupStateReplayEntry): boolean {
    this.assertActive();
    const stableEntry = validateAndCloneReplayEntry(entry);
    const recordId = toHex(stableEntry.recordId);
    const existing = this.working.replay.get(recordId);
    if (existing !== undefined) {
      if (!sameReplayEntry(existing, stableEntry)) {
        throw new Error('replay recordId has different metadata');
      }
      return false;
    }
    if (this.working.replay.size >= MAX_GROUP_STATE_METADATA_ENTRIES) {
      throw new Error('replay entry limit reached');
    }
    let operationId: string | undefined;
    if (stableEntry.operationId !== undefined) {
      operationId = toHex(stableEntry.operationId);
      const priorRecord = this.working.operationToRecord.get(operationId);
      if (priorRecord !== undefined && priorRecord !== recordId) {
        throw new Error('operationId belongs to a different replay recordId');
      }
    }
    this.adjustCommittedBytes(replayEntryCommittedBytes(stableEntry));
    if (operationId !== undefined) {
      this.working.operationToRecord.set(operationId, recordId);
    }
    this.working.replay.set(recordId, stableEntry);
    return true;
  }

  removeReplay(recordId: Uint8Array): boolean {
    this.assertActive();
    const stableRecordId = cloneFixedId(recordId, 'replay recordId');
    const recordHex = toHex(stableRecordId);
    const existing = this.working.replay.get(recordHex);
    if (existing === undefined) return false;
    this.adjustCommittedBytes(-replayEntryCommittedBytes(existing));
    this.working.replay.delete(recordHex);
    if (existing.operationId !== undefined) {
      const operationHex = toHex(existing.operationId);
      if (this.working.operationToRecord.get(operationHex) === recordHex) {
        this.working.operationToRecord.delete(operationHex);
      }
    }
    return true;
  }

  markFork(evidence: GroupStateForkEvidence): boolean {
    this.assertActive();
    const normalized = normalizeForkEvidence(evidence);
    if (this.working.forkEvidence !== undefined) {
      if (!sameForkEvidence(this.working.forkEvidence, normalized)) {
        throw new Error('group already has different fork evidence');
      }
      return false;
    }
    this.adjustCommittedBytes(forkEvidenceCommittedBytes(normalized));
    this.working.forkEvidence = normalized;
    return true;
  }

  validateBeforeCommit(): void {
    this.assertActive();
    const recomputedCommittedBytes = committedStateBytes(
      this.working,
      this.maximumCommittedBytes,
    );
    if (recomputedCommittedBytes !== this.committedBytes) {
      throw new Error('group-state store committed-byte accounting mismatch');
    }
    if (
      this.working.consumedKeyPackageRefs.size >
      MAX_CONSUMED_KEY_PACKAGE_MARKERS
    ) {
      throw new Error('consumed KeyPackage marker limit exceeded');
    }
    if (
      this.working.outbox.size > MAX_GROUP_STATE_METADATA_ENTRIES ||
      this.working.replay.size > MAX_GROUP_STATE_METADATA_ENTRIES
    ) {
      throw new Error('group-state metadata entry limit exceeded');
    }
    if (
      this.working.pendingKeyPackages.size >
      MAX_PENDING_KEY_PACKAGE_ENTRIES ||
      this.working.pendingKeyPackageRequests.size >
        MAX_PENDING_KEY_PACKAGE_ENTRIES ||
      pendingKeyPackageBytes(this.working.pendingKeyPackages.values()) >
        MAX_PENDING_KEY_PACKAGE_BYTES
    ) {
      throw new Error('pending KeyPackage retention limit exceeded');
    }
    for (const [encodedReference, state] of this.working.pendingKeyPackages) {
      const validated = validateAndCloneEncryptedKeyPackageState(
        state,
        this.key,
      );
      if (
        toHex(getEncryptedKeyPackageValue(validated).reference) !==
        encodedReference
      ) {
        throw new Error('pending KeyPackage map key does not match reference');
      }
      if (this.working.consumedKeyPackageRefs.has(encodedReference)) {
        throw new Error('KeyPackage cannot be both pending and consumed');
      }
    }
    const requestedReferences = new Set<string>();
    for (const [encodedOperationId, request] of
      this.working.pendingKeyPackageRequests) {
      const validated = validateAndClonePendingKeyPackageRequest(request);
      if (toHex(validated.operationId) !== encodedOperationId) {
        throw new Error(
          'pending KeyPackage request map key does not match operationId',
        );
      }
      const encodedReference = toHex(validated.keyPackageReference);
      if (!this.working.pendingKeyPackages.has(encodedReference)) {
        throw new Error(
          'pending KeyPackage request references missing encrypted state',
        );
      }
      if (requestedReferences.has(encodedReference)) {
        throw new Error(
          'pending KeyPackage reference has multiple operation bindings',
        );
      }
      requestedReferences.add(encodedReference);
    }
    if (
      requestedReferences.size !== this.working.pendingKeyPackages.size ||
      [...this.working.pendingKeyPackages.keys()].some(
        (encodedReference) => !requestedReferences.has(encodedReference),
      )
    ) {
      throw new Error(
        'every pending KeyPackage must have exactly one request binding',
      );
    }
    for (const [encodedReference, reference] of
      this.working.consumedKeyPackageRefs) {
      cloneKeyPackageReference(reference);
      if (toHex(reference) !== encodedReference) {
        throw new Error('consumed KeyPackage map key does not match reference');
      }
    }
    const epoch =
      this.working.encryptedState === undefined
        ? undefined
        : getEncryptedGroupStateValue(this.working.encryptedState).epoch;
    if (epoch === undefined) {
      if (
        this.working.consumedKeyPackageRefs.size > 0 ||
        this.working.outbox.size > 0 ||
        this.working.replay.size > 0 ||
        this.working.forkEvidence !== undefined
      ) {
        throw new Error(
          'consumed/replay metadata cannot commit without encrypted group state',
        );
      }
      return;
    }
    for (const entry of this.working.outbox.values()) {
      if (entry.epoch > epoch) {
        throw new Error('outbox epoch is newer than encrypted state');
      }
    }
    for (const entry of this.working.replay.values()) {
      if (entry.epoch > epoch) {
        throw new Error('replay epoch is newer than encrypted state');
      }
    }
    if (
      this.working.forkEvidence !== undefined &&
      this.working.forkEvidence.epoch > epoch
    ) {
      throw new Error('fork evidence is newer than encrypted state');
    }
  }

  close(): void {
    this.active = false;
  }

  private assertActive(): void {
    if (!this.active) throw new Error('group-state transaction is no longer active');
  }

  private adjustCommittedBytes(delta: number): void {
    const next = this.committedBytes + delta;
    if (
      !Number.isSafeInteger(next) ||
      next < COMMITTED_STATE_FIXED_OVERHEAD ||
      next > this.maximumCommittedBytes
    ) {
      throw new Error('group-state store committed-byte limit reached');
    }
    this.committedBytes = next;
  }
}

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
        cloneBytes(
          reference,
          'consumed KeyPackage reference',
          1,
          MAX_KEY_PACKAGE_REFERENCE_BYTES,
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
        cloneBytes(
          reference,
          'consumed KeyPackage reference',
          1,
          MAX_KEY_PACKAGE_REFERENCE_BYTES,
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

function cloneEncryptedState(state: EncryptedGroupState): EncryptedGroupState {
  return deserializeEncryptedGroupState.call(
    EncryptedGroupState,
    serializedEncryptedGroupState(state),
  );
}

function cloneEncryptedKeyPackageState(
  state: EncryptedKeyPackageState,
): EncryptedKeyPackageState {
  return deserializeEncryptedKeyPackageState.call(
    EncryptedKeyPackageState,
    serializedEncryptedKeyPackageState(state),
  );
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
    total += intrinsicByteLength(serializedEncryptedKeyPackageState(state));
    if (total > MAX_PENDING_KEY_PACKAGE_BYTES) return total;
  }
  return total;
}

function serializedEncryptedGroupState(
  state: EncryptedGroupState,
): Uint8Array {
  if (!isEncryptedGroupState(state)) {
    throw new Error(
      'group-state store accepts only EncryptedGroupState; plaintext private state is forbidden',
    );
  }
  return cloneBytes(
    serializeEncryptedGroupState.call(state),
    'serialized encrypted group state',
    1,
    MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
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
  return cloneBytes(
    serializeEncryptedKeyPackageState.call(state),
    'serialized encrypted KeyPackage state',
    1,
    MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
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

function validateAndCloneStoreKey(key: GroupStateStoreKey): GroupStateStoreKey {
  const record = exactPlainDataObject(
    key,
    ['protocol', 'groupId'],
    ['protocol', 'groupId'],
    'store key',
  );
  const protocol = validateAndCloneProtocol(
    dataProperty(record, 'protocol'),
  );
  const groupId = cloneBytes(
    dataProperty(record, 'groupId'),
    'groupId',
    1,
    1024,
  );
  return {
    protocol,
    groupId,
  };
}

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

function validateAndCloneProtocol(value: unknown): GroupSecurityProtocol {
  const protocol = exactPlainDataObject(
    value,
    ['id', 'version'],
    ['id', 'version'],
    'protocol',
  );
  const id = dataProperty(protocol, 'id');
  const version = dataProperty(protocol, 'version');
  if (
    typeof id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(id) ||
    !Number.isInteger(version) ||
    (version as number) < 0 ||
    (version as number) > 0xffff
  ) {
    throw new Error('invalid canonical protocol identifier');
  }
  return { id, version: version as number };
}

function validateAndCloneOutboxEntry(
  value: GroupStateOutboxEntry,
): GroupStateOutboxEntry {
  const entry = exactPlainDataObject(
    value,
    ['id', 'kind', 'epoch', 'payload', 'createdAt'],
    ['id', 'kind', 'epoch', 'payload', 'createdAt'],
    'outbox entry',
  );
  const kind = dataProperty(entry, 'kind');
  const epoch = dataProperty(entry, 'epoch');
  const createdAt = dataProperty(entry, 'createdAt');
  if (
    typeof kind !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(kind)
  ) {
    throw new Error('invalid outbox kind');
  }
  validateU64(epoch as bigint, 'outbox epoch');
  if (!Number.isSafeInteger(createdAt) || (createdAt as number) < 0) {
    throw new Error('outbox createdAt must be a non-negative safe integer');
  }
  return {
    id: cloneFixedId(dataProperty(entry, 'id'), 'outbox id'),
    kind,
    epoch: epoch as bigint,
    payload: cloneBytes(
      dataProperty(entry, 'payload'),
      'outbox payload',
      1,
      MAX_OUTBOX_PAYLOAD_BYTES,
    ),
    createdAt: createdAt as number,
  };
}

function validateAndCloneReplayEntry(
  value: GroupStateReplayEntry,
): GroupStateReplayEntry {
  const entry = exactPlainDataObject(
    value,
    ['recordId', 'operationId', 'epoch', 'controlRecord'],
    ['recordId', 'epoch', 'controlRecord'],
    'replay entry',
  );
  const operationId = optionalDataProperty(entry, 'operationId');
  const epoch = dataProperty(entry, 'epoch');
  validateU64(epoch as bigint, 'replay epoch');
  return {
    recordId: cloneFixedId(
      dataProperty(entry, 'recordId'),
      'replay recordId',
    ),
    operationId:
      operationId === undefined
        ? undefined
        : cloneFixedId(operationId, 'replay operationId'),
    epoch: epoch as bigint,
    controlRecord: cloneBytes(
      dataProperty(entry, 'controlRecord'),
      'replay controlRecord',
      1,
      MAX_CONTROL_RECORD_BYTES,
    ),
  };
}

function validateAndClonePendingKeyPackageRequest(
  value: GroupStatePendingKeyPackageRequest,
): GroupStatePendingKeyPackageRequest {
  const request = exactPlainDataObject(
    value,
    ['operationId', 'requestCommitment', 'keyPackageReference'],
    ['operationId', 'requestCommitment', 'keyPackageReference'],
    'pending KeyPackage request',
  );
  return {
    operationId: cloneFixedId(
      dataProperty(request, 'operationId'),
      'pending KeyPackage operationId',
    ),
    requestCommitment: cloneFixedId(
      dataProperty(request, 'requestCommitment'),
      'pending KeyPackage request commitment',
    ),
    keyPackageReference: cloneKeyPackageReference(
      dataProperty(request, 'keyPackageReference') as Uint8Array,
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
  const evidence = exactPlainDataObject(
    value,
    [
      'epoch',
      'parentRecordId',
      'firstRecordId',
      'firstControlRecord',
      'secondRecordId',
      'secondControlRecord',
    ],
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
  const epoch = dataProperty(evidence, 'epoch');
  validateU64(epoch as bigint, 'fork epoch');
  const cloned: GroupStateForkEvidence = {
    epoch: epoch as bigint,
    parentRecordId: cloneFixedId(
      dataProperty(evidence, 'parentRecordId'),
      'fork parentRecordId',
    ),
    firstRecordId: cloneFixedId(
      dataProperty(evidence, 'firstRecordId'),
      'fork firstRecordId',
    ),
    firstControlRecord: cloneBytes(
      dataProperty(evidence, 'firstControlRecord'),
      'fork firstControlRecord',
      1,
      MAX_CONTROL_RECORD_BYTES,
    ),
    secondRecordId: cloneFixedId(
      dataProperty(evidence, 'secondRecordId'),
      'fork secondRecordId',
    ),
    secondControlRecord: cloneBytes(
      dataProperty(evidence, 'secondControlRecord'),
      'fork secondControlRecord',
      1,
      MAX_CONTROL_RECORD_BYTES,
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

function committedStateBytes(
  state: MutableState,
  maximum: number,
): number {
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
      intrinsicByteLength(reference) + 2,
      maximum,
    );
  }
  for (const entry of state.outbox.values()) {
    total = addCommittedBytes(
      total,
      outboxEntryCommittedBytes(entry),
      maximum,
    );
  }
  for (const entry of state.replay.values()) {
    total = addCommittedBytes(
      total,
      replayEntryCommittedBytes(entry),
      maximum,
    );
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
  const next = total + addition;
  if (!Number.isSafeInteger(next) || next > maximum) {
    throw new Error('group-state store committed-byte limit reached');
  }
  return next;
}

function encryptedStateCommittedBytes(state: EncryptedGroupState): number {
  return intrinsicByteLength(serializedEncryptedGroupState(state)) + 4;
}

function pendingEntryCommittedBytes(
  state: EncryptedKeyPackageState,
): number {
  const reference = getEncryptedKeyPackageValue(state).reference;
  return (
    intrinsicByteLength(serializedEncryptedKeyPackageState(state)) +
    intrinsicByteLength(reference) +
    6
  );
}

function pendingRequestCommittedBytes(
  request: GroupStatePendingKeyPackageRequest,
): number {
  return (
    2 * GROUP_STATE_STORE_ID_LENGTH +
    2 +
    intrinsicByteLength(request.keyPackageReference)
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
    intrinsicByteLength(entry.payload)
  );
}

function replayEntryCommittedBytes(entry: GroupStateReplayEntry): number {
  return (
    GROUP_STATE_STORE_ID_LENGTH +
    1 +
    (entry.operationId === undefined
      ? 0
      : 4 + intrinsicByteLength(entry.operationId)) +
    8 +
    4 +
    intrinsicByteLength(entry.controlRecord)
  );
}

function forkEvidenceCommittedBytes(evidence: GroupStateForkEvidence): number {
  return (
    1 +
    4 +
    8 +
    3 * GROUP_STATE_STORE_ID_LENGTH +
    4 +
    intrinsicByteLength(evidence.firstControlRecord) +
    4 +
    intrinsicByteLength(evidence.secondControlRecord)
  );
}

function exactPlainDataObject(
  value: unknown,
  allowed: ReadonlyArray<string>,
  required: ReadonlyArray<string>,
  field: string,
): Record<PropertyKey, unknown> {
  if (
    value === null ||
    typeof value !== 'object' ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw new Error(`${field} must be a plain object`);
  }
  const record = value as Record<PropertyKey, unknown>;
  const keys = Reflect.ownKeys(record);
  if (
    keys.some((key) => typeof key !== 'string' || !allowed.includes(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    throw new Error(`${field} has unexpected or missing fields`);
  }
  for (const key of keys) dataProperty(record, key as string);
  return record;
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

function compareBytes(first: Uint8Array, second: Uint8Array): number {
  const firstLength = intrinsicByteLength(first);
  const secondLength = intrinsicByteLength(second);
  const length = Math.min(firstLength, secondLength);
  for (let index = 0; index < length; index++) {
    if (first[index] !== second[index]) return first[index] - second[index];
  }
  return firstLength - secondLength;
}

function cloneFixedId(value: unknown, field: string): Uint8Array {
  return cloneBytes(
    value,
    field,
    GROUP_STATE_STORE_ID_LENGTH,
    GROUP_STATE_STORE_ID_LENGTH,
  );
}

function cloneKeyPackageReference(reference: unknown): Uint8Array {
  return cloneBytes(
    reference,
    'KeyPackage reference',
    1,
    MAX_KEY_PACKAGE_REFERENCE_BYTES,
  );
}

function cloneBytes(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): Uint8Array {
  let length: number;
  let buffer: ArrayBufferLike;
  let tag: unknown;
  try {
    tag = Reflect.apply(typedArrayTag, value, []);
    length = Reflect.apply(typedArrayByteLength, value, []) as number;
    buffer = Reflect.apply(typedArrayBuffer, value, []) as ArrayBufferLike;
  } catch {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  if (
    tag !== 'Uint8Array' ||
    !Number.isSafeInteger(length) ||
    length < minimum ||
    length > maximum ||
    isSharedArrayBuffer(buffer)
  ) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  const clone = new Uint8Array(length);
  uint8ArraySet.call(clone, value as Uint8Array);
  return clone;
}

function intrinsicByteLength(value: Uint8Array): number {
  return Reflect.apply(typedArrayByteLength, value, []) as number;
}

function isSharedArrayBuffer(value: ArrayBufferLike): boolean {
  if (sharedArrayBufferByteLength === undefined) return false;
  try {
    Reflect.apply(sharedArrayBufferByteLength, value, []);
    return true;
  } catch {
    return false;
  }
}

function validateU64(value: bigint, field: string): void {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
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
    optionalBytesEqual(a.operationId, b.operationId) &&
    equalBytes(a.controlRecord, b.controlRecord)
  );
}

function optionalBytesEqual(
  a: Uint8Array | undefined,
  b: Uint8Array | undefined,
): boolean {
  return a === undefined || b === undefined ? a === b : equalBytes(a, b);
}

function sameProtocol(
  a: GroupSecurityProtocol,
  b: GroupSecurityProtocol,
): boolean {
  return a.id === b.id && a.version === b.version;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  const aLength = intrinsicByteLength(a);
  const bLength = intrinsicByteLength(b);
  if (aLength !== bLength) return false;
  let different = 0;
  for (let i = 0; i < aLength; i++) different |= a[i] ^ b[i];
  return different === 0;
}

function encodeStoreKey(key: GroupStateStoreKey): string {
  return `${key.protocol.id}:${key.protocol.version}:${toHex(key.groupId)}`;
}

function toHex(bytes: Uint8Array): string {
  const length = intrinsicByteLength(bytes);
  const encoded = new Array<string>(length);
  for (let index = 0; index < length; index++) {
    encoded[index] = HEX_BYTE_LOOKUP[bytes[index]];
  }
  return Reflect.apply(arrayJoin, encoded, ['']) as string;
}
