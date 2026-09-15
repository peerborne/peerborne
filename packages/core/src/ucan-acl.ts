import {
  ACL,
  ACLOperationInProgressError,
  PreparedACLRemoval,
} from './acl.js';
import { ACLProvider } from './acl-provider.js';
import { UCAN, createUCAN } from './ucan.js';
import { DocumentCapability, capabilityImplies } from './capabilities.js';
import { LRUCache } from './lru-cache.js';
import { EPOCH_ID_LENGTH } from './epoch.js';
import {
  copyUnsharedUint8Array,
  snapshotDeepEnumerableData,
} from './utils.js';

/**
 * An entry in the UCAN-based ACL.
 */
export interface UCANACLEntry {
  /** The member's public key, Base64-encoded */
  publicKeyBase64: string;
  /** The UCAN token granting this access */
  ucan: UCAN;
  /** Parsed capabilities from the UCAN */
  capabilities: string[];
  /** Who delegated this access (Base64-encoded public key) */
  grantedBy: string;
  /** Epoch ID when access was granted */
  epochId?: Uint8Array;
  /** Whether this entry has been revoked */
  revoked: boolean;
}

function copyUCAN(ucan: UCAN): UCAN {
  return {
    ...ucan,
    capabilities: ucan.capabilities.map(({ resource, ability }) => ({
      resource,
      ability,
    })),
    proofs: [...ucan.proofs],
  };
}

function copyOptionalEpochId(epochId: unknown): Uint8Array | undefined {
  return epochId === undefined
    ? undefined
    : copyUnsharedUint8Array(
        epochId,
        EPOCH_ID_LENGTH,
        EPOCH_ID_LENGTH,
        'UCAN ACL epoch ID',
      );
}

function copyUCANEntry(entry: UCANACLEntry): UCANACLEntry {
  return {
    ...entry,
    ucan: copyUCAN(entry.ucan),
    capabilities: [...entry.capabilities],
    epochId: copyOptionalEpochId(entry.epochId),
  };
}

const MAX_STABLE_READ_ATTEMPTS = 3;
const MAX_CACHED_LISTING_IDENTITIES = 128;
const MAX_CACHED_IDENTITY_ENCODING_LENGTH = 8 * 1024;
/** Hard limit that keeps one backing listing's identity-codec fanout bounded. */
export const MAX_UCAN_ACL_LISTING_IDENTITIES = 4096;
const CACHED_IDENTITY_SNAPSHOT_LIMITS = {
  maxDepth: 8,
  maxObjects: 16,
  maxProperties: 64,
  maxArrayLength: 64,
  maxValueBytes: 8 * 1024,
} as const;
const arrayIsArray = Array.isArray;
const objectGetPrototypeOf = Object.getPrototypeOf;
const reflectApply = Reflect.apply;
const reflectGet = Reflect.get;

interface CachedListingIdentity<PublicKey> {
  readonly backingRevision: object;
  readonly template: PublicKey;
}

/**
 * UCAN-based ACL with fine-grained capability support.
 *
 * Capability metadata and local revocation tombstones are process-local; only
 * membership in the backing ACL is replicated. Capability checks therefore
 * require current backing membership first, so a remote removal takes effect
 * locally even while a stale metadata entry remains cached. Because generic
 * backing changes do not identify affected users, a remote merge never clears
 * a local tombstone: a remotely re-added identity stays denied until an
 * explicit local `add` or `grant`. A removal observed only through a remote
 * merge cannot create such a tombstone, so this wrapper does not provide
 * distributed strong-removal semantics by itself.
 *
 * The generic ACL contract exposes one opaque mutable state and does not
 * promise key-isolated commits, so overlapping calls could derive changes
 * from the same document-wide baseline. All asynchronous backing operations
 * are therefore single-flight. Checks, listings, entry lookups, mutations, and
 * the synchronous `current()` snapshot reject with a retryable conflict while
 * another public operation is unresolved, rather than risk observing partially
 * changed backing state or deadlocking on deferred backing-to-wrapper
 * recursion. External orchestration may wait for that conflict to settle and
 * retry. Backing ACL implementations and identity codecs must instead
 * propagate it because they may own the operation that must settle. Direct
 * synchronous backing-to-wrapper recursion is also rejected. Any rejected
 * opaque mutation poisons the instance because the generic ACL contract does
 * not identify which memberships may already have changed. A failed backing
 * addition also quarantines its requested identity, while a previously granted
 * UCAN is preserved only when stable backing membership was proven before the
 * attempt.
 *
 * The identity serializer must be canonical and collision-free for the
 * provider's identity domain, and must capture caller-owned state before its
 * first asynchronous suspension. Object and function identities additionally
 * require a deserializer that returns a fully detached identity with the same
 * canonical encoding. Listing caches retain only bounded, private canonical
 * templates for one backing revision, and every identity returned to a caller
 * is freshly detached. Primitive identities are immutable and remain
 * supported with the two-argument constructor. Backing listings above
 * {@link MAX_UCAN_ACL_LISTING_IDENTITIES} fail before identity codecs start,
 * so sparse or proxied arrays cannot schedule unbounded snapshot work.
 */
export class UCANACL<ChangesType, PublicKey> implements ACL<ChangesType, PublicKey> {
  private _entries: Map<string, UCANACLEntry> = new Map(); // publicKeyBase64 -> entry
  private _revokedKeys: Set<string> = new Set(); // set of revoked public key base64 strings
  private _metadataRevision: object = {};
  private _backingRevision: object = {};
  private _failedAdditions: Set<string> = new Set();
  private _pendingAdditions: Map<string, number> = new Map();
  private _pendingGrants: Set<string> = new Set();
  private _pendingRemovals: Map<string, number> = new Map();
  private _publicOperationsInFlight = 0;
  private _backingOperationsInFlight = 0;
  private _backingInvocationDepth = 0;
  private readonly _backingOperationSettlements = new Set<Promise<void>>();
  private readonly _publicOperationSettlements = new Set<Promise<void>>();
  private readonly _issuedOperationConflicts = new WeakSet<
    ACLOperationInProgressError
  >();
  private _backingStateUncertain = false;
  private _backingSyncContractViolated = false;
  private readonly _listingIdentityCache = new LRUCache<
    string,
    CachedListingIdentity<PublicKey>
  >(MAX_CACHED_LISTING_IDENTITIES);

  // Private backing ACL so membership checks cannot bypass the wrapper's
  // capability and local-revocation gates.
  constructor(
    private readonly _backing: ACL<ChangesType, PublicKey>,
    private readonly _serializePublicKey: (key: PublicKey) => Promise<string>,
    private readonly _deserializePublicKey?: (
      serialized: string,
    ) => Promise<PublicKey>,
  ) {}

  /** Bind metadata and backing membership to one canonical identity. */
  private async _snapshotPublicKey(
    publicKey: PublicKey,
    operation: string,
  ): Promise<{ publicKey: PublicKey; keyBase64: string }> {
    const keyBase64 = await this._canonicalPublicKey(publicKey, operation);
    const stablePublicKey = await this._deserializeStablePublicKey(
      publicKey,
      keyBase64,
      operation,
    );
    if (!this._deserializePublicKey) {
      return { publicKey: stablePublicKey, keyBase64 };
    }
    if ((await this._serializePublicKey(stablePublicKey)) !== keyBase64) {
      throw new Error(
        `${operation} rejected a non-canonical public-key round trip`,
      );
    }
    return { publicKey: stablePublicKey, keyBase64 };
  }

  private async _canonicalPublicKey(
    publicKey: PublicKey,
    operation: string,
  ): Promise<string> {
    const keyBase64 = await this._serializePublicKey(publicKey);
    if (typeof keyBase64 !== 'string' || keyBase64.length === 0) {
      throw new TypeError(
        `${operation} requires a non-empty canonical public-key encoding`,
      );
    }
    return keyBase64;
  }

  private async _deserializeStablePublicKey(
    publicKey: PublicKey,
    keyBase64: string,
    operation: string,
  ): Promise<PublicKey> {
    const mutableIdentity =
      (typeof publicKey === 'object' && publicKey !== null) ||
      typeof publicKey === 'function';
    if (!this._deserializePublicKey) {
      if (mutableIdentity) {
        throw new Error(
          `${operation} requires a public-key deserializer for mutable identities`,
        );
      }
      return publicKey;
    }

    const stablePublicKey = await this._deserializePublicKey(keyBase64);
    if (mutableIdentity && stablePublicKey === publicKey) {
      throw new Error(
        `${operation} requires the public-key deserializer to return a detached identity`,
      );
    }
    return stablePublicKey;
  }

  private _cloneCacheableListingIdentity(
    publicKey: PublicKey,
  ): PublicKey | undefined {
    let clone: PublicKey;
    try {
      clone = snapshotDeepEnumerableData(
        publicKey,
        'ACL listing identity',
        CACHED_IDENTITY_SNAPSHOT_LIMITS,
      );
      const sourceIsObject =
        typeof publicKey === 'object' && publicKey !== null;
      if (
        sourceIsObject &&
        (clone === publicKey ||
          reflectApply(objectGetPrototypeOf, Object, [clone]) !==
            reflectApply(objectGetPrototypeOf, Object, [publicKey]))
      ) {
        return undefined;
      }
    } catch {
      return undefined;
    }
    return clone;
  }

  private async _snapshotListedPublicKey(
    publicKey: PublicKey,
    operation: string,
    backingRevision: object,
  ): Promise<{ publicKey: PublicKey; keyBase64: string }> {
    const keyBase64 = await this._canonicalPublicKey(publicKey, operation);
    const cacheableEncoding =
      keyBase64.length <= MAX_CACHED_IDENTITY_ENCODING_LENGTH;
    if (cacheableEncoding) {
      const cached = this._listingIdentityCache.get(keyBase64);
      if (cached?.backingRevision === backingRevision) {
        const clone = this._cloneCacheableListingIdentity(cached.template);
        if (clone !== undefined) return { publicKey: clone, keyBase64 };
      }
    }

    const stablePublicKey = await this._deserializeStablePublicKey(
      publicKey,
      keyBase64,
      operation,
    );
    if (!this._deserializePublicKey) {
      return { publicKey: stablePublicKey, keyBase64 };
    }
    if (cacheableEncoding) {
      // Keep a clone that neither the codec nor any caller can retain. Validate
      // canonicality on a separate throwaway clone before caching it.
      const template = this._cloneCacheableListingIdentity(stablePublicKey);
      const validationIdentity =
        template === undefined
          ? undefined
          : this._cloneCacheableListingIdentity(template);
      const returnedIdentity =
        template === undefined
          ? undefined
          : this._cloneCacheableListingIdentity(template);
      if (
        template !== undefined &&
        validationIdentity !== undefined &&
        returnedIdentity !== undefined
      ) {
        let validationEncoding: string | undefined;
        try {
          validationEncoding = await this._serializePublicKey(
            validationIdentity,
          );
        } catch {
          // A structurally cloneable identity can still rely on representation
          // details that the bounded clone intentionally does not preserve.
        }
        if (validationEncoding === keyBase64) {
          if (this._backingRevision === backingRevision) {
            this._listingIdentityCache.set(keyBase64, {
              backingRevision,
              template,
            });
          }
          return { publicKey: returnedIdentity, keyBase64 };
        }
      }
    }

    if ((await this._serializePublicKey(stablePublicKey)) !== keyBase64) {
      throw new Error(
        `${operation} rejected a non-canonical public-key round trip`,
      );
    }
    return { publicKey: stablePublicKey, keyBase64 };
  }

  /** Reserve the complete identity-codec and membership-mutation lifetime. */
  private _startMembershipMutation<T>(
    publicKey: PublicKey,
    operationName: string,
    operation: (snapshot: {
      publicKey: PublicKey;
      keyBase64: string;
    }) => Promise<T>,
    reserve?: (snapshot: {
      publicKey: PublicKey;
      keyBase64: string;
    }) => (() => void) | undefined,
    captureInputs?: () => void,
  ): Promise<T> {
    this._assertPublicOperationAvailable(operationName);
    const finishPublicOperation = this._beginPublicOperation();

    const mutation = (async () => {
      // Reserve the operation before capturing caller-owned iterables or
      // invoking a caller-supplied codec. Both can execute synchronously and
      // must not reenter the wrapper around this operation.
      captureInputs?.();
      const snapshot = this._snapshotPublicKey(publicKey, operationName);
      let releaseReservation: (() => void) | undefined;
      try {
        const stableSnapshot = await snapshot;
        this._assertHealthy(operationName);
        releaseReservation = reserve?.(stableSnapshot);
        this._assertHealthy(operationName);
        return await operation(stableSnapshot);
      } finally {
        releaseReservation?.();
      }
    })();
    return mutation.finally(() => {
      finishPublicOperation();
    });
  }

  private _markMetadataMutation(): void {
    this._metadataRevision = {};
  }

  private _markBackingMutation(): void {
    this._backingRevision = {};
  }

  private _assertHealthy(operation: string): void {
    if (this._backingInvocationDepth !== 0) {
      throw new Error(
        `${operation} cannot reenter the UCAN ACL from a backing ACL operation`,
      );
    }
    if (this._backingSyncContractViolated) {
      throw new Error(
        `${operation} is unavailable because the backing ACL violated a synchronous operation contract`,
      );
    }
    if (this._backingStateUncertain) {
      throw new Error(
        `${operation} is unavailable because a failed ACL backing mutation may have ` +
          'partially changed backing membership',
      );
    }
  }

  /** Reject direct backing-to-wrapper recursion at its synchronous boundary. */
  private _invokeBacking<T>(operation: () => T): T {
    this._backingInvocationDepth++;
    try {
      return operation();
    } finally {
      this._backingInvocationDepth--;
    }
  }

  private _invokeSynchronousBacking<T>(
    operation: () => T,
    operationName: string,
  ): T {
    return this._invokeBacking(() => {
      const result = operation();
      let then: unknown;
      if (
        (typeof result === 'object' && result !== null) ||
        typeof result === 'function'
      ) {
        try {
          then = reflectGet(result, 'then');
        } catch {
          this._backingSyncContractViolated = true;
          throw new TypeError(
            `${operationName} returned an invalid asynchronous result`,
          );
        }
      }
      if (typeof then === 'function') {
        // Poison before assimilating the thenable. Its continuation may have
        // already been scheduled and must not be able to reenter this wrapper
        // after the synchronous invocation guard is released.
        this._backingSyncContractViolated = true;
        void Promise.resolve(result).catch(() => undefined);
        throw new TypeError(`${operationName} must complete synchronously`);
      }
      return result;
    });
  }

  private _beginBackingOperation(): () => void {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    this._backingOperationSettlements.add(settlement);
    this._backingOperationsInFlight++;
    return () => {
      this._backingOperationsInFlight--;
      this._backingOperationSettlements.delete(settlement);
      settle();
    };
  }

  private _beginPublicOperation(): () => void {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    this._publicOperationSettlements.add(settlement);
    this._publicOperationsInFlight++;
    return () => {
      this._publicOperationsInFlight--;
      this._publicOperationSettlements.delete(settlement);
      settle();
    };
  }

  private async _runPublicOperation<T>(
    operationName: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    this._assertPublicOperationAvailable(operationName);
    const finishPublicOperation = this._beginPublicOperation();
    try {
      return await operation();
    } finally {
      finishPublicOperation();
    }
  }

  private _operationConflict(
    operation: string,
    settlements: Iterable<Promise<void>>,
  ): ACLOperationInProgressError {
    const conflict = new ACLOperationInProgressError(
      operation,
      Promise.all([...settlements]).then(() => undefined),
    );
    this._issuedOperationConflicts.add(conflict);
    return conflict;
  }

  private _isForeignOperationConflict(
    error: unknown,
  ): error is ACLOperationInProgressError {
    return (
      error instanceof ACLOperationInProgressError &&
      !this._issuedOperationConflicts.has(error)
    );
  }

  private _assertBackingOperationAvailable(operation: string): void {
    this._assertHealthy(operation);
    if (this._backingOperationsInFlight !== 0) {
      throw this._operationConflict(
        operation,
        this._backingOperationSettlements,
      );
    }
  }

  private _assertPublicOperationAvailable(operation: string): void {
    this._assertHealthy(operation);
    const settlements = [
      ...this._publicOperationSettlements,
      ...this._backingOperationSettlements,
    ];
    if (
      this._publicOperationsInFlight !== 0 ||
      this._backingOperationsInFlight !== 0
    ) {
      throw this._operationConflict(operation, settlements);
    }
  }

  private _quarantineAddition(keyBase64: string): void {
    this._failedAdditions.add(keyBase64);
    this._markMetadataMutation();
  }

  private async _hasStablePriorEntry(
    publicKey: PublicKey,
    keyBase64: string,
    operation: string,
  ): Promise<boolean> {
    const entry = this._entries.get(keyBase64);
    if (
      !entry ||
      this._pendingRemovals.has(keyBase64) ||
      this._revokedKeys.has(keyBase64) ||
      this._failedAdditions.has(keyBase64)
    ) {
      return false;
    }

    const metadataRevision = this._metadataRevision;
    const backingRevision = this._backingRevision;
    const isMember =
      (await this._runBackingRead(() => this._backing.check(publicKey))) ===
      true;
    this._assertBackingOperationAvailable(operation);
    return (
      isMember &&
      this._metadataRevision === metadataRevision &&
      this._backingRevision === backingRevision &&
      this._entries.get(keyBase64) === entry &&
      !this._pendingRemovals.has(keyBase64) &&
      !this._revokedKeys.has(keyBase64) &&
      !this._failedAdditions.has(keyBase64)
    );
  }

  private async _runBackingMutation<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    this._assertBackingOperationAvailable('ACL backing mutation');
    const finishBackingOperation = this._beginBackingOperation();
    try {
      return await this._invokeBacking(operation);
    } catch (error) {
      this._backingStateUncertain = true;
      if (error instanceof ACLOperationInProgressError) {
        throw new Error(
          'Backing ACL mutation reported a retry conflict after invocation; backing state is uncertain',
        );
      }
      throw error;
    } finally {
      // A rejected provider operation may still have changed opaque backing
      // state before reporting failure. Rotate the revision on every outcome
      // and keep all reads closed until an unresolved call has settled.
      this._markBackingMutation();
      finishBackingOperation();
    }
  }

  private async _runBackingRead<T>(operation: () => Promise<T>): Promise<T> {
    this._assertBackingOperationAvailable('ACL backing read');
    const finishBackingOperation = this._beginBackingOperation();
    try {
      return await this._invokeBacking(operation);
    } catch (error) {
      if (
        error instanceof ACLOperationInProgressError &&
        !this._isForeignOperationConflict(error)
      ) {
        throw new Error(
          'Backing ACL read cannot reenter this UCAN ACL while its read is unresolved',
        );
      }
      throw error;
    } finally {
      finishBackingOperation();
    }
  }

  private _reservePendingRemoval(keyBase64: string): () => void {
    this._pendingRemovals.set(
      keyBase64,
      (this._pendingRemovals.get(keyBase64) ?? 0) + 1,
    );
    return () => {
      const remaining = (this._pendingRemovals.get(keyBase64) ?? 1) - 1;
      if (remaining === 0) {
        this._pendingRemovals.delete(keyBase64);
      } else {
        this._pendingRemovals.set(keyBase64, remaining);
      }
    };
  }

  private _reservePendingAddition(keyBase64: string): () => void {
    this._pendingAdditions.set(
      keyBase64,
      (this._pendingAdditions.get(keyBase64) ?? 0) + 1,
    );
    return () => {
      const remaining = (this._pendingAdditions.get(keyBase64) ?? 1) - 1;
      if (remaining === 0) {
        this._pendingAdditions.delete(keyBase64);
      } else {
        this._pendingAdditions.set(keyBase64, remaining);
      }
    };
  }

  private _assertMetadataRevision(
    expected: object,
    operation: string,
  ): void {
    if (this._metadataRevision !== expected) {
      throw new Error(
        `${operation} became stale after UCAN metadata changed`,
      );
    }
  }

  private _isLocallyAuthorized(
    keyBase64: string,
    capability?: string,
  ): boolean {
    if (
      this._pendingRemovals.has(keyBase64) ||
      this._revokedKeys.has(keyBase64)
    ) {
      return false;
    }
    if (this._failedAdditions.has(keyBase64)) {
      return false;
    }
    const entry = this._entries.get(keyBase64);
    if (entry) {
      return (
        capability === undefined ||
        entry.capabilities.some((held) => capabilityImplies(held, capability))
      );
    }
    if (
      this._pendingAdditions.has(keyBase64) ||
      this._pendingGrants.has(keyBase64)
    ) {
      return false;
    }
    return true;
  }

  async add(publicKey: PublicKey): Promise<ChangesType> {
    return this._startMembershipMutation(
      publicKey,
      'ACL addition',
      async (snapshot) => {
        const preservePriorEntry = await this._hasStablePriorEntry(
          snapshot.publicKey,
          snapshot.keyBase64,
          'ACL addition',
        );
        let metadataRevision!: object;
        const changes = await this._runBackingMutation(() => {
          if (!preservePriorEntry) {
            this._quarantineAddition(snapshot.keyBase64);
          }
          metadataRevision = this._metadataRevision;
          return this._backing.add(snapshot.publicKey);
        });
        this._assertMetadataRevision(metadataRevision, 'ACL addition');
        this._revokedKeys.delete(snapshot.keyBase64);
        this._failedAdditions.delete(snapshot.keyBase64);
        this._markMetadataMutation();
        return changes;
      },
      (snapshot) => this._reservePendingAddition(snapshot.keyBase64),
    );
  }

  async remove(publicKey: PublicKey): Promise<ChangesType> {
    return this._startMembershipMutation(
      publicKey,
      'ACL removal',
      (snapshot) => this._removeSnapshot(snapshot),
      (snapshot) => this._reservePendingRemoval(snapshot.keyBase64),
    );
  }

  private async _removeSnapshot(snapshot: {
    publicKey: PublicKey;
    keyBase64: string;
  }): Promise<ChangesType> {
    const prepareRemove = this._backing.prepareRemove;
    if (typeof prepareRemove === 'function') {
      const prepared = await this._prepareBackingRemoval(
        snapshot.publicKey,
        snapshot.keyBase64,
        prepareRemove,
        true,
      );
      prepared.commit();
      return prepared.changes;
    }

    const changes = await this._runBackingMutation(() =>
      this._backing.remove(snapshot.publicKey),
    );
    this._revokedKeys.add(snapshot.keyBase64);
    this._failedAdditions.delete(snapshot.keyBase64);
    this._entries.delete(snapshot.keyBase64);
    this._markMetadataMutation();
    return changes;
  }

  async prepareRemove(
    publicKey: PublicKey,
  ): Promise<PreparedACLRemoval<ChangesType>> {
    this._assertHealthy('Prepared ACL removal');
    const prepareRemove = this._backing.prepareRemove;
    if (typeof prepareRemove !== 'function') {
      throw new Error('Backing ACL does not support staged removal');
    }
    const snapshot = await this._snapshotPublicKey(
      publicKey,
      'Prepared ACL removal',
    );
    this._assertHealthy('Prepared ACL removal');
    return this._prepareBackingRemoval(
      snapshot.publicKey,
      snapshot.keyBase64,
      prepareRemove,
    );
  }

  private async _prepareBackingRemoval(
    publicKey: PublicKey,
    keyBase64: string,
    prepareRemove: NonNullable<ACL<ChangesType, PublicKey>['prepareRemove']>,
    allowActiveMutation = false,
  ): Promise<PreparedACLRemoval<ChangesType>> {
    this._assertHealthy('Prepared ACL removal');
    const metadataRevision = this._metadataRevision;
    const backingRevision = this._backingRevision;
    const prepared = await prepareRemove.call(this._backing, publicKey);
    this._assertHealthy('Prepared ACL removal');
    this._assertMetadataRevision(metadataRevision, 'Prepared ACL removal');
    if (this._backingRevision !== backingRevision) {
      throw new Error(
        'Prepared ACL removal became stale after backing ACL changed',
      );
    }
    let committed = false;
    return {
      changes: prepared.changes,
      commit: () => {
        this._assertHealthy('Prepared ACL removal');
        if (committed) {
          throw new Error('Prepared ACL removal was already committed');
        }
        if (!allowActiveMutation) {
          this._assertPublicOperationAvailable(
            'Prepared ACL removal commit',
          );
        }
        this._assertMetadataRevision(metadataRevision, 'Prepared ACL removal');
        if (this._backingRevision !== backingRevision) {
          throw new Error(
            'Prepared ACL removal became stale after backing ACL changed',
          );
        }
        try {
          prepared.commit();
        } finally {
          this._markBackingMutation();
        }
        this._revokedKeys.add(keyBase64);
        this._failedAdditions.delete(keyBase64);
        this._entries.delete(keyBase64);
        this._markMetadataMutation();
        committed = true;
      },
    };
  }

  current(): ChangesType {
    this._assertPublicOperationAvailable('ACL current-state read');
    if (this._failedAdditions.size !== 0) {
      throw new Error(
        'ACL current-state read is unavailable while an unproven backing addition is quarantined',
      );
    }
    return this._invokeSynchronousBacking(
      () => this._backing.current(),
      'Backing ACL current-state read',
    );
  }

  /**
   * Apply remote membership only while no local mutation is admitted or
   * executing. Callers must retry the same changes after the local operation
   * settles when this method rejects.
   */
  merge(changes: ChangesType): void {
    this._assertPublicOperationAvailable('ACL merge');
    const finishBackingOperation = this._beginBackingOperation();
    try {
      this._invokeSynchronousBacking(
        () => this._backing.merge(changes),
        'Backing ACL merge',
      );
    } catch (error) {
      this._backingStateUncertain = true;
      if (error instanceof ACLOperationInProgressError) {
        throw new Error(
          'Backing ACL merge reported a retry conflict after invocation; backing state is uncertain',
        );
      }
      throw error;
    } finally {
      this._markBackingMutation();
      finishBackingOperation();
    }
  }

  async check(publicKey: PublicKey, capability?: string): Promise<boolean> {
    return this._runPublicOperation('ACL check', async () => {
      const snapshot = await this._snapshotPublicKey(
        publicKey,
        'ACL check',
      );
      for (
        let attempt = 0;
        attempt < MAX_STABLE_READ_ATTEMPTS;
        attempt++
      ) {
        this._assertBackingOperationAvailable('ACL check');
        if (this._pendingRemovals.has(snapshot.keyBase64)) {
          return false;
        }

        const backingRevision = this._backingRevision;
        const metadataRevision = this._metadataRevision;
        const isMember =
          (await this._runBackingRead(() =>
            this._backing.check(snapshot.publicKey),
          )) === true;
        this._assertBackingOperationAvailable('ACL check');
        if (
          this._backingRevision !== backingRevision ||
          this._metadataRevision !== metadataRevision
        ) {
          continue;
        }
        if (!isMember) {
          return false;
        }

        return this._isLocallyAuthorized(snapshot.keyBase64, capability);
      }
      throw new Error(
        `ACL check remained stale after ${MAX_STABLE_READ_ATTEMPTS} attempts`,
      );
    });
  }

  async users(capability?: string): Promise<PublicKey[]> {
    return this._runPublicOperation('ACL listing', async () => {
      for (
        let attempt = 0;
        attempt < MAX_STABLE_READ_ATTEMPTS;
        attempt++
      ) {
        this._assertBackingOperationAvailable('ACL listing');
        const backingRevision = this._backingRevision;
        const metadataRevision = this._metadataRevision;
        const allUsers = await this._runBackingRead(() =>
          this._backing.users(),
        );
        this._assertBackingOperationAvailable('ACL listing');
        if (
          this._backingRevision !== backingRevision ||
          this._metadataRevision !== metadataRevision
        ) {
          continue;
        }
        const snapshotTasks: Array<
          Promise<{ publicKey: PublicKey; keyBase64: string }>
        > = [];
        let enumerationFailed = false;
        let enumerationError: unknown;
        try {
          const isArray = reflectApply(arrayIsArray, Array, [
            allUsers,
          ]) as boolean;
          const length = isArray
            ? reflectGet(allUsers, 'length')
            : undefined;
          if (
            !isArray ||
            !Number.isSafeInteger(length) ||
            (length as number) < 0
          ) {
            throw new TypeError(
              'Backing ACL listing must return a stable array',
            );
          }
          if ((length as number) > MAX_UCAN_ACL_LISTING_IDENTITIES) {
            throw new RangeError(
              `Backing ACL listing exceeds ${MAX_UCAN_ACL_LISTING_IDENTITIES} identities`,
            );
          }
          for (let index = 0; index < (length as number); index++) {
            const user = reflectGet(allUsers, String(index)) as PublicKey;
            snapshotTasks.push(
              this._snapshotListedPublicKey(
                user,
                'ACL listing',
                backingRevision,
              ),
            );
          }
        } catch (error) {
          enumerationFailed = true;
          enumerationError = error;
        }
        const snapshotResults = await Promise.allSettled(snapshotTasks);
        if (enumerationFailed) throw enumerationError;
        for (const result of snapshotResults) {
          if (result.status === 'rejected') throw result.reason;
        }
        const snapshots = snapshotResults.map((result) => {
          if (result.status !== 'fulfilled') {
            throw new Error('ACL listing identity snapshot did not settle');
          }
          return result.value;
        });
        this._assertBackingOperationAvailable('ACL listing');
        if (
          this._backingRevision !== backingRevision ||
          this._metadataRevision !== metadataRevision
        ) {
          continue;
        }
        return snapshots
          .filter(({ keyBase64 }) =>
            this._isLocallyAuthorized(keyBase64, capability),
          )
          .map(({ publicKey }) => publicKey);
      }
      throw new Error(
        `ACL listing remained stale after ${MAX_STABLE_READ_ATTEMPTS} attempts`,
      );
    });
  }

  /**
   * Grant a capability to a user via UCAN delegation.
   */
  async grant(
    publicKey: PublicKey,
    capability: DocumentCapability,
    documentId: string,
    issuerPrivateKey: CryptoKey,
    issuerPublicKeyBase64: string,
    proofs: string[] = [],
    epochId?: Uint8Array,
  ): Promise<ChangesType> {
    let stableProofs!: string[];
    let stableEpochId: Uint8Array | undefined;
    return this._startMembershipMutation(
      publicKey,
      'Capability grant',
      async (snapshot) => {
        const ucan = await createUCAN(
          issuerPrivateKey,
          issuerPublicKeyBase64,
          snapshot.keyBase64,
          [{ resource: documentId, ability: capability }],
          stableProofs,
        );
        const entry = copyUCANEntry({
          publicKeyBase64: snapshot.keyBase64,
          ucan,
          capabilities: [capability],
          grantedBy: issuerPublicKeyBase64,
          epochId: stableEpochId,
          revoked: false,
        });
        const preservePriorEntry = await this._hasStablePriorEntry(
          snapshot.publicKey,
          snapshot.keyBase64,
          'Capability grant',
        );
        let additionMetadataRevision!: object;
        const changes = await this._runBackingMutation(() => {
          if (!preservePriorEntry) {
            this._quarantineAddition(snapshot.keyBase64);
          }
          additionMetadataRevision = this._metadataRevision;
          return this._backing.add(snapshot.publicKey);
        });
        this._assertMetadataRevision(
          additionMetadataRevision,
          'Capability grant',
        );
        this._revokedKeys.delete(snapshot.keyBase64);
        this._failedAdditions.delete(snapshot.keyBase64);
        this._entries.set(snapshot.keyBase64, entry);
        this._markMetadataMutation();
        return changes;
      },
      (snapshot) => {
        if (this._pendingGrants.has(snapshot.keyBase64)) {
          throw new Error(
            'A capability grant for this user is already in progress',
          );
        }
        this._pendingGrants.add(snapshot.keyBase64);
        return () => this._pendingGrants.delete(snapshot.keyBase64);
      },
      () => {
        stableProofs = [...proofs];
        stableEpochId = copyOptionalEpochId(epochId);
      },
    );
  }

  /**
   * Revoke a user's access. This invalidates their UCAN and all downstream delegations.
   */
  async revoke(publicKey: PublicKey): Promise<ChangesType> {
    return this.remove(publicKey);
  }

  /**
   * Get the ACL entry for a specific user.
   */
  async getEntry(publicKey: PublicKey): Promise<UCANACLEntry | undefined> {
    return this._runPublicOperation('ACL entry lookup', async () => {
      const snapshot = await this._snapshotPublicKey(
        publicKey,
        'ACL entry lookup',
      );
      this._assertBackingOperationAvailable('ACL entry lookup');
      const entry = this._entries.get(snapshot.keyBase64);
      return entry && copyUCANEntry(entry);
    });
  }
}

/**
 * Provider for UCAN-based ACLs. The codec has the same canonical,
 * collision-free, synchronous-capture and detached-deserialization contract
 * described by {@link UCANACL}. Supply `deserializePublicKey` whenever
 * `PublicKey` is mutable; UCAN metadata transitions fail closed without it.
 */
export class UCANACLProvider<ChangesType, PublicKey> implements ACLProvider<ChangesType, PublicKey> {
  private readonly _initializedBackings = new WeakSet<object>();

  constructor(
    private readonly _backingAclProvider: ACLProvider<ChangesType, PublicKey>,
    private readonly _serializePublicKey: (key: PublicKey) => Promise<string>,
    private readonly _deserializePublicKey?: (
      serialized: string,
    ) => Promise<PublicKey>,
  ) {}

  initialize(): UCANACL<ChangesType, PublicKey> {
    const backingAcl = this._backingAclProvider.initialize();
    if (this._initializedBackings.has(backingAcl)) {
      throw new Error(
        'Backing ACL provider returned a shared instance; initialize() must return isolated ACL state',
      );
    }
    this._initializedBackings.add(backingAcl);
    return new UCANACL(
      backingAcl,
      this._serializePublicKey,
      this._deserializePublicKey,
    );
  }
}
