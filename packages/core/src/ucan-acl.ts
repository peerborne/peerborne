import {
  ACL,
  ACLOperationInProgressError,
  PreparedACLChange,
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
const MAX_BACKING_PROPERTY_PROTOTYPE_DEPTH = 32;
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
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const nativeObjectConstructor = Object;
const nativeObjectPrototype = Object.prototype;
const nativeFunctionPrototype = Function.prototype;
const reflectApply = Reflect.apply;
const reflectGet = Reflect.get;
const emptyBackingArguments: never[] = [];
const nativePromiseConstructor = Promise;
const nativePromisePrototype = Promise.prototype;
const promiseThen = Promise.prototype.then;
const nativePromiseSpeciesDescriptor = objectGetOwnPropertyDescriptor(
  nativePromiseConstructor,
  Symbol.species,
);
const ignorePromiseSettlement = (_value: unknown): undefined => undefined;
const ignoredPromiseSettlementArguments = [
  ignorePromiseSettlement,
  ignorePromiseSettlement,
];

function observeNativePromiseSettlement(value: object): boolean {
  try {
    void reflectApply(
      promiseThen,
      value,
      ignoredPromiseSettlementArguments,
    );
    return true;
  } catch {
    // Non-native thenables are never assimilated.
    return false;
  }
}

interface CachedListingIdentity<PublicKey> {
  readonly backingRevision: object;
  readonly template: PublicKey;
}

interface CapturedBackingFinalizer {
  readonly receiver: object;
  readonly method: (...args: never[]) => unknown;
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
 * A backing commit claim consumed by this wrapper must be a plain record whose
 * immediate prototype is `Object.prototype` or `null`. Class instances are
 * rejected so a custom constructor or Promise species hook cannot disguise an
 * asynchronous claim as a synchronous record.
 * Backing `current()` remains an opaque generic value for compatibility. Its
 * synchronous contract is mandatory: runtime checks detect ordinary native
 * Promises and visible thenables, but JavaScript exposes no hook-free Promise
 * brand predicate for an object with deliberately forged prototype and
 * constructor state.
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
  private _backingReentryAttempts = 0;
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
      this._backingReentryAttempts++;
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
    resultPolicy: 'opaque' | 'plain-claim' | 'void' = 'opaque',
  ): T {
    return this._invokeBacking(() => {
      const result = operation();
      if (resultPolicy === 'void') {
        if (result !== undefined) {
          this._backingSyncContractViolated = true;
          if (
            (typeof result === 'object' && result !== null) ||
            typeof result === 'function'
          ) {
            this._observeInvalidNativePromiseReturn(
              result,
              `${operationName} result`,
            );
          }
          throw new TypeError(`${operationName} must complete synchronously`);
        }
        return result;
      }

      const requirePlainClaimResult = resultPolicy === 'plain-claim';
      let hasThenProperty = false;
      let then: unknown;
      let isNativePromise = false;
      if (
        (typeof result === 'object' && result !== null) ||
        typeof result === 'function'
      ) {
        let plainClaimPrototype: object | null | undefined;
        if (requirePlainClaimResult) {
          try {
            plainClaimPrototype = reflectApply(objectGetPrototypeOf, Object, [
              result,
            ]) as object | null;
          } catch {
            this._backingSyncContractViolated = true;
            throw new TypeError(
              `${operationName} returned an invalid claim record`,
            );
          }
          if (
            plainClaimPrototype !== null &&
            plainClaimPrototype !== nativeObjectPrototype &&
            plainClaimPrototype !== nativePromisePrototype
          ) {
            this._backingSyncContractViolated = true;
            throw new TypeError(
              `${operationName} returned an invalid asynchronous result: expected a plain claim record`,
            );
          }
        }
        try {
          const thenProperty = this._backingDataProperty(
            result,
            'then',
            `${operationName} result then`,
          );
          hasThenProperty = thenProperty.found;
          then = thenProperty.value;
        } catch {
          this._backingSyncContractViolated = true;
          this._observeInvalidNativePromiseReturn(
            result,
            `${operationName} result`,
          );
          throw new TypeError(
            `${operationName} returned an invalid asynchronous result`,
          );
        }
        let observationIsSafe = false;
        try {
          observationIsSafe = this._canSafelyObserveNativePromise(
            result,
            `${operationName} result`,
          );
        } catch {
          if (requirePlainClaimResult) {
            this._backingSyncContractViolated = true;
            this._observeInvalidNativePromiseReturn(
              result,
              `${operationName} result`,
            );
            throw new TypeError(
              `${operationName} returned an invalid asynchronous result`,
            );
          }
        }
        if (requirePlainClaimResult && !hasThenProperty && !observationIsSafe) {
          this._backingSyncContractViolated = true;
          this._observeInvalidNativePromiseReturn(
            result,
            `${operationName} result`,
          );
          throw new TypeError(
            `${operationName} returned an invalid asynchronous result`,
          );
        }
        if (observationIsSafe) {
          // The captured intrinsic checks the internal Promise brand without
          // assimilating a custom thenable. Attempt it for every object whose
          // species path is known to be hook-free. Plain claim results fail
          // closed when that proof is unavailable; opaque current-state reads
          // retain arbitrary synchronous ChangesType compatibility and rely
          // on the provider contract for deliberately ambiguous object shapes.
          isNativePromise = observeNativePromiseSettlement(result);
        }
        if (
          requirePlainClaimResult &&
          !isNativePromise &&
          plainClaimPrototype === nativePromisePrototype
        ) {
          this._backingSyncContractViolated = true;
          throw new TypeError(
            `${operationName} returned an invalid asynchronous result: expected a plain claim record`,
          );
        }
      }
      if (
        isNativePromise ||
        (requirePlainClaimResult
          ? hasThenProperty
          : typeof then === 'function')
      ) {
        // Custom thenables are never invoked by this wrapper. Native async
        // work may already be scheduled and must find later operations closed.
        this._backingSyncContractViolated = true;
        if (
          !isNativePromise &&
          ((typeof result === 'object' && result !== null) ||
            typeof result === 'function')
        ) {
          this._observeInvalidNativePromiseReturn(
            result,
            `${operationName} result`,
          );
        }
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

  private async _runBackingPreparation<T>(
    operation: () => Promise<T>,
    onInvokedFailure?: () => void,
  ): Promise<{ result: T; backingRevision: object }> {
    this._assertBackingOperationAvailable('ACL backing preparation');
    const finishBackingOperation = this._beginBackingOperation();
    let result!: T;
    let backingRevision!: object;
    try {
      result = await this._invokeBacking(operation);
    } catch (error) {
      const foreignConflict = this._isForeignOperationConflict(error);
      if (!foreignConflict) {
        onInvokedFailure?.();
      }
      if (
        error instanceof ACLOperationInProgressError &&
        !foreignConflict
      ) {
        throw new Error(
          'Backing ACL preparation cannot reenter this UCAN ACL while its preparation is unresolved',
        );
      }
      throw error;
    } finally {
      // Rotate the revision even though the prepared operation must not change
      // live membership. This makes a later backing operation stale this
      // preparation and accounts for opaque private staging on every outcome.
      this._markBackingMutation();
      backingRevision = this._backingRevision;
      finishBackingOperation();
    }
    return { result, backingRevision };
  }

  private _runBackingInspection<T>(
    operationName: string,
    operation: () => T,
  ): T {
    return this._runBackingCapture(operationName, operation).result;
  }

  private _runBackingCapture<T>(
    operationName: string,
    operation: () => T,
    onInvokedFailure?: () => void,
  ): { result: T; backingRevision: object } {
    this._assertBackingOperationAvailable(operationName);
    const finishBackingOperation = this._beginBackingOperation();
    let result!: T;
    let backingRevision!: object;
    try {
      result = this._invokeBacking(operation);
    } catch (error) {
      onInvokedFailure?.();
      this._backingStateUncertain = true;
      if (error instanceof ACLOperationInProgressError) {
        throw new Error(
          `${operationName} reported a retry conflict after invocation; backing state is uncertain`,
        );
      }
      throw error;
    } finally {
      this._markBackingMutation();
      backingRevision = this._backingRevision;
      finishBackingOperation();
    }
    return { result, backingRevision };
  }

  private _backingPrepareAdd():
    | NonNullable<ACL<ChangesType, PublicKey>['prepareAdd']>
    | undefined {
    return this._runBackingInspection(
      'Backing ACL addition preparation lookup',
      () => {
        const property = this._backingDataProperty(
          this._backing,
          'prepareAdd',
          'Backing ACL prepareAdd',
        );
        if (!property.found) return undefined;
        const prepareAdd = property.value;
        if (prepareAdd === undefined) return undefined;
        if (typeof prepareAdd !== 'function') {
          throw new TypeError(
            'Backing ACL prepareAdd property must be a function when present',
          );
        }
        return prepareAdd as NonNullable<
          ACL<ChangesType, PublicKey>['prepareAdd']
        >;
      },
    );
  }

  private _backingPrepareRemove():
    | NonNullable<ACL<ChangesType, PublicKey>['prepareRemove']>
    | undefined {
    return this._runBackingInspection(
      'Backing ACL preparation lookup',
      () => {
        const property = this._backingDataProperty(
          this._backing,
          'prepareRemove',
          'Backing ACL prepareRemove',
        );
        if (!property.found) return undefined;
        const prepareRemove = property.value;
        if (prepareRemove === undefined) return undefined;
        if (typeof prepareRemove !== 'function') {
          throw new TypeError(
            'Backing ACL prepareRemove property must be a function when present',
          );
        }
        return prepareRemove as NonNullable<
          ACL<ChangesType, PublicKey>['prepareRemove']
        >;
      },
    );
  }

  private _backingDataProperty(
    target: object,
    property: PropertyKey,
    field: string,
  ): { readonly found: boolean; readonly value?: unknown } {
    let owner: object | null = target;
    const visited = new Set<object>();
    let depth = 0;
    while (owner !== null) {
      if (
        visited.has(owner) ||
        depth++ >= MAX_BACKING_PROPERTY_PROTOTYPE_DEPTH
      ) {
        throw new TypeError(`${field} has an invalid prototype chain`);
      }
      visited.add(owner);
      const descriptor = reflectApply(
        objectGetOwnPropertyDescriptor,
        Object,
        [owner, property],
      ) as PropertyDescriptor | undefined;
      if (descriptor !== undefined) {
        if (!('value' in descriptor)) {
          throw new TypeError(`${field} must be a data property`);
        }
        return { found: true, value: descriptor.value };
      }
      owner = reflectApply(objectGetPrototypeOf, Object, [owner]) as
        | object
        | null;
    }
    return { found: false };
  }

  /**
   * Promise.prototype.then performs species construction after its internal
   * Promise brand check. Preflight that later step without invoking accessors
   * or constructors so a hostile branded Promise cannot turn a species throw
   * into a false "not a Promise" result.
   */
  private _canSafelyObserveNativePromise(
    target: object,
    field: string,
  ): boolean {
    const constructorProperty = this._backingDataProperty(
      target,
      'constructor',
      `${field} constructor`,
    );
    if (
      !constructorProperty.found ||
      constructorProperty.value === undefined
    ) {
      return true;
    }
    const constructor = constructorProperty.value;
    if (
      (typeof constructor !== 'object' || constructor === null) &&
      typeof constructor !== 'function'
    ) {
      return false;
    }

    if (constructor === nativePromiseConstructor) {
      const currentSpeciesDescriptor = reflectApply(
        objectGetOwnPropertyDescriptor,
        Object,
        [nativePromiseConstructor, Symbol.species],
      ) as PropertyDescriptor | undefined;
      if (
        currentSpeciesDescriptor !== undefined &&
        !('value' in currentSpeciesDescriptor)
      ) {
        return (
          nativePromiseSpeciesDescriptor !== undefined &&
          !('value' in nativePromiseSpeciesDescriptor) &&
          currentSpeciesDescriptor.get ===
            nativePromiseSpeciesDescriptor.get &&
          currentSpeciesDescriptor.set ===
            nativePromiseSpeciesDescriptor.set
        );
      }
      const species = currentSpeciesDescriptor?.value;
      return (
        currentSpeciesDescriptor !== undefined &&
        (species === undefined ||
          species === null ||
          species === nativePromiseConstructor)
      );
    }

    // An arbitrary object or function can be a Proxy whose descriptor trap
    // reports a harmless data property while its ordinary `get` trap throws or
    // mutates state when Promise.prototype.then performs species lookup. Only
    // trust the captured intrinsic Object constructor and its pristine
    // prototype chain. Plain claim records use exactly this path; custom class
    // instances are rejected by the stricter claim-result policy.
    if (constructor !== nativeObjectConstructor) return false;
    if (
      reflectApply(objectGetPrototypeOf, Object, [
        nativeObjectConstructor,
      ]) !== nativeFunctionPrototype ||
      reflectApply(objectGetPrototypeOf, Object, [
        nativeFunctionPrototype,
      ]) !== nativeObjectPrototype ||
      reflectApply(objectGetPrototypeOf, Object, [nativeObjectPrototype]) !==
        null
    ) {
      return false;
    }
    for (const owner of [
      nativeObjectConstructor,
      nativeFunctionPrototype,
      nativeObjectPrototype,
    ]) {
      const descriptor = reflectApply(
        objectGetOwnPropertyDescriptor,
        Object,
        [owner, Symbol.species],
      ) as PropertyDescriptor | undefined;
      if (descriptor === undefined) continue;
      if (!('value' in descriptor)) return false;
      return (
        descriptor.value === undefined ||
        descriptor.value === null ||
        descriptor.value === nativePromiseConstructor
      );
    }
    return true;
  }

  /** Observe only a safely branded forbidden Promise return. */
  private _observeInvalidNativePromiseReturn(
    value: object,
    field: string,
  ): void {
    try {
      if (this._canSafelyObserveNativePromise(value, field)) {
        observeNativePromiseSettlement(value);
      }
    } catch {
      // The result is rejected below regardless; never invoke unsafe species
      // hooks merely to suppress a malicious provider's rejection.
    }
  }

  private _captureBackingPreparedChange(
    prepared: unknown,
    changeName: 'addition' | 'removal',
    onInvokedFailure?: () => void,
  ): {
    readonly result: {
      readonly changes: ChangesType;
      readonly commit: () => void;
      readonly claimCommit?: () => unknown;
    };
    readonly backingRevision: object;
  } {
    const preparedName = `prepared-${changeName}`;
    return this._runBackingCapture(
      `Backing ACL ${preparedName} capture`,
      () => {
        if (
          (typeof prepared !== 'object' || prepared === null) &&
          typeof prepared !== 'function'
        ) {
          throw new TypeError(
            `Backing ACL prepared ${changeName} must be an object`,
          );
        }
        const changesProperty = this._backingDataProperty(
          prepared,
          'changes',
          `Backing ACL ${preparedName} changes`,
        );
        if (!changesProperty.found) {
          throw new TypeError(
            `Backing ACL prepared ${changeName} must provide changes`,
          );
        }
        const commitProperty = this._backingDataProperty(
          prepared,
          'commit',
          `Backing ACL ${preparedName} commit`,
        );
        const commit = commitProperty.value;
        if (!commitProperty.found || typeof commit !== 'function') {
          throw new TypeError(
            `Backing ACL prepared ${changeName} must provide a commit function`,
          );
        }
        const claimProperty = this._backingDataProperty(
          prepared,
          'claimCommit',
          `Backing ACL ${preparedName} claimCommit`,
        );
        const claimCommit = claimProperty.value;
        if (
          claimProperty.found &&
          claimCommit !== undefined &&
          typeof claimCommit !== 'function'
        ) {
          throw new TypeError(
            `Backing ACL prepared ${changeName} claimCommit must be a function when present`,
          );
        }
        return {
          changes: changesProperty.value as ChangesType,
          commit: () => reflectApply(commit, prepared, []),
          claimCommit:
            typeof claimCommit === 'function'
              ? () => reflectApply(claimCommit, prepared, [])
              : undefined,
        };
      },
      onInvokedFailure,
    );
  }

  private _runBackingCommit(operation: () => void): void {
    this._assertBackingOperationAvailable('ACL backing commit');
    const finishBackingOperation = this._beginBackingOperation();
    try {
      this._invokeSynchronousBacking(
        operation,
        'Backing ACL commit',
        'void',
      );
    } catch (error) {
      this._backingStateUncertain = true;
      if (error instanceof ACLOperationInProgressError) {
        throw new Error(
          'Backing ACL commit reported a retry conflict after invocation; backing state is uncertain',
        );
      }
      throw error;
    } finally {
      this._markBackingMutation();
      finishBackingOperation();
    }
  }

  private _runBackingClaim(
    operation: () => unknown,
    changeName: 'addition' | 'removal',
  ): CapturedBackingFinalizer {
    const operationName = `Backing ACL ${changeName} commit claim`;
    this._assertBackingOperationAvailable(operationName);
    const finishBackingOperation = this._beginBackingOperation();
    const reentryAttempts = this._backingReentryAttempts;
    let rotateBackingRevision = true;
    try {
      let claim: unknown;
      try {
        claim = this._invokeSynchronousBacking(
          operation,
          operationName,
          'plain-claim',
        );
      } catch (error) {
        const foreignConflict = this._isForeignOperationConflict(error);
        if (
          foreignConflict &&
          this._backingReentryAttempts === reentryAttempts &&
          !this._backingSyncContractViolated
        ) {
          // The conflict class certifies rejection at the backing provider's
          // own pre-invocation boundary, so this exact stage may be retried.
          rotateBackingRevision = false;
        }
        if (
          this._backingReentryAttempts !== reentryAttempts ||
          this._backingSyncContractViolated ||
          (error instanceof ACLOperationInProgressError && !foreignConflict)
        ) {
          this._backingStateUncertain = true;
          if (error instanceof ACLOperationInProgressError) {
            throw new Error(
              `${operationName} reported a retry conflict after invocation; backing state is uncertain`,
            );
          }
        }
        throw error;
      }
      if (this._backingReentryAttempts !== reentryAttempts) {
        this._backingStateUncertain = true;
        throw new Error(
          `${operationName} attempted to reenter the UCAN ACL; backing state is uncertain`,
        );
      }

      try {
        const finalize = this._invokeBacking(() => {
          if (
            (typeof claim !== 'object' || claim === null) &&
            typeof claim !== 'function'
          ) {
            throw new TypeError(
              `Backing ACL ${changeName} commit claim must be an object`,
            );
          }
          const finalizeProperty = this._backingDataProperty(
            claim,
            'finalize',
            `Backing ACL ${changeName} commit claim finalizer`,
          );
          const capturedFinalize = finalizeProperty.value;
          if (
            !finalizeProperty.found ||
            typeof capturedFinalize !== 'function'
          ) {
            throw new TypeError(
              `Backing ACL ${changeName} commit claim must provide a finalize function`,
            );
          }
          return {
            receiver: claim,
            method: capturedFinalize as (...args: never[]) => unknown,
          };
        });
        if (this._backingReentryAttempts !== reentryAttempts) {
          throw new Error(
            `${operationName} attempted to reenter the UCAN ACL; backing state is uncertain`,
          );
        }
        return finalize;
      } catch (error) {
        this._backingStateUncertain = true;
        if (error instanceof ACLOperationInProgressError) {
          throw new Error(
            `${operationName} reported a retry conflict after returning a claim; backing state is uncertain`,
          );
        }
        throw error;
      }
    } finally {
      // A claim may reserve opaque private staged state even though it cannot
      // change live membership. Rotate after success and uncertified failures
      // so older stages and cached listings cannot survive that transition.
      if (rotateBackingRevision) this._markBackingMutation();
      finishBackingOperation();
    }
  }

  private _runBackingClaimFinalizer(
    finalizer: CapturedBackingFinalizer,
  ): void {
    const reentryAttempts = this._backingReentryAttempts;
    try {
      this._assertHealthy('Backing ACL commit claim finalizer');
      this._backingInvocationDepth++;
      let result: unknown;
      try {
        result = reflectApply(
          finalizer.method,
          finalizer.receiver,
          emptyBackingArguments,
        );
      } finally {
        this._backingInvocationDepth--;
      }
      if (result !== undefined) {
        this._backingSyncContractViolated = true;
        if (
          (typeof result === 'object' && result !== null) ||
          typeof result === 'function'
        ) {
          this._observeInvalidNativePromiseReturn(
            result,
            'Backing ACL commit claim finalizer result',
          );
        }
        throw new TypeError(
          'Backing ACL commit claim finalizer must complete synchronously without a return value',
        );
      }
      if (this._backingReentryAttempts !== reentryAttempts) {
        throw new Error(
          'Backing ACL commit claim finalizer attempted to reenter the UCAN ACL',
        );
      }
    } catch (error) {
      this._backingStateUncertain = true;
      if (error instanceof ACLOperationInProgressError) {
        throw new Error(
          'Backing ACL commit claim finalizer reported a retry conflict; backing state is uncertain',
        );
      }
      throw error;
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
        const prepareAdd = this._backingPrepareAdd();
        const preservePriorEntry = await this._hasStablePriorEntry(
          snapshot.publicKey,
          snapshot.keyBase64,
          'ACL addition',
        );
        if (typeof prepareAdd === 'function') {
          const prepared = await this._prepareBackingAddition(
            snapshot.publicKey,
            snapshot.keyBase64,
            prepareAdd,
            true,
            preservePriorEntry,
          );
          prepared.commit();
          return prepared.changes;
        }
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

  async prepareAdd(
    publicKey: PublicKey,
  ): Promise<PreparedACLChange<ChangesType>> {
    return this._startMembershipMutation(
      publicKey,
      'Prepared ACL addition',
      async (snapshot) => {
        const prepareAdd = this._backingPrepareAdd();
        if (typeof prepareAdd !== 'function') {
          throw new Error('Backing ACL does not support staged addition');
        }
        return this._prepareBackingAddition(
          snapshot.publicKey,
          snapshot.keyBase64,
          prepareAdd,
        );
      },
    );
  }

  private async _prepareBackingAddition(
    publicKey: PublicKey,
    keyBase64: string,
    prepareAdd: NonNullable<ACL<ChangesType, PublicKey>['prepareAdd']>,
    allowActiveMutation = false,
    preservePriorEntry?: boolean,
  ): Promise<PreparedACLChange<ChangesType>> {
    this._assertBackingOperationAvailable('Prepared ACL addition');
    preservePriorEntry ??= await this._hasStablePriorEntry(
      publicKey,
      keyBase64,
      'Prepared ACL addition',
    );
    this._assertBackingOperationAvailable('Prepared ACL addition');
    const metadataRevision = this._metadataRevision;
    const quarantineUnprovenAddition = preservePriorEntry
      ? undefined
      : () => this._quarantineAddition(keyBase64);
    const { result: prepared } = await this._runBackingPreparation(
      () => reflectApply(prepareAdd, this._backing, [publicKey]),
      quarantineUnprovenAddition,
    );
    const { result: captured, backingRevision } =
      this._captureBackingPreparedChange(
        prepared,
        'addition',
        quarantineUnprovenAddition,
      );
    this._assertBackingOperationAvailable('Prepared ACL addition');
    this._assertMetadataRevision(metadataRevision, 'Prepared ACL addition');
    if (this._backingRevision !== backingRevision) {
      throw new Error(
        'Prepared ACL addition became stale after backing ACL changed',
      );
    }
    const backingClaimCommit = captured.claimCommit;
    if (backingClaimCommit) {
      let state:
        | 'prepared'
        | 'claimed'
        | 'finalizing'
        | 'committed'
        | 'failed' = 'prepared';
      const claimCommit = () => {
        this._assertHealthy('Prepared ACL addition');
        if (state !== 'prepared') {
          throw new Error(
            'Prepared ACL addition was already committed or claimed',
          );
        }
        if (!allowActiveMutation) {
          this._assertPublicOperationAvailable(
            'Prepared ACL addition claim',
          );
        }
        this._assertMetadataRevision(metadataRevision, 'Prepared ACL addition');
        if (this._backingRevision !== backingRevision) {
          throw new Error(
            'Prepared ACL addition became stale after backing ACL changed',
          );
        }

        const committedRevokedKeys = new Set(this._revokedKeys);
        committedRevokedKeys.delete(keyBase64);
        const committedFailedAdditions = new Set(this._failedAdditions);
        committedFailedAdditions.delete(keyBase64);
        const committedMetadataRevision = {};
        const committedBackingRevision = {};
        const finalizeBacking = this._runBackingClaim(
          backingClaimCommit,
          'addition',
        );
        state = 'claimed';
        return {
          finalize: () => {
            if (state === 'committed') return;
            if (state !== 'claimed') {
              throw new Error(
                'Prepared ACL addition claim cannot be finalized',
              );
            }
            state = 'finalizing';
            try {
              this._runBackingClaimFinalizer(finalizeBacking);
            } catch (error) {
              this._backingRevision = committedBackingRevision;
              state = 'failed';
              throw error;
            }
            this._revokedKeys = committedRevokedKeys;
            this._failedAdditions = committedFailedAdditions;
            this._metadataRevision = committedMetadataRevision;
            this._backingRevision = committedBackingRevision;
            state = 'committed';
          },
        };
      };
      return {
        changes: captured.changes,
        claimCommit,
        commit: () => claimCommit().finalize(),
      };
    }
    let committed = false;
    return {
      changes: captured.changes,
      commit: () => {
        this._assertHealthy('Prepared ACL addition');
        if (committed) {
          throw new Error('Prepared ACL addition was already committed');
        }
        if (!allowActiveMutation) {
          this._assertPublicOperationAvailable(
            'Prepared ACL addition commit',
          );
        }
        this._assertMetadataRevision(metadataRevision, 'Prepared ACL addition');
        if (this._backingRevision !== backingRevision) {
          throw new Error(
            'Prepared ACL addition became stale after backing ACL changed',
          );
        }
        // Even a previously-valid capability is hidden for the duration of
        // the opaque commit. A contract-violating backing implementation can
        // otherwise remove and partially re-add that identity reentrantly
        // before throwing, reviving stale UCAN metadata.
        this._runBackingCommit(() => {
          // Quarantine only after the backing-commit preflight succeeds. A
          // busy/poisoned wrapper rejection is known to precede any backing
          // call and must leave wrapper metadata untouched.
          this._quarantineAddition(keyBase64);
          return captured.commit();
        });
        this._revokedKeys.delete(keyBase64);
        this._failedAdditions.delete(keyBase64);
        this._markMetadataMutation();
        committed = true;
      },
    };
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
    const prepareRemove = this._backingPrepareRemove();
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
    return this._startMembershipMutation(
      publicKey,
      'Prepared ACL removal',
      async (snapshot) => {
        const prepareRemove = this._backingPrepareRemove();
        if (typeof prepareRemove !== 'function') {
          throw new Error('Backing ACL does not support staged removal');
        }
        return this._prepareBackingRemoval(
          snapshot.publicKey,
          snapshot.keyBase64,
          prepareRemove,
        );
      },
    );
  }

  private async _prepareBackingRemoval(
    publicKey: PublicKey,
    keyBase64: string,
    prepareRemove: NonNullable<ACL<ChangesType, PublicKey>['prepareRemove']>,
    allowActiveMutation = false,
  ): Promise<PreparedACLRemoval<ChangesType>> {
    this._assertBackingOperationAvailable('Prepared ACL removal');
    const metadataRevision = this._metadataRevision;
    const { result: prepared } = await this._runBackingPreparation(() =>
      reflectApply(prepareRemove, this._backing, [publicKey]),
    );
    const { result: captured, backingRevision } =
      this._captureBackingPreparedChange(prepared, 'removal');
    this._assertBackingOperationAvailable('Prepared ACL removal');
    this._assertMetadataRevision(metadataRevision, 'Prepared ACL removal');
    if (this._backingRevision !== backingRevision) {
      throw new Error(
        'Prepared ACL removal became stale after backing ACL changed',
      );
    }
    const backingClaimCommit = captured.claimCommit;
    if (backingClaimCommit) {
      let state:
        | 'prepared'
        | 'claimed'
        | 'finalizing'
        | 'committed'
        | 'failed' = 'prepared';
      const claimCommit = () => {
        this._assertHealthy('Prepared ACL removal');
        if (state !== 'prepared') {
          throw new Error(
            'Prepared ACL removal was already committed or claimed',
          );
        }
        if (!allowActiveMutation) {
          this._assertPublicOperationAvailable(
            'Prepared ACL removal claim',
          );
        }
        this._assertMetadataRevision(metadataRevision, 'Prepared ACL removal');
        if (this._backingRevision !== backingRevision) {
          throw new Error(
            'Prepared ACL removal became stale after backing ACL changed',
          );
        }

        const committedRevokedKeys = new Set(this._revokedKeys);
        committedRevokedKeys.add(keyBase64);
        const committedFailedAdditions = new Set(this._failedAdditions);
        committedFailedAdditions.delete(keyBase64);
        const committedEntries = new Map(this._entries);
        committedEntries.delete(keyBase64);
        const committedMetadataRevision = {};
        const committedBackingRevision = {};
        const finalizeBacking = this._runBackingClaim(
          backingClaimCommit,
          'removal',
        );
        state = 'claimed';
        return {
          finalize: () => {
            if (state === 'committed') return;
            if (state !== 'claimed') {
              throw new Error(
                'Prepared ACL removal claim cannot be finalized',
              );
            }
            state = 'finalizing';
            try {
              this._runBackingClaimFinalizer(finalizeBacking);
            } catch (error) {
              this._backingRevision = committedBackingRevision;
              state = 'failed';
              throw error;
            }
            this._revokedKeys = committedRevokedKeys;
            this._failedAdditions = committedFailedAdditions;
            this._entries = committedEntries;
            this._metadataRevision = committedMetadataRevision;
            this._backingRevision = committedBackingRevision;
            state = 'committed';
          },
        };
      };
      return {
        changes: captured.changes,
        claimCommit,
        commit: () => claimCommit().finalize(),
      };
    }
    let committed = false;
    return {
      changes: captured.changes,
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
        this._runBackingCommit(captured.commit);
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
        'void',
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
