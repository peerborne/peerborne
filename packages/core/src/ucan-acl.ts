import { ACL } from './acl.js';
import { ACLProvider } from './acl-provider.js';
import { UCAN, createUCAN } from './ucan.js';
import { DocumentCapability, capabilityImplies } from './capabilities.js';

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

function copyUCANEntry(entry: UCANACLEntry): UCANACLEntry {
  return {
    ...entry,
    ucan: copyUCAN(entry.ucan),
    capabilities: [...entry.capabilities],
    epochId: entry.epochId && new Uint8Array(entry.epochId),
  };
}

const MAX_STABLE_USER_LISTING_ATTEMPTS = 3;

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
 * Backing membership mutations are globally FIFO, including mutations for
 * different identities. The generic ACL contract exposes one opaque mutable
 * state and does not promise key-isolated commits, so overlapping backing
 * calls could derive changes from the same document-wide baseline. Identity
 * codecs start eagerly, but invocation-order admission and backing execution
 * are global, so a slow earlier codec or backing call delays later mutations.
 * A backing mutation is hidden from reads while unresolved. Any rejected
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
 * canonical encoding. Primitive identities are immutable and remain supported
 * with the two-argument constructor.
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
  private _membershipMutationTail: Promise<void> = Promise.resolve();
  private _membershipAdmissionTail: Promise<void> = Promise.resolve();
  private _pendingMembershipMutations = 0;
  private _backingMutationsInFlight = 0;
  private _backingStateUncertain = false;

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
    const keyBase64 = await this._serializePublicKey(publicKey);
    if (typeof keyBase64 !== 'string' || keyBase64.length === 0) {
      throw new TypeError(
        `${operation} requires a non-empty canonical public-key encoding`,
      );
    }

    const mutableIdentity =
      (typeof publicKey === 'object' && publicKey !== null) ||
      typeof publicKey === 'function';
    if (!this._deserializePublicKey) {
      if (mutableIdentity) {
        throw new Error(
          `${operation} requires a public-key deserializer for mutable identities`,
        );
      }
      return { publicKey, keyBase64 };
    }

    const stablePublicKey = await this._deserializePublicKey(keyBase64);
    if (mutableIdentity && stablePublicKey === publicKey) {
      throw new Error(
        `${operation} requires the public-key deserializer to return a detached identity`,
      );
    }
    if ((await this._serializePublicKey(stablePublicKey)) !== keyBase64) {
      throw new Error(
        `${operation} rejected a non-canonical public-key round trip`,
      );
    }
    return { publicKey: stablePublicKey, keyBase64 };
  }

  /** Keep all backing membership and metadata transitions ordered. */
  private async _runMembershipMutation<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const previous = this._membershipMutationTail;
    let release!: () => void;
    const turn = new Promise<void>((resolve) => {
      release = resolve;
    });
    this._membershipMutationTail = turn;
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this._membershipMutationTail === turn) {
        this._membershipMutationTail = Promise.resolve();
      }
    }
  }

  /** Preserve invocation order while asynchronous codecs resolve. */
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
  ): Promise<T> {
    this._assertHealthy(operationName);
    const snapshot = this._snapshotPublicKey(publicKey, operationName);
    void snapshot.catch(() => undefined);
    const previousAdmission = this._membershipAdmissionTail;
    let releaseAdmission!: () => void;
    const admission = new Promise<void>((resolve) => {
      releaseAdmission = resolve;
    });
    this._membershipAdmissionTail = admission;
    this._pendingMembershipMutations++;

    const mutation = (async () => {
      await previousAdmission;
      let queued: Promise<T> | undefined;
      let releaseReservation: (() => void) | undefined;
      try {
        const stableSnapshot = await snapshot;
        this._assertHealthy(operationName);
        releaseReservation = reserve?.(stableSnapshot);
        queued = this._runMembershipMutation(
          () => {
            this._assertHealthy(operationName);
            return operation(stableSnapshot);
          },
        );
        if (releaseReservation) {
          queued = queued.finally(releaseReservation);
        }
      } finally {
        releaseAdmission();
      }
      return queued!;
    })();
    return mutation.finally(() => {
      this._pendingMembershipMutations--;
    });
  }

  private _markMetadataMutation(): void {
    this._metadataRevision = {};
  }

  private _markBackingMutation(): void {
    this._backingRevision = {};
  }

  private _assertHealthy(operation: string): void {
    if (this._backingStateUncertain) {
      throw new Error(
        `${operation} is unavailable because a failed ACL backing mutation may have ` +
          'partially changed backing membership',
      );
    }
  }

  private _assertReadable(operation: string): void {
    this._assertHealthy(operation);
    if (this._backingMutationsInFlight !== 0) {
      throw new Error(
        `${operation} is unavailable while an ACL backing mutation is in progress`,
      );
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
    const isMember = (await this._backing.check(publicKey)) === true;
    this._assertHealthy(operation);
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
    this._assertHealthy('ACL backing mutation');
    this._backingMutationsInFlight++;
    try {
      return await operation();
    } catch (error) {
      this._backingStateUncertain = true;
      throw error;
    } finally {
      // A rejected provider operation may still have changed opaque backing
      // state before reporting failure. Rotate the revision on every outcome
      // and keep all reads closed until an unresolved call has settled.
      this._backingMutationsInFlight--;
      this._markBackingMutation();
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
        if (!preservePriorEntry) {
          this._quarantineAddition(snapshot.keyBase64);
        }
        const metadataRevision = this._metadataRevision;
        const changes = await this._runBackingMutation(() =>
          this._backing.add(snapshot.publicKey),
        );
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
      async (snapshot) => {
        const changes = await this._runBackingMutation(() =>
          this._backing.remove(snapshot.publicKey),
        );
        this._revokedKeys.add(snapshot.keyBase64);
        this._failedAdditions.delete(snapshot.keyBase64);
        this._entries.delete(snapshot.keyBase64);
        this._markMetadataMutation();
        return changes;
      },
      (snapshot) => this._reservePendingRemoval(snapshot.keyBase64),
    );
  }

  current(): ChangesType {
    this._assertReadable('ACL current-state read');
    if (this._failedAdditions.size !== 0) {
      throw new Error(
        'ACL current-state read is unavailable while an unproven backing addition is quarantined',
      );
    }
    return this._backing.current();
  }

  /**
   * Apply remote membership only while no local mutation is admitted or
   * executing. Callers must retry the same changes after the local operation
   * settles when this method rejects.
   */
  merge(changes: ChangesType): void {
    this._assertHealthy('ACL merge');
    if (this._pendingMembershipMutations !== 0) {
      throw new Error(
        'Cannot merge ACL changes while a local membership mutation is pending',
      );
    }
    if (this._backingMutationsInFlight !== 0) {
      throw new Error(
        'Cannot merge ACL changes while a backing mutation is in progress',
      );
    }
    this._backingMutationsInFlight++;
    try {
      this._backing.merge(changes);
    } catch (error) {
      this._backingStateUncertain = true;
      throw error;
    } finally {
      this._backingMutationsInFlight--;
      this._markBackingMutation();
    }
  }

  async check(publicKey: PublicKey, capability?: string): Promise<boolean> {
    this._assertReadable('ACL check');
    const snapshot = await this._snapshotPublicKey(publicKey, 'ACL check');
    this._assertReadable('ACL check');

    if (this._pendingRemovals.has(snapshot.keyBase64)) {
      return false;
    }

    const backingRevision = this._backingRevision;
    const isMember = (await this._backing.check(snapshot.publicKey)) === true;
    this._assertReadable('ACL check');
    if (this._backingRevision !== backingRevision) {
      return false;
    }
    if (!isMember) {
      return false;
    }

    return this._isLocallyAuthorized(snapshot.keyBase64, capability);
  }

  async users(capability?: string): Promise<PublicKey[]> {
    for (
      let attempt = 0;
      attempt < MAX_STABLE_USER_LISTING_ATTEMPTS;
      attempt++
    ) {
      this._assertReadable('ACL listing');
      const backingRevision = this._backingRevision;
      const metadataRevision = this._metadataRevision;
      const allUsers = await this._backing.users();
      this._assertReadable('ACL listing');
      if (
        this._backingRevision !== backingRevision ||
        this._metadataRevision !== metadataRevision
      ) {
        continue;
      }
      const snapshots = await Promise.all(
        allUsers.map((user) => this._snapshotPublicKey(user, 'ACL listing')),
      );
      this._assertReadable('ACL listing');
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
      `ACL listing remained stale after ${MAX_STABLE_USER_LISTING_ATTEMPTS} attempts`,
    );
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
    const stableProofs = [...proofs];
    const stableEpochId = epochId && new Uint8Array(epochId);
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
        if (!preservePriorEntry) {
          this._quarantineAddition(snapshot.keyBase64);
        }
        const additionMetadataRevision = this._metadataRevision;
        const changes = await this._runBackingMutation(() =>
          this._backing.add(snapshot.publicKey),
        );
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
    this._assertReadable('ACL entry lookup');
    const snapshot = await this._snapshotPublicKey(
      publicKey,
      'ACL entry lookup',
    );
    this._assertReadable('ACL entry lookup');
    const entry = this._entries.get(snapshot.keyBase64);
    return entry && copyUCANEntry(entry);
  }
}

/**
 * Provider for UCAN-based ACLs. The codec has the same canonical,
 * collision-free, synchronous-capture and detached-deserialization contract
 * described by {@link UCANACL}. Supply `deserializePublicKey` whenever
 * `PublicKey` is mutable; UCAN metadata transitions fail closed without it.
 */
export class UCANACLProvider<ChangesType, PublicKey> implements ACLProvider<ChangesType, PublicKey> {
  constructor(
    private readonly _backingAclProvider: ACLProvider<ChangesType, PublicKey>,
    private readonly _serializePublicKey: (key: PublicKey) => Promise<string>,
    private readonly _deserializePublicKey?: (
      serialized: string,
    ) => Promise<PublicKey>,
  ) {}

  initialize(): UCANACL<ChangesType, PublicKey> {
    const backingAcl = this._backingAclProvider.initialize();
    return new UCANACL(
      backingAcl,
      this._serializePublicKey,
      this._deserializePublicKey,
    );
  }
}
