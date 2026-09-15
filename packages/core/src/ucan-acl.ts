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
  private _metadataRevisions: Map<string, object> = new Map();
  private _pendingGrants: Set<string> = new Set();
  private _membershipMutationTail: Promise<void> = Promise.resolve();
  private _membershipAdmissionTail: Promise<void> = Promise.resolve();
  private _pendingMembershipMutations = 0;

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
        releaseReservation = reserve?.(stableSnapshot);
        queued = this._runMembershipMutation(
          () => operation(stableSnapshot),
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

  private _markMetadataMutation(keyBase64: string): void {
    this._metadataRevisions.set(keyBase64, {});
  }

  private _assertMetadataRevision(
    keyBase64: string,
    expected: object | undefined,
    operation: string,
  ): void {
    if (this._metadataRevisions.get(keyBase64) !== expected) {
      throw new Error(
        `${operation} became stale after UCAN metadata changed`,
      );
    }
  }

  async add(publicKey: PublicKey): Promise<ChangesType> {
    return this._startMembershipMutation(
      publicKey,
      'ACL addition',
      async (snapshot) => {
        const metadataRevision = this._metadataRevisions.get(
          snapshot.keyBase64,
        );
        const changes = await this._backing.add(snapshot.publicKey);
        this._assertMetadataRevision(
          snapshot.keyBase64,
          metadataRevision,
          'ACL addition',
        );
        this._revokedKeys.delete(snapshot.keyBase64);
        this._markMetadataMutation(snapshot.keyBase64);
        return changes;
      },
    );
  }

  async remove(publicKey: PublicKey): Promise<ChangesType> {
    return this._startMembershipMutation(
      publicKey,
      'ACL removal',
      async (snapshot) => {
        const changes = await this._backing.remove(snapshot.publicKey);
        this._revokedKeys.add(snapshot.keyBase64);
        this._entries.delete(snapshot.keyBase64);
        this._markMetadataMutation(snapshot.keyBase64);
        return changes;
      },
    );
  }

  current(): ChangesType {
    return this._backing.current();
  }

  /**
   * Apply remote membership only while no local mutation is admitted or
   * executing. Callers must retry the same changes after the local operation
   * settles when this method rejects.
   */
  merge(changes: ChangesType): void {
    if (this._pendingMembershipMutations !== 0) {
      throw new Error(
        'Cannot merge ACL changes while a local membership mutation is pending',
      );
    }
    this._backing.merge(changes);
  }

  async check(publicKey: PublicKey, capability?: string): Promise<boolean> {
    const snapshot = await this._snapshotPublicKey(publicKey, 'ACL check');

    if ((await this._backing.check(snapshot.publicKey)) !== true) {
      return false;
    }

    if (this._pendingGrants.has(snapshot.keyBase64)) {
      return false;
    }

    // Check if revoked
    if (this._revokedKeys.has(snapshot.keyBase64)) {
      return false;
    }

    if (!capability) {
      return true;
    }

    const entry = this._entries.get(snapshot.keyBase64);
    if (!entry) {
      // Backwards compatibility for members added through the basic ACL API.
      return true;
    }

    // Check if any held capability implies the required one
    return entry.capabilities.some(held => capabilityImplies(held, capability));
  }

  async users(capability?: string): Promise<PublicKey[]> {
    const allUsers = await this._backing.users();

    const filtered: PublicKey[] = [];
    for (const user of allUsers) {
      if ((await this.check(user, capability)) === true) {
        filtered.push(user);
      }
    }
    return filtered;
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
        const metadataRevision = this._metadataRevisions.get(
          snapshot.keyBase64,
        );
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
        const changes = await this._backing.add(snapshot.publicKey);
        this._assertMetadataRevision(
          snapshot.keyBase64,
          metadataRevision,
          'Capability grant',
        );
        this._revokedKeys.delete(snapshot.keyBase64);
        this._entries.set(snapshot.keyBase64, entry);
        this._markMetadataMutation(snapshot.keyBase64);
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
    const keyBase64 = await this._serializePublicKey(publicKey);
    if (typeof keyBase64 !== 'string' || keyBase64.length === 0) {
      throw new TypeError(
        'ACL lookup requires a non-empty canonical public-key encoding',
      );
    }
    const entry = this._entries.get(keyBase64);
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
