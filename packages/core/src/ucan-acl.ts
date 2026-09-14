import { ACL, PreparedACLChange } from './acl.js';
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
 * locally even while a stale metadata entry remains cached. A later remote
 * re-add can reactivate that cached metadata, so this wrapper does not provide
 * distributed strong-removal semantics by itself.
 */
export class UCANACL<ChangesType, PublicKey> implements ACL<ChangesType, PublicKey> {
  private _entries: Map<string, UCANACLEntry> = new Map(); // publicKeyBase64 -> entry
  private _revokedKeys: Set<string> = new Set(); // set of revoked public key base64 strings
  private _pendingGrants: Set<string> = new Set();

  // Private backing ACL so membership checks cannot bypass the wrapper's
  // capability and local-revocation gates.
  constructor(
    private readonly _backing: ACL<ChangesType, PublicKey>,
    private readonly _serializePublicKey: (key: PublicKey) => Promise<string>,
  ) {}

  async add(publicKey: PublicKey): Promise<ChangesType> {
    const keyBase64 = await this._serializePublicKey(publicKey);
    const prepareAdd = this._backing.prepareAdd;
    let changes: ChangesType;
    if (typeof prepareAdd === 'function') {
      const prepared = await this._prepareBackingAddition(
        publicKey,
        keyBase64,
        prepareAdd,
      );
      prepared.commit();
      return prepared.changes;
    }
    changes = await this._backing.add(publicKey);
    // A successful local add is an explicit reauthorization. Clear a local
    // tombstone only after backing membership exists; failed adds must remain
    // revoked.
    this._revokedKeys.delete(keyBase64);
    return changes;
  }

  async prepareAdd(
    publicKey: PublicKey,
  ): Promise<PreparedACLChange<ChangesType>> {
    const prepareAdd = this._backing.prepareAdd;
    if (typeof prepareAdd !== 'function') {
      throw new Error('Backing ACL does not support staged addition');
    }
    const keyBase64 = await this._serializePublicKey(publicKey);
    return this._prepareBackingAddition(publicKey, keyBase64, prepareAdd);
  }

  private async _prepareBackingAddition(
    publicKey: PublicKey,
    keyBase64: string,
    prepareAdd: NonNullable<ACL<ChangesType, PublicKey>['prepareAdd']>,
  ): Promise<PreparedACLChange<ChangesType>> {
    const prepared = await prepareAdd.call(this._backing, publicKey);
    let committed = false;
    return {
      changes: prepared.changes,
      commit: () => {
        if (committed) {
          throw new Error('Prepared ACL addition was already committed');
        }
        prepared.commit();
        this._revokedKeys.delete(keyBase64);
        committed = true;
      },
    };
  }

  async remove(publicKey: PublicKey): Promise<ChangesType> {
    const keyBase64 = await this._serializePublicKey(publicKey);
    const prepareRemove = this._backing.prepareRemove;
    if (typeof prepareRemove === 'function') {
      const prepared = await this._prepareBackingRemoval(
        publicKey,
        keyBase64,
        prepareRemove,
      );
      prepared.commit();
      return prepared.changes;
    }

    const changes = await this._backing.remove(publicKey);
    this._revokedKeys.add(keyBase64);
    this._entries.delete(keyBase64);
    return changes;
  }

  async prepareRemove(
    publicKey: PublicKey,
  ): Promise<PreparedACLChange<ChangesType>> {
    const prepareRemove = this._backing.prepareRemove;
    if (typeof prepareRemove !== 'function') {
      throw new Error('Backing ACL does not support staged removal');
    }
    const keyBase64 = await this._serializePublicKey(publicKey);
    return this._prepareBackingRemoval(publicKey, keyBase64, prepareRemove);
  }

  private async _prepareBackingRemoval(
    publicKey: PublicKey,
    keyBase64: string,
    prepareRemove: NonNullable<ACL<ChangesType, PublicKey>['prepareRemove']>,
  ): Promise<PreparedACLChange<ChangesType>> {
    const prepared = await prepareRemove.call(this._backing, publicKey);
    let committed = false;
    return {
      changes: prepared.changes,
      commit: () => {
        if (committed) {
          throw new Error('Prepared ACL removal was already committed');
        }
        prepared.commit();
        this._revokedKeys.add(keyBase64);
        this._entries.delete(keyBase64);
        committed = true;
      },
    };
  }

  current(): ChangesType {
    return this._backing.current();
  }

  merge(changes: ChangesType): void {
    this._backing.merge(changes);
  }

  async check(publicKey: PublicKey, capability?: string): Promise<boolean> {
    if (!capability) {
      return (await this._backing.check(publicKey)) === true;
    }

    const keyBase64 = await this._serializePublicKey(publicKey);

    if ((await this._backing.check(publicKey)) !== true) {
      return false;
    }

    if (this._pendingGrants.has(keyBase64)) {
      return false;
    }

    // Check if revoked
    if (this._revokedKeys.has(keyBase64)) {
      return false;
    }

    const entry = this._entries.get(keyBase64);
    if (!entry) {
      // Backwards compatibility for members added through the basic ACL API.
      return true;
    }

    // Check if any held capability implies the required one
    return entry.capabilities.some(held => capabilityImplies(held, capability));
  }

  async users(capability?: string): Promise<PublicKey[]> {
    const allUsers = await this._backing.users();

    if (!capability) {
      return allUsers;
    }

    // Filter users by capability
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
    const keyBase64 = await this._serializePublicKey(publicKey);

    if (this._pendingGrants.has(keyBase64)) {
      throw new Error('A capability grant for this user is already in progress');
    }
    this._pendingGrants.add(keyBase64);

    try {
      const ucan = await createUCAN(
        issuerPrivateKey,
        issuerPublicKeyBase64,
        keyBase64,
        [{ resource: documentId, ability: capability }],
        stableProofs,
      );
      const entry = copyUCANEntry({
        publicKeyBase64: keyBase64,
        ucan,
        capabilities: [capability],
        grantedBy: issuerPublicKeyBase64,
        epochId: stableEpochId,
        revoked: false,
      });
      const changes = await this._backing.add(publicKey);

      // Install the capability and clear a previous local revocation only
      // after the backing membership mutation succeeds.
      this._revokedKeys.delete(keyBase64);
      this._entries.set(keyBase64, entry);
      return changes;
    } finally {
      this._pendingGrants.delete(keyBase64);
    }
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
    const entry = this._entries.get(keyBase64);
    return entry && copyUCANEntry(entry);
  }
}

/**
 * Provider for UCAN-based ACLs.
 */
export class UCANACLProvider<ChangesType, PublicKey> implements ACLProvider<ChangesType, PublicKey> {
  constructor(
    private readonly _backingAclProvider: ACLProvider<ChangesType, PublicKey>,
    private readonly _serializePublicKey: (key: PublicKey) => Promise<string>,
  ) {}

  initialize(): UCANACL<ChangesType, PublicKey> {
    const backingAcl = this._backingAclProvider.initialize();
    return new UCANACL(backingAcl, this._serializePublicKey);
  }
}
