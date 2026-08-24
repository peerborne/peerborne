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

/**
 * UCAN-based ACL with fine-grained capability support.
 *
 * Conflict resolution follows p2panda's "strong removal" pattern:
 * - Concurrent mutual revocations: both parties are removed (safety-first)
 * - Concurrent grant + revoke of the same user: revoke wins
 * - Concurrent grants by different admins: both apply (CRDT merge)
 *
 * All access to the backing ACL should go through UCANACL methods to keep
 * state consistent between the entries map, revoked set, and backing ACL.
 */
export class UCANACL<ChangesType, PublicKey> implements ACL<ChangesType, PublicKey> {
  private _entries: Map<string, UCANACLEntry> = new Map(); // publicKeyBase64 -> entry
  private _revokedKeys: Set<string> = new Set(); // set of revoked public key base64 strings

  // Private backing ACL -- all access must go through UCANACL methods
  // to keep _entries, _revokedKeys, and the backing ACL in sync.
  constructor(
    private readonly _backing: ACL<ChangesType, PublicKey>,
    private readonly _serializePublicKey: (key: PublicKey) => Promise<string>,
  ) {}

  async add(publicKey: PublicKey): Promise<ChangesType> {
    return this._backing.add(publicKey);
  }

  async remove(publicKey: PublicKey): Promise<ChangesType> {
    const keyBase64 = await this._serializePublicKey(publicKey);
    this._revokedKeys.add(keyBase64);
    this._entries.delete(keyBase64);
    return this._backing.remove(publicKey);
  }

  current(): ChangesType {
    return this._backing.current();
  }

  merge(changes: ChangesType): void {
    this._backing.merge(changes);
  }

  async check(publicKey: PublicKey, capability?: string): Promise<boolean> {
    if (!capability) {
      return this._backing.check(publicKey);
    }

    const keyBase64 = await this._serializePublicKey(publicKey);

    // Check if revoked
    if (this._revokedKeys.has(keyBase64)) {
      return false;
    }

    const entry = this._entries.get(keyBase64);
    if (!entry) {
      // Fall back to backing ACL for basic membership check
      return this._backing.check(publicKey);
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
      if (await this.check(user, capability)) {
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
    const keyBase64 = await this._serializePublicKey(publicKey);

    const ucan = await createUCAN(
      issuerPrivateKey,
      issuerPublicKeyBase64,
      keyBase64,
      [{ resource: documentId, ability: capability }],
      proofs,
    );

    this._entries.set(keyBase64, {
      publicKeyBase64: keyBase64,
      ucan,
      capabilities: [capability],
      grantedBy: issuerPublicKeyBase64,
      epochId,
      revoked: false,
    });

    return this._backing.add(publicKey);
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
    return this._entries.get(keyBase64);
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
