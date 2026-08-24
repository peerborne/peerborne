import type { AesAlgorithmName } from './auth-provider.js';

/** Length of an epoch ID in bytes (SHA-256 hash). */
export const EPOCH_ID_LENGTH = 32;

/**
 * Length of AES-256-GCM nonce in bytes. CTR and CBC use 16-byte nonces instead.
 *
 * @remarks Renamed from `NONCE_LENGTH` in the AES-CTR/CBC support update. This
 * is a breaking rename, but no migration alias is provided because there are no
 * known live consumers of the old name.
 */
export const GCM_NONCE_LENGTH = 12;

/** HKDF info string for deriving the epoch secret. */
export const EPOCH_SECRET_INFO = 'swarmdb-epoch-v1';

/**
 * HKDF info strings for deriving encryption keys, keyed by algorithm.
 *
 * @remarks Changed from a single string (the previous AES-GCM-only value
 * `'aes-gcm-key'`) to an algorithm-keyed record in the AES-CTR/CBC support
 * update. This is a breaking type change, accepted because there are no
 * known live consumers of the old value.
 */
export const ENCRYPTION_KEY_INFO: Record<AesAlgorithmName, string> = {
  'AES-GCM': 'aes-gcm-key',
  'AES-CTR': 'aes-ctr-key',
  'AES-CBC': 'aes-cbc-key',
};

/**
 * Represents an epoch -- a contiguous period during which a specific set of
 * members shares a symmetric encryption key. Epoch boundaries are triggered
 * by member add/remove or explicit key updates.
 */
export interface Epoch {
  /** 32-byte SHA-256 hash identifying this epoch. */
  id: Uint8Array;
  /** The symmetric AES-256 encryption key for this epoch (GCM, CTR, or CBC). */
  encryptionKey: CryptoKey;
  /** Set of member public key hashes in this epoch. */
  memberHashes: Set<string>;
  /** Parent epoch ID (undefined for the first epoch). */
  parentEpochId?: Uint8Array;
  /** Timestamp when this epoch was created. */
  createdAt: number;
}

/** Result of an epoch transition. */
export interface EpochTransition {
  /** The new epoch. */
  epoch: Epoch;
  /** Reason for the transition. */
  reason: 'member_added' | 'member_removed' | 'key_update';
  /** Public key hash of the affected member (for add/remove). */
  affectedMember?: string;
}

/**
 * Convert a Uint8Array to a lowercase hex string.
 */
export function toHex(bytes: Uint8Array): string {
  const hexChars: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hexChars[i] = bytes[i].toString(16).padStart(2, '0');
  }
  return hexChars.join('');
}

/**
 * Generate an epoch ID as a SHA-256 hash of the concatenation of the group
 * secret and the optional parent epoch ID. Using a hash instead of a sequential
 * counter prevents conflicts from concurrent epoch creation.
 *
 * @param groupSecret - The shared group secret from key agreement.
 * @param parentEpochId - The ID of the preceding epoch, if any.
 * @returns A 32-byte Uint8Array epoch ID.
 */
export async function generateEpochId(
  groupSecret: Uint8Array,
  parentEpochId?: Uint8Array,
): Promise<Uint8Array> {
  const input = parentEpochId
    ? new Uint8Array([...groupSecret, ...parentEpochId])
    : groupSecret;
  const hash = await crypto.subtle.digest('SHA-256', input.buffer as ArrayBuffer);
  return new Uint8Array(hash);
}

/**
 * Derive an epoch secret from the group key agreement output using HKDF-SHA256.
 *
 * ```
 * epoch_secret = HKDF-SHA256(ikm: groupKeyAgreementOutput, salt: epochId, info: "swarmdb-epoch-v1")
 * ```
 *
 * @param groupKeyAgreementOutput - The raw shared secret from the group key agreement protocol.
 * @param epochId - The 32-byte epoch ID, used as the HKDF salt.
 * @returns A 32-byte derived epoch secret.
 */
export async function deriveEpochSecret(
  groupKeyAgreementOutput: Uint8Array,
  epochId: Uint8Array,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    groupKeyAgreementOutput.buffer as ArrayBuffer,
    'HKDF',
    false,
    ['deriveBits'],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: epochId.buffer as ArrayBuffer,
      info: new TextEncoder().encode(EPOCH_SECRET_INFO),
    },
    baseKey,
    256, // 32 bytes
  );
  return new Uint8Array(derived);
}

/**
 * Derive an AES-256 CryptoKey from an epoch secret using HKDF-SHA256.
 *
 * The HKDF info string includes the algorithm name for domain separation,
 * ensuring keys derived for different algorithms are distinct.
 *
 * @param epochSecret - The 32-byte epoch secret from {@link deriveEpochSecret}.
 * @param algorithmName - The AES algorithm to bind the key to (default: AES-GCM).
 * @returns A CryptoKey suitable for the specified algorithm's encrypt/decrypt.
 */
export async function deriveEncryptionKey(
  epochSecret: Uint8Array,
  algorithmName: AesAlgorithmName = 'AES-GCM',
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    epochSecret.buffer as ArrayBuffer,
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new ArrayBuffer(0),
      info: new TextEncoder().encode(ENCRYPTION_KEY_INFO[algorithmName]),
    },
    baseKey,
    { name: algorithmName, length: 256 },
    // CTR/CBC require extractable keys so we can derive HMAC keys via exportKey.
    // GCM keys do not need extraction, so keep them non-extractable for security.
    algorithmName !== 'AES-GCM',
    ['encrypt', 'decrypt'],
  );
}

/**
 * Create a complete epoch with a derived encryption key.
 *
 * This generates the epoch ID, derives the epoch secret, and then derives
 * the AES-256 encryption key in a single call.
 *
 * @param groupSecret - The shared group secret from key agreement.
 * @param members - Set of member public key hashes for this epoch.
 * @param parentEpochId - The parent epoch ID, if any.
 * @param algorithmName - The AES algorithm for the encryption key (default: AES-GCM).
 * @returns A fully constructed {@link Epoch}.
 */
export async function createEpoch(
  groupSecret: Uint8Array,
  members: Set<string>,
  parentEpochId?: Uint8Array,
  algorithmName: AesAlgorithmName = 'AES-GCM',
): Promise<Epoch> {
  const epochId = await generateEpochId(groupSecret, parentEpochId);
  const epochSecret = await deriveEpochSecret(groupSecret, epochId);
  const encryptionKey = await deriveEncryptionKey(epochSecret, algorithmName);

  return {
    id: epochId,
    encryptionKey,
    memberHashes: new Set(members),
    parentEpochId,
    createdAt: Date.now(),
  };
}

/**
 * Manages a chain of epochs, providing lookup by ID and transitions
 * that produce new epochs when membership changes.
 */
export class EpochManager {
  private _epochs: Map<string, Epoch> = new Map();
  private _currentEpochId?: Uint8Array;

  /** The current (most recent) epoch, or undefined if none exist. */
  get currentEpoch(): Epoch | undefined {
    if (!this._currentEpochId) return undefined;
    return this._epochs.get(toHex(this._currentEpochId));
  }

  /** Add an epoch to the manager and set it as the current epoch. */
  addEpoch(epoch: Epoch): void {
    this._epochs.set(toHex(epoch.id), epoch);
    this._currentEpochId = epoch.id;
  }

  /** Retrieve an epoch by its ID. */
  getEpoch(epochId: Uint8Array): Epoch | undefined {
    return this._epochs.get(toHex(epochId));
  }

  /** Return all known epochs in insertion order. */
  get epochs(): Epoch[] {
    return Array.from(this._epochs.values());
  }

  /**
   * Transition to a new epoch. Creates a child epoch whose parent is the
   * current epoch and sets it as the new current epoch.
   *
   * @param groupSecret - The new shared group secret from key agreement.
   * @param members - The updated set of member public key hashes.
   * @param reason - The reason for the epoch transition.
   * @param options - Optional settings for the transition.
   * @param options.affectedMember - The public key hash of the added/removed member, if applicable.
   * @param options.algorithmName - The AES algorithm for the encryption key (default: AES-GCM).
   * @returns The {@link EpochTransition} describing the new epoch and its cause.
   *
   * @remarks The 4th parameter changed from a positional `affectedMember?: string`
   * to an `options` object in the AES-CTR/CBC support update so the algorithm
   * choice cannot be silently swallowed by a stringly-typed positional arg.
   * This is a breaking signature change, accepted because there are no known
   * live consumers; no overload shim is provided.
   */
  async transitionEpoch(
    groupSecret: Uint8Array,
    members: Set<string>,
    reason: EpochTransition['reason'],
    options?: {
      affectedMember?: string;
      algorithmName?: AesAlgorithmName;
    },
  ): Promise<EpochTransition> {
    const { affectedMember, algorithmName = 'AES-GCM' } = options ?? {};
    const epoch = await createEpoch(groupSecret, members, this._currentEpochId, algorithmName);
    this.addEpoch(epoch);

    return {
      epoch,
      reason,
      affectedMember,
    };
  }
}