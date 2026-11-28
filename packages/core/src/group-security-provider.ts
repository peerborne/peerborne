/**
 * Protocol-neutral group-security contracts.
 *
 * Implementations may wrap a reviewed group-security protocol. These types do
 * not implement or claim interoperability with any particular protocol.
 */
import { defineEnumerableDataProperty } from './internal/data-property.js';
import {
  bufferOf,
  byteLengthOf,
  byteOffsetOf,
  concatBytes,
  copyUnsharedUint8Array,
  equalBytes,
} from './internal/bytes.js';
import {
  asciiBytes,
  encodeU16,
  encodeU32,
  encodeU64,
  lengthPrefixed16,
  lengthPrefixed32,
  requireU64,
} from './internal/big-endian.js';
import {
  isCanonicalIdentifier,
  isCanonicalProtocol,
} from './internal/protocol-identifier.js';

const ENCRYPTED_GROUP_STATE_MAGIC = new Uint8Array([
  0x53, 0x57, 0x4d, 0x47, 0x53, 0x30, 0x30, 0x31,
]);
const ENCRYPTED_KEY_PACKAGE_STATE_MAGIC = new Uint8Array([
  0x53, 0x57, 0x4d, 0x4b, 0x50, 0x30, 0x30, 0x31,
]);
const APPLIED_MEMBERSHIP_DELTA_DOMAIN = asciiBytes(
  'peerborne/group-security-applied-membership-delta/v1\0',
);

export const ENCRYPTED_GROUP_STATE_VERSION = 1;
export const ENCRYPTED_KEY_PACKAGE_STATE_VERSION = 1;

const MAX_SHORT_BYTES = 0xffff;
const MAX_GROUP_ID_BYTES = 1024;
const MAX_HASH_BYTES = 128;
const MAX_MEMBER_ID_BYTES = 512;
const MAX_KEY_PACKAGE_REFERENCE_BYTES = 512;
const MAX_KEY_PACKAGE_PAYLOAD_BYTES = 4 * 1024 * 1024;
const MAX_MEMBERSHIP_CHANGES = 4096;
const MAX_CIPHERTEXT_BYTES = 64 * 1024 * 1024;
const MAX_PROTOCOL_ID_BYTES = 128;
const MAX_PROTECTOR_ALGORITHM_BYTES = 128;
const MAX_PROTECTOR_KEY_ID_BYTES = 256;
const MAX_ENCRYPTED_KEY_PACKAGE_STATE_SERIALIZED_BYTES =
  32 +
  MAX_PROTOCOL_ID_BYTES +
  MAX_GROUP_ID_BYTES +
  MAX_KEY_PACKAGE_REFERENCE_BYTES +
  MAX_KEY_PACKAGE_PAYLOAD_BYTES +
  MAX_PROTECTOR_ALGORITHM_BYTES +
  MAX_PROTECTOR_KEY_ID_BYTES +
  MAX_SHORT_BYTES +
  MAX_CIPHERTEXT_BYTES;
const MAX_ENCRYPTED_GROUP_STATE_SERIALIZED_BYTES =
  38 +
  MAX_PROTOCOL_ID_BYTES +
  MAX_GROUP_ID_BYTES +
  MAX_HASH_BYTES * 2 +
  MAX_PROTECTOR_ALGORITHM_BYTES +
  MAX_PROTECTOR_KEY_ID_BYTES +
  MAX_SHORT_BYTES +
  MAX_CIPHERTEXT_BYTES;

const objectGetPrototypeOf = Object.getPrototypeOf;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectPrototype = Object.prototype;
const objectPrototypeHasOwnProperty = objectPrototype.hasOwnProperty;
const arrayIsArray = Array.isArray;
const arrayPrototype = Array.prototype;
const numberIsSafeInteger = Number.isSafeInteger;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const uint8ArraySubarray = Uint8Array.prototype.subarray;

function appendArrayValue<T>(target: T[], value: T): void {
  defineEnumerableDataProperty(target, target.length, value);
}

export interface GroupSecurityProtocol {
  readonly id: string;
  readonly version: number;
}

export interface GroupSecurityPublicState {
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
  readonly epoch: bigint;
  /** RFC 9420 starts with an empty confirmed transcript at epoch zero. */
  readonly confirmedTranscriptHash: Uint8Array;
  readonly treeHash: Uint8Array;
}

export interface GroupKeyPackage {
  readonly protocol: GroupSecurityProtocol;
  /** Document group this one-time package is exclusively authorized to join. */
  readonly groupId: Uint8Array;
  readonly reference: Uint8Array;
  readonly payload: Uint8Array;
}

export interface GroupSecurityCommit {
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
  readonly priorEpoch: bigint;
  readonly epoch: bigint;
  readonly payload: Uint8Array;
}

export interface GroupWelcome {
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
  readonly epoch: bigint;
  readonly recipientKeyPackageRef: Uint8Array;
  readonly payload: Uint8Array;
}

/**
 * A cryptographic group-membership transition. An `update` rotates or replaces
 * the named member's key package; role-only authorization changes with no
 * provider membership effect belong in a separate control path.
 */
export type GroupMembershipChange =
  | {
      readonly kind: 'add';
      readonly memberId: Uint8Array;
      readonly keyPackage: GroupKeyPackage;
    }
  | { readonly kind: 'remove'; readonly memberId: Uint8Array }
  | {
      readonly kind: 'update';
      readonly memberId: Uint8Array;
      readonly keyPackage: GroupKeyPackage;
    };

/** Provider-reported membership effect of an applied protocol commit. */
export type AppliedGroupMembershipChange =
  | {
      readonly kind: 'add';
      readonly memberId: Uint8Array;
      readonly keyPackageRef: Uint8Array;
    }
  | { readonly kind: 'remove'; readonly memberId: Uint8Array }
  | {
      readonly kind: 'update';
      readonly memberId: Uint8Array;
      readonly keyPackageRef: Uint8Array;
    };

export interface AppliedGroupMembershipDelta {
  readonly changes: ReadonlyArray<AppliedGroupMembershipChange>;
}

export interface GroupSecurityCommitResult {
  readonly commit: GroupSecurityCommit;
  readonly welcomes: ReadonlyArray<GroupWelcome>;
  readonly state: GroupSecurityPublicState;
  readonly appliedMembership: AppliedGroupMembershipDelta;
}

export interface GroupSecurityActiveApplyResult {
  readonly status: 'applied' | 'duplicate';
  readonly state: GroupSecurityPublicState;
  readonly appliedMembership: AppliedGroupMembershipDelta;
}

/** A removed member authenticates removal but cannot derive the next epoch state. */
export interface GroupSecurityRemovedApplyResult {
  readonly status: 'removed';
  /** Identity authenticated from the removed local protocol leaf. */
  readonly memberId: Uint8Array;
  readonly appliedMembership: AppliedGroupMembershipDelta;
}

export type GroupSecurityApplyResult =
  | GroupSecurityActiveApplyResult
  | GroupSecurityRemovedApplyResult;

export interface GroupStateCiphertext {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** Authenticated-encryption boundary for private provider state. */
export interface GroupStateProtector {
  readonly algorithm: string;
  readonly keyId: string;
  seal(
    plaintext: Uint8Array,
    associatedData: Uint8Array,
  ): Promise<GroupStateCiphertext>;
  open(
    sealed: GroupStateCiphertext,
    associatedData: Uint8Array,
  ): Promise<Uint8Array>;
}

export interface CreateGroupInput {
  readonly groupId: Uint8Array;
  /** Application identity expected for the protocol group's creator leaf. */
  readonly creatorMemberId: Uint8Array;
  /** Provider-specific creator credential; it is not itself a member ID. */
  readonly credential: Uint8Array;
  readonly authenticatedData?: Uint8Array;
}

export interface GroupSecurityCreateResult {
  readonly state: GroupSecurityPublicState;
  /** Identity authenticated from the protocol creator credential/leaf. */
  readonly authenticatedCreatorMemberId: Uint8Array;
}

export interface CreateKeyPackageInput {
  /** Document group this one-time KeyPackage is exclusively bound to. */
  readonly groupId: Uint8Array;
  /** Application member identity the provider must authenticate and bind. */
  readonly memberId: Uint8Array;
  /** Provider-specific credential material; it is not itself a member ID. */
  readonly credential: Uint8Array;
  /** Caller-stable request commitment authenticated by the public package. */
  readonly requestCommitment: Uint8Array;
  readonly extensions?: ReadonlyMap<number, Uint8Array>;
}

export interface JoinGroupInput {
  readonly welcome: GroupWelcome;
  readonly keyPackageRef: Uint8Array;
  readonly authenticatedData?: Uint8Array;
}

export interface CreateGroupCommitInput {
  /** Empty changes request a cryptographic self-update without a roster change. */
  readonly changes: ReadonlyArray<GroupMembershipChange>;
  readonly authenticatedData?: Uint8Array;
}

export interface ExportGroupSecretInput {
  readonly label: string;
  readonly context: Uint8Array;
  readonly length: number;
}

/**
 * Stateful protocol adapter. A provider owns at most one active group and
 * crosses the persistence boundary only through encrypted export/import.
 * Returned records must expose finite own data properties, and returned byte
 * fields must be genuine unshared `Uint8Array` snapshots; coordinators detach
 * them before authentication, comparison, or persistence.
 */
export interface GroupSecurityProvider {
  readonly protocol: GroupSecurityProtocol;
  /**
   * Stable lifecycle identity shared by every forwarding wrapper over the
   * same mutable provider. When omitted, the provider object itself is used.
   * The token must never change for one provider instance.
   */
  readonly lifecycleIdentity?: object;
  /**
   * Report whether this provider currently owns an active group. This check
   * must be authoritative: lifecycle uncertainty or storage failure must
   * reject rather than report `false`.
   */
  hasActiveGroup(): Promise<boolean>;
  /**
   * Create a globally one-time reference bound irreversibly to `input.groupId`.
   * The same private package must never be exported or consumed for another
   * group, including after provider restart.
   */
  createKeyPackage(input: CreateKeyPackageInput): Promise<GroupKeyPackage>;
  /**
   * Validate the protocol credential carried by a public KeyPackage and derive
   * its authenticated application member identity. This operation must be
   * read-only and must derive the result from provider-validated package
   * contents, never from unauthenticated caller metadata.
   */
  authenticateKeyPackageMember(
    keyPackage: GroupKeyPackage,
  ): Promise<Uint8Array>;
  /** Derive the request commitment authenticated by the public KeyPackage. */
  authenticateKeyPackageRequestCommitment(
    keyPackage: GroupKeyPackage,
  ): Promise<Uint8Array>;
  /**
   * Export the one-time private state for a previously created KeyPackage.
   * Repeated exports of an unconsumed reference must return a byte-identical
   * envelope, allowing an ambiguous durable-write retry to compare safely.
   */
  exportEncryptedKeyPackage(
    reference: Uint8Array,
    protector: GroupStateProtector,
  ): Promise<EncryptedKeyPackageState>;
  /** Restore a pending, not-yet-consumed KeyPackage after restart. */
  importEncryptedKeyPackage(
    state: EncryptedKeyPackageState,
    protector: GroupStateProtector,
  ): Promise<GroupKeyPackage>;
  /**
   * Optionally and securely discard one pending KeyPackage after a failed
   * persistence attempt. Without it, callers must discard the provider.
   */
  clearKeyPackageState?(reference: Uint8Array): Promise<void>;
  /** Create a group and report the credential-authenticated creator identity. */
  createGroup(input: CreateGroupInput): Promise<GroupSecurityCreateResult>;
  joinGroup(input: JoinGroupInput): Promise<GroupSecurityPublicState>;
  /** Add/Update packages must authenticate to their matching `memberId`. */
  createCommit(
    input: CreateGroupCommitInput,
  ): Promise<GroupSecurityCommitResult>;
  /**
   * Authenticate received protocol messages and Add/Update credentials before
   * applying. A removed result must erase active private group state and must
   * not claim next-epoch state the removed member cannot derive.
   */
  applyCommit(commit: GroupSecurityCommit): Promise<GroupSecurityApplyResult>;
  exportSecret(input: ExportGroupSecretInput): Promise<Uint8Array>;
  getPublicState(): Promise<GroupSecurityPublicState>;
  /**
   * Return every live member ID from protocol-authenticated credentials in
   * the current decrypting group. The same provider exclusively serves the
   * coordinator so this read describes the state reported by getPublicState.
   * Strict coordinated documents require this read-only capability, and a
   * coordinated document with a signed authority log is strict by default
   * when its provider implements it.
   */
  getAuthenticatedMemberIds?(): Promise<readonly Uint8Array[]>;
  exportEncryptedState(
    protector: GroupStateProtector,
  ): Promise<EncryptedGroupState>;
  importEncryptedState(
    state: EncryptedGroupState,
    protector: GroupStateProtector,
  ): Promise<GroupSecurityPublicState>;
  /**
   * Optionally and securely discards an active or partially-created group.
   * Coordinators use this when a fresh provider cannot be checkpointed before
   * bootstrap/restore. Without it, callers must discard that provider instance
   * after an initialization failure.
   */
  clearGroupState?(): Promise<void>;
}

const encryptedKeyPackageStateInstances = new WeakSet<object>();
const encryptedGroupStateInstances = new WeakSet<object>();
const encryptedKeyPackageStateConstructionToken = {};
const encryptedGroupStateConstructionToken = {};

/**
 * Ciphertext-only envelope for one pending KeyPackage's private material.
 * The public KeyPackage and intended document group are authenticated as
 * associated data so stored private material cannot be relabeled or reused in
 * another group's join.
 */
export class EncryptedKeyPackageState {
  readonly #keyPackageValue: GroupKeyPackage;
  readonly #algorithm: string;
  readonly #keyId: string;
  readonly #nonceValue: Uint8Array;
  readonly #ciphertextValue: Uint8Array;

  private constructor(
    constructionToken: typeof encryptedKeyPackageStateConstructionToken,
    keyPackageValue: GroupKeyPackage,
    algorithm: string,
    keyId: string,
    nonceValue: Uint8Array,
    ciphertextValue: Uint8Array,
  ) {
    if (constructionToken !== encryptedKeyPackageStateConstructionToken) {
      throw new TypeError('EncryptedKeyPackageState construction is private');
    }
    this.#keyPackageValue = keyPackageValue;
    this.#algorithm = algorithm;
    this.#keyId = keyId;
    this.#nonceValue = nonceValue;
    this.#ciphertextValue = ciphertextValue;
    encryptedKeyPackageStateInstances.add(this);
  }

  get keyPackage(): GroupKeyPackage {
    return cloneKeyPackage(this.#keyPackageValue);
  }

  /** Document group for which this one-time package may be consumed. */
  get groupId(): Uint8Array {
    return new Uint8Array(this.#keyPackageValue.groupId);
  }

  get algorithm(): string {
    return this.#algorithm;
  }

  get keyId(): string {
    return this.#keyId;
  }

  get nonce(): Uint8Array {
    return new Uint8Array(this.#nonceValue);
  }

  get ciphertext(): Uint8Array {
    return new Uint8Array(this.#ciphertextValue);
  }

  static async seal(
    keyPackage: GroupKeyPackage,
    privateState: Uint8Array,
    protector: GroupStateProtector,
  ): Promise<EncryptedKeyPackageState> {
    const snapshot = cloneKeyPackage(keyPackage);
    const privateStateSnapshot = copyUnsharedUint8Array(
      privateState,
      1,
      MAX_CIPHERTEXT_BYTES,
      'private KeyPackage state',
    );
    const algorithm = protector.algorithm;
    const keyId = protector.keyId;
    validateProtectorIdentity(algorithm, keyId);
    const associatedData = encodeKeyPackageAssociatedData(
      snapshot,
      algorithm,
      keyId,
    );
    const sealed = await protector.seal(
      privateStateSnapshot,
      associatedData,
    );
    const sealedSnapshot = snapshotGroupStateCiphertext(sealed);
    return new EncryptedKeyPackageState(
      encryptedKeyPackageStateConstructionToken,
      snapshot,
      algorithm,
      keyId,
      sealedSnapshot.nonce,
      sealedSnapshot.ciphertext,
    );
  }

  async open(protector: GroupStateProtector): Promise<Uint8Array> {
    const algorithm = protector.algorithm;
    const keyId = protector.keyId;
    if (
      algorithm !== this.algorithm ||
      keyId !== this.keyId
    ) {
      throw new Error(
        'KeyPackage protector does not match the envelope algorithm/keyId',
      );
    }
    const plaintext = await protector.open(
      { nonce: this.nonce, ciphertext: this.ciphertext },
      encodeKeyPackageAssociatedData(
        this.#keyPackageValue,
        this.#algorithm,
        this.#keyId,
      ),
    );
    return copyUnsharedUint8Array(
      plaintext,
      1,
      MAX_CIPHERTEXT_BYTES,
      'opened private KeyPackage state',
    );
  }

  serialize(): Uint8Array {
    return concatBytes([
      encodeKeyPackageAssociatedData(
        this.#keyPackageValue,
        this.#algorithm,
        this.#keyId,
      ),
      encodeU16(byteLengthOf(this.#nonceValue)),
      this.#nonceValue,
      encodeU32(byteLengthOf(this.#ciphertextValue)),
      this.#ciphertextValue,
    ]);
  }

  static deserialize(bytes: Uint8Array): EncryptedKeyPackageState {
    const reader = new ByteReader(
      bytes,
      'encrypted KeyPackage state',
      MAX_ENCRYPTED_KEY_PACKAGE_STATE_SERIALIZED_BYTES,
    );
    reader.expect(ENCRYPTED_KEY_PACKAGE_STATE_MAGIC, 'magic');
    const version = reader.u16('version');
    if (version !== ENCRYPTED_KEY_PACKAGE_STATE_VERSION) {
      throw new Error(`unsupported encrypted KeyPackage-state version ${version}`);
    }
    const keyPackage: GroupKeyPackage = {
      protocol: {
        id: reader.string16('protocol.id'),
        version: reader.u16('protocol.version'),
      },
      groupId: reader.bytes16('groupId', 1, MAX_GROUP_ID_BYTES),
      reference: reader.bytes16(
        'reference',
        1,
        MAX_KEY_PACKAGE_REFERENCE_BYTES,
      ),
      payload: reader.bytes32('payload', 1, MAX_KEY_PACKAGE_PAYLOAD_BYTES),
    };
    const algorithm = reader.string16('algorithm');
    const keyId = reader.string16('keyId');
    const nonce = reader.bytes16('nonce', 1, MAX_SHORT_BYTES);
    const ciphertext = reader.bytes32('ciphertext', 1, MAX_CIPHERTEXT_BYTES);
    reader.done();
    validateKeyPackage(keyPackage);
    validateProtectorIdentity(algorithm, keyId);
    return new EncryptedKeyPackageState(
      encryptedKeyPackageStateConstructionToken,
      keyPackage,
      algorithm,
      keyId,
      nonce,
      ciphertext,
    );
  }
}

Object.freeze(EncryptedKeyPackageState.prototype);
Object.freeze(EncryptedKeyPackageState);

const encryptedKeyPackageStatePrototype =
  EncryptedKeyPackageState.prototype;
const encryptedKeyPackageStateSerialize =
  encryptedKeyPackageStatePrototype.serialize;

export function isEncryptedKeyPackageState(
  value: unknown,
): value is EncryptedKeyPackageState {
  return (
    value !== null &&
    typeof value === 'object' &&
    encryptedKeyPackageStateInstances.has(value) &&
    objectGetPrototypeOf(value) === encryptedKeyPackageStatePrototype &&
    !hasOwnEnvelopeOverride(value, [
      'keyPackage',
      'groupId',
      'algorithm',
      'keyId',
      'nonce',
      'ciphertext',
      'open',
      'serialize',
    ]) &&
    objectGetOwnPropertyDescriptor(
      encryptedKeyPackageStatePrototype,
      'serialize',
    )?.value === encryptedKeyPackageStateSerialize
  );
}

/** Ciphertext-only, authenticated envelope for durable private group state. */
export class EncryptedGroupState {
  readonly #stateValue: GroupSecurityPublicState;
  readonly #algorithm: string;
  readonly #keyId: string;
  readonly #nonceValue: Uint8Array;
  readonly #ciphertextValue: Uint8Array;

  private constructor(
    constructionToken: typeof encryptedGroupStateConstructionToken,
    stateValue: GroupSecurityPublicState,
    algorithm: string,
    keyId: string,
    nonceValue: Uint8Array,
    ciphertextValue: Uint8Array,
  ) {
    if (constructionToken !== encryptedGroupStateConstructionToken) {
      throw new TypeError('EncryptedGroupState construction is private');
    }
    this.#stateValue = stateValue;
    this.#algorithm = algorithm;
    this.#keyId = keyId;
    this.#nonceValue = nonceValue;
    this.#ciphertextValue = ciphertextValue;
    encryptedGroupStateInstances.add(this);
  }

  get state(): GroupSecurityPublicState {
    return clonePublicState(this.#stateValue);
  }

  get algorithm(): string {
    return this.#algorithm;
  }

  get keyId(): string {
    return this.#keyId;
  }

  get nonce(): Uint8Array {
    return new Uint8Array(this.#nonceValue);
  }

  get ciphertext(): Uint8Array {
    return new Uint8Array(this.#ciphertextValue);
  }

  static async seal(
    state: GroupSecurityPublicState,
    privateState: Uint8Array,
    protector: GroupStateProtector,
  ): Promise<EncryptedGroupState> {
    const snapshot = clonePublicState(state);
    const privateStateSnapshot = copyUnsharedUint8Array(
      privateState,
      1,
      MAX_CIPHERTEXT_BYTES,
      'privateState',
    );
    const algorithm = protector.algorithm;
    const keyId = protector.keyId;
    validateProtectorIdentity(algorithm, keyId);
    const associatedData = encodeAssociatedData(
      snapshot,
      algorithm,
      keyId,
    );
    const sealed = await protector.seal(
      privateStateSnapshot,
      associatedData,
    );
    const sealedSnapshot = snapshotGroupStateCiphertext(sealed);
    return new EncryptedGroupState(
      encryptedGroupStateConstructionToken,
      snapshot,
      algorithm,
      keyId,
      sealedSnapshot.nonce,
      sealedSnapshot.ciphertext,
    );
  }

  async open(protector: GroupStateProtector): Promise<Uint8Array> {
    const algorithm = protector.algorithm;
    const keyId = protector.keyId;
    if (
      algorithm !== this.algorithm ||
      keyId !== this.keyId
    ) {
      throw new Error(
        'group-state protector does not match the envelope algorithm/keyId',
      );
    }
    const plaintext = await protector.open(
      { nonce: this.nonce, ciphertext: this.ciphertext },
      encodeAssociatedData(
        this.#stateValue,
        this.#algorithm,
        this.#keyId,
      ),
    );
    return copyUnsharedUint8Array(
      plaintext,
      1,
      MAX_CIPHERTEXT_BYTES,
      'opened private group state',
    );
  }

  serialize(): Uint8Array {
    const associatedData = encodeAssociatedData(
      this.#stateValue,
      this.#algorithm,
      this.#keyId,
    );
    return concatBytes([
      associatedData,
      encodeU16(byteLengthOf(this.#nonceValue)),
      this.#nonceValue,
      encodeU32(byteLengthOf(this.#ciphertextValue)),
      this.#ciphertextValue,
    ]);
  }

  static deserialize(bytes: Uint8Array): EncryptedGroupState {
    const reader = new ByteReader(
      bytes,
      'encrypted group state',
      MAX_ENCRYPTED_GROUP_STATE_SERIALIZED_BYTES,
    );
    reader.expect(ENCRYPTED_GROUP_STATE_MAGIC, 'magic');
    const version = reader.u16('version');
    if (version !== ENCRYPTED_GROUP_STATE_VERSION) {
      throw new Error(`unsupported encrypted group-state version ${version}`);
    }
    const protocol = {
      id: reader.string16('protocol.id'),
      version: reader.u16('protocol.version'),
    };
    const groupId = reader.bytes16('groupId', 1, MAX_GROUP_ID_BYTES);
    const epoch = reader.u64('epoch');
    const state: GroupSecurityPublicState = {
      protocol,
      groupId,
      epoch,
      confirmedTranscriptHash: reader.bytes16(
        'confirmedTranscriptHash',
        epoch === 0n ? 0 : 1,
        MAX_HASH_BYTES,
      ),
      treeHash: reader.bytes16('treeHash', 1, MAX_HASH_BYTES),
    };
    const algorithm = reader.string16('algorithm');
    const keyId = reader.string16('keyId');
    const nonce = reader.bytes16('nonce', 1, MAX_SHORT_BYTES);
    const ciphertext = reader.bytes32(
      'ciphertext',
      1,
      MAX_CIPHERTEXT_BYTES,
    );
    reader.done();
    validatePublicState(state);
    validateProtectorIdentity(algorithm, keyId);
    return new EncryptedGroupState(
      encryptedGroupStateConstructionToken,
      state,
      algorithm,
      keyId,
      nonce,
      ciphertext,
    );
  }
}

Object.freeze(EncryptedGroupState.prototype);
Object.freeze(EncryptedGroupState);

const encryptedGroupStatePrototype = EncryptedGroupState.prototype;
const encryptedGroupStateSerialize = encryptedGroupStatePrototype.serialize;

export function isEncryptedGroupState(
  value: unknown,
): value is EncryptedGroupState {
  return (
    value !== null &&
    typeof value === 'object' &&
    encryptedGroupStateInstances.has(value) &&
    objectGetPrototypeOf(value) === encryptedGroupStatePrototype &&
    !hasOwnEnvelopeOverride(value, [
      'state',
      'algorithm',
      'keyId',
      'nonce',
      'ciphertext',
      'open',
      'serialize',
    ]) &&
    objectGetOwnPropertyDescriptor(
      encryptedGroupStatePrototype,
      'serialize',
    )?.value === encryptedGroupStateSerialize
  );
}

function hasOwnEnvelopeOverride(
  value: object,
  properties: ReadonlyArray<string>,
): boolean {
  for (let index = 0; index < properties.length; index++) {
    if (
      reflectApply(objectPrototypeHasOwnProperty, value, [properties[index]])
    ) {
      return true;
    }
  }
  return false;
}

/** Canonical, protocol-neutral encoding used to bind provider-applied changes. */
export function canonicalAppliedGroupMembershipDelta(
  delta: AppliedGroupMembershipDelta,
): Uint8Array {
  const snapshot = snapshotAppliedGroupMembershipDelta(delta);
  const parts: Uint8Array[] = [
    APPLIED_MEMBERSHIP_DELTA_DOMAIN,
    encodeU16(snapshot.changes.length),
  ];
  const memberIds = new Set<string>();
  const keyPackageRefs = new Set<string>();
  for (let index = 0; index < snapshot.changes.length; index++) {
    const change = snapshot.changes[index];
    const label = `applied membership change ${index}`;
    const memberKey = byteKey(change.memberId);
    if (memberIds.has(memberKey)) {
      throw new Error(`${label} duplicates a memberId`);
    }
    memberIds.add(memberKey);
    if (change.kind === 'remove') {
      appendArrayValue(parts, new Uint8Array([2]));
      appendArrayValue(parts, lengthPrefixed16(change.memberId));
      continue;
    }
    const keyPackageRef = byteKey(change.keyPackageRef);
    if (keyPackageRefs.has(keyPackageRef)) {
      throw new Error(`${label} duplicates a keyPackageRef`);
    }
    keyPackageRefs.add(keyPackageRef);
    appendArrayValue(
      parts,
      new Uint8Array([change.kind === 'add' ? 1 : 3]),
    );
    appendArrayValue(parts, lengthPrefixed16(change.memberId));
    appendArrayValue(parts, lengthPrefixed16(change.keyPackageRef));
  }
  return concatBytes(parts);
}

function snapshotGroupStateCiphertext(
  sealed: unknown,
): GroupStateCiphertext {
  const raw = exactPlainDataValues(
    sealed,
    'sealed group state',
    ['nonce', 'ciphertext'],
  );
  return {
    nonce: copyUnsharedUint8Array(
      raw.nonce,
      1,
      MAX_SHORT_BYTES,
      'nonce',
    ),
    ciphertext: copyUnsharedUint8Array(
      raw.ciphertext,
      1,
      MAX_CIPHERTEXT_BYTES,
      'ciphertext',
    ),
  };
}

function snapshotAppliedGroupMembershipDelta(
  delta: AppliedGroupMembershipDelta,
): AppliedGroupMembershipDelta {
  const deltaValues = exactPlainDataValues(
    delta,
    'applied membership delta',
    ['changes'],
  );
  const values = strictArraySnapshot(
    deltaValues.changes,
    'applied membership delta changes',
    0,
    MAX_MEMBERSHIP_CHANGES,
  );
  const changes: AppliedGroupMembershipChange[] = new Array(values.length);
  for (let index = 0; index < values.length; index++) {
    defineEnumerableDataProperty(
      changes,
      index,
      snapshotAppliedMembershipChange(
        values[index],
        `applied membership change ${index}`,
      ),
    );
  }
  return { changes };
}

function snapshotAppliedMembershipChange(
  value: unknown,
  label: string,
): AppliedGroupMembershipChange {
  const descriptors = plainDataDescriptors(value, label);
  const kind = descriptorDataValue(descriptors, 'kind', label);
  const expected =
    kind === 'remove'
      ? ['kind', 'memberId']
      : kind === 'add' || kind === 'update'
        ? ['kind', 'memberId', 'keyPackageRef']
        : undefined;
  if (expected === undefined) {
    throw new Error(`${label} has an invalid kind`);
  }
  requireExactDescriptorKeys(descriptors, label, expected);
  const memberId = copyUnsharedUint8Array(
    descriptorDataValue(descriptors, 'memberId', label),
    1,
    MAX_MEMBER_ID_BYTES,
    `${label} memberId`,
  );
  if (kind === 'remove') return { kind, memberId };
  return {
    kind: kind as 'add' | 'update',
    memberId,
    keyPackageRef: copyUnsharedUint8Array(
      descriptorDataValue(descriptors, 'keyPackageRef', label),
      1,
      MAX_KEY_PACKAGE_REFERENCE_BYTES,
      `${label} keyPackageRef`,
    ),
  };
}

function exactPlainDataValues(
  value: unknown,
  label: string,
  expectedKeys: ReadonlyArray<string>,
): Record<string, unknown> {
  const descriptors = plainDataDescriptors(value, label);
  requireExactDescriptorKeys(descriptors, label, expectedKeys);
  const result: Record<string, unknown> = {};
  for (let index = 0; index < expectedKeys.length; index++) {
    const key = expectedKeys[index];
    defineEnumerableDataProperty(
      result,
      key,
      descriptorDataValue(descriptors, key, label),
    );
  }
  return result;
}

function plainDataDescriptors(
  value: unknown,
  label: string,
): Record<PropertyKey, PropertyDescriptor> {
  if (value === null || typeof value !== 'object') {
    throw new Error(`${label} must be a plain object`);
  }
  try {
    const prototype = objectGetPrototypeOf(value);
    if (prototype !== objectPrototype && prototype !== null) {
      throw new Error(`${label} must be a plain object`);
    }
    return objectGetOwnPropertyDescriptors(value);
  } catch {
    throw new Error(`${label} must be a plain object`);
  }
}

function descriptorDataValue(
  descriptors: Record<PropertyKey, PropertyDescriptor>,
  key: string,
  label: string,
): unknown {
  const descriptor = descriptors[key];
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !('value' in descriptor)
  ) {
    throw new Error(`${label} must contain only enumerable data properties`);
  }
  return descriptor.value;
}

function requireExactDescriptorKeys(
  descriptors: Record<PropertyKey, PropertyDescriptor>,
  label: string,
  expectedKeys: ReadonlyArray<string>,
): void {
  const keys = reflectOwnKeys(descriptors);
  if (keys.length !== expectedKeys.length) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
  for (let index = 0; index < keys.length; index++) {
    const key = keys[index];
    let expected = false;
    if (typeof key === 'string') {
      for (
        let expectedIndex = 0;
        expectedIndex < expectedKeys.length;
        expectedIndex++
      ) {
        if (key === expectedKeys[expectedIndex]) {
          expected = true;
          break;
        }
      }
    }
    if (!expected) {
      throw new Error(`${label} has unexpected or missing fields`);
    }
  }
}

function strictArraySnapshot(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): unknown[] {
  let isArray: boolean;
  let prototype: object | null;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = reflectApply(arrayIsArray, Array, [value]) as boolean;
    prototype = isArray ? objectGetPrototypeOf(value) : null;
    lengthDescriptor = isArray
      ? objectGetOwnPropertyDescriptor(value, 'length')
      : undefined;
  } catch {
    throw new Error(`${label} must be a bounded plain array`);
  }
  const length =
    lengthDescriptor !== undefined && 'value' in lengthDescriptor
      ? lengthDescriptor.value
      : undefined;
  if (
    !isArray ||
    prototype !== arrayPrototype ||
    !numberIsSafeInteger(length) ||
    (length as number) < minimum ||
    (length as number) > maximum
  ) {
    throw new Error('applied membership delta has an invalid change count');
  }
  let keys: PropertyKey[];
  try {
    keys = reflectOwnKeys(value as object);
  } catch {
    throw new Error(`${label} must be a bounded plain array`);
  }
  let hasLength = false;
  for (let index = 0; index < keys.length; index++) {
    if (keys[index] === 'length') {
      hasLength = true;
      break;
    }
  }
  if (keys.length !== (length as number) + 1 || !hasLength) {
    throw new Error(`${label} must not be sparse or contain extra properties`);
  }
  const result = new Array<unknown>(length as number);
  for (let index = 0; index < result.length; index++) {
    const descriptor = objectGetOwnPropertyDescriptor(value, index);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${label} must contain only own data properties`);
    }
    defineEnumerableDataProperty(result, index, descriptor.value);
  }
  return result;
}

function snapshotOwnDataFields(
  value: unknown,
  label: string,
  fields: ReadonlyArray<string>,
): Record<string, unknown> {
  if (value === null || typeof value !== 'object') {
    throw new Error(`${label} must be a plain object`);
  }
  let prototype: object | null;
  try {
    prototype = objectGetPrototypeOf(value);
  } catch {
    throw new Error(`${label} must be a plain object`);
  }
  if (prototype !== objectPrototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  const result: Record<string, unknown> = {};
  for (let index = 0; index < fields.length; index++) {
    const field = fields[index];
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = objectGetOwnPropertyDescriptor(value, field);
    } catch {
      throw new Error(`${label} must contain only own data properties`);
    }
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${label} must contain only own data properties`);
    }
    defineEnumerableDataProperty(result, field, descriptor.value);
  }
  return result;
}

function byteKey(value: Uint8Array): string {
  const hex = '0123456789abcdef';
  let result = '';
  const length = byteLengthOf(value);
  for (let index = 0; index < length; index++) {
    const byte = value[index];
    result += hex[(byte >>> 4) & 0x0f] + hex[byte & 0x0f];
  }
  return result;
}

/** SHA-256 commitment to the domain-separated canonical applied delta. */
export async function appliedGroupMembershipDeltaHash(
  delta: AppliedGroupMembershipDelta,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      canonicalAppliedGroupMembershipDelta(delta) as BufferSource,
    ),
  );
}

function encodeAssociatedData(
  state: GroupSecurityPublicState,
  algorithm: string,
  keyId: string,
): Uint8Array {
  validatePublicState(state);
  validateProtectorIdentity(algorithm, keyId);
  return concatBytes([
    ENCRYPTED_GROUP_STATE_MAGIC,
    encodeU16(ENCRYPTED_GROUP_STATE_VERSION),
    lengthPrefixed16(new TextEncoder().encode(state.protocol.id)),
    encodeU16(state.protocol.version),
    lengthPrefixed16(state.groupId),
    encodeU64(state.epoch),
    lengthPrefixed16(state.confirmedTranscriptHash),
    lengthPrefixed16(state.treeHash),
    lengthPrefixed16(new TextEncoder().encode(algorithm)),
    lengthPrefixed16(new TextEncoder().encode(keyId)),
  ]);
}

function encodeKeyPackageAssociatedData(
  keyPackage: GroupKeyPackage,
  algorithm: string,
  keyId: string,
): Uint8Array {
  validateKeyPackage(keyPackage);
  validateProtectorIdentity(algorithm, keyId);
  return concatBytes([
    ENCRYPTED_KEY_PACKAGE_STATE_MAGIC,
    encodeU16(ENCRYPTED_KEY_PACKAGE_STATE_VERSION),
    lengthPrefixed16(new TextEncoder().encode(keyPackage.protocol.id)),
    encodeU16(keyPackage.protocol.version),
    lengthPrefixed16(keyPackage.groupId),
    lengthPrefixed16(keyPackage.reference),
    lengthPrefixed32(keyPackage.payload),
    lengthPrefixed16(new TextEncoder().encode(algorithm)),
    lengthPrefixed16(new TextEncoder().encode(keyId)),
  ]);
}

function cloneKeyPackage(keyPackage: GroupKeyPackage): GroupKeyPackage {
  const raw = snapshotOwnDataFields(
    keyPackage,
    'KeyPackage',
    ['protocol', 'groupId', 'reference', 'payload'],
  );
  const rawProtocol = snapshotOwnDataFields(
    raw.protocol,
    'KeyPackage protocol',
    ['id', 'version'],
  );
  const snapshot: GroupKeyPackage = {
    protocol: {
      id: rawProtocol.id as string,
      version: rawProtocol.version as number,
    },
    groupId: copyUnsharedUint8Array(
      raw.groupId,
      1,
      MAX_GROUP_ID_BYTES,
      'KeyPackage groupId',
    ),
    reference: copyUnsharedUint8Array(
      raw.reference,
      1,
      MAX_KEY_PACKAGE_REFERENCE_BYTES,
      'KeyPackage reference',
    ),
    payload: copyUnsharedUint8Array(
      raw.payload,
      1,
      MAX_KEY_PACKAGE_PAYLOAD_BYTES,
      'KeyPackage payload',
    ),
  };
  validateKeyPackage(snapshot);
  return snapshot;
}

function validateKeyPackage(keyPackage: GroupKeyPackage): void {
  if (keyPackage === null || typeof keyPackage !== 'object') {
    throw new Error('KeyPackage must be an object');
  }
  validateProtocol(keyPackage.protocol);
  validateBytes(
    keyPackage.groupId,
    'KeyPackage groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  validateBytes(
    keyPackage.reference,
    'KeyPackage reference',
    1,
    MAX_KEY_PACKAGE_REFERENCE_BYTES,
  );
  validateBytes(
    keyPackage.payload,
    'KeyPackage payload',
    1,
    MAX_KEY_PACKAGE_PAYLOAD_BYTES,
  );
}

function clonePublicState(
  state: GroupSecurityPublicState,
): GroupSecurityPublicState {
  const raw = snapshotOwnDataFields(
    state,
    'group public state',
    [
      'protocol',
      'groupId',
      'epoch',
      'confirmedTranscriptHash',
      'treeHash',
    ],
  );
  const rawProtocol = snapshotOwnDataFields(
    raw.protocol,
    'group public state protocol',
    ['id', 'version'],
  );
  const snapshot: GroupSecurityPublicState = {
    protocol: {
      id: rawProtocol.id as string,
      version: rawProtocol.version as number,
    },
    groupId: copyUnsharedUint8Array(
      raw.groupId,
      1,
      MAX_GROUP_ID_BYTES,
      'groupId',
    ),
    epoch: raw.epoch as bigint,
    confirmedTranscriptHash: copyUnsharedUint8Array(
      raw.confirmedTranscriptHash,
      raw.epoch === 0n ? 0 : 1,
      MAX_HASH_BYTES,
      'confirmedTranscriptHash',
    ),
    treeHash: copyUnsharedUint8Array(
      raw.treeHash,
      1,
      MAX_HASH_BYTES,
      'treeHash',
    ),
  };
  validatePublicState(snapshot);
  return snapshot;
}

function validatePublicState(state: GroupSecurityPublicState): void {
  if (state === null || typeof state !== 'object') {
    throw new Error('group public state must be an object');
  }
  validateProtocol(state.protocol);
  validateBytes(state.groupId, 'groupId', 1, MAX_GROUP_ID_BYTES);
  requireU64(state.epoch, 'epoch');
  validateBytes(
    state.confirmedTranscriptHash,
    'confirmedTranscriptHash',
    state.epoch === 0n ? 0 : 1,
    MAX_HASH_BYTES,
  );
  validateBytes(state.treeHash, 'treeHash', 1, MAX_HASH_BYTES);
}

function validateProtocol(protocol: GroupSecurityProtocol): void {
  if (
    protocol === null ||
    typeof protocol !== 'object' ||
    !isCanonicalProtocol(protocol.id, protocol.version)
  ) {
    throw new Error('invalid canonical group-security protocol identifier');
  }
}

function validateProtectorIdentity(algorithm: string, keyId: string): void {
  if (
    !isCanonicalIdentifier(algorithm) ||
    typeof keyId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$/.test(keyId)
  ) {
    throw new Error('invalid group-state protector algorithm/keyId');
  }
}

function validateBytes(
  value: Uint8Array,
  field: string,
  minimum: number,
  maximum: number,
): void {
  let length: number;
  try {
    length = byteLengthOf(value);
  } catch {
    throw new Error(`${field} has an invalid length`);
  }
  if (length < minimum || length > maximum) {
    throw new Error(`${field} has an invalid length`);
  }
}

class ByteReader {
  private offset = 0;
  private readonly bytes: Uint8Array;

  constructor(
    value: Uint8Array,
    private readonly label: string,
    maximumLength: number,
  ) {
    this.bytes = copyUnsharedUint8Array(value, 0, maximumLength, label);
  }

  expect(expected: Uint8Array, field: string): void {
    const actual = this.take(byteLengthOf(expected), field);
    if (!equalBytes(actual, expected)) throw new Error(`invalid ${field}`);
  }

  u16(field: string): number {
    const bytes = this.take(2, field);
    const value = new DataView(bufferOf(bytes), byteOffsetOf(bytes), 2);
    return value.getUint16(0, false);
  }

  u32(field: string): number {
    const bytes = this.take(4, field);
    return new DataView(bufferOf(bytes), byteOffsetOf(bytes), 4).getUint32(
      0,
      false,
    );
  }

  u64(field: string): bigint {
    const bytes = this.take(8, field);
    return new DataView(bufferOf(bytes), byteOffsetOf(bytes), 8).getBigUint64(
      0,
      false,
    );
  }

  bytes16(field: string, minimum: number, maximum: number): Uint8Array {
    const length = this.u16(`${field} length`);
    this.validateLength(length, field, minimum, maximum);
    return new Uint8Array(this.take(length, field));
  }

  bytes32(field: string, minimum: number, maximum: number): Uint8Array {
    const length = this.u32(`${field} length`);
    this.validateLength(length, field, minimum, maximum);
    return new Uint8Array(this.take(length, field));
  }

  string16(field: string): string {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
      this.bytes16(field, 1, MAX_SHORT_BYTES),
    );
    if (!/^[\x20-\x7e]+$/.test(decoded)) {
      throw new Error(`${field} must be printable ASCII`);
    }
    return decoded;
  }

  done(): void {
    if (this.offset !== byteLengthOf(this.bytes)) {
      throw new Error(`${this.label} has trailing bytes`);
    }
  }

  private take(length: number, field: string): Uint8Array {
    if (length < 0 || this.offset + length > byteLengthOf(this.bytes)) {
      throw new Error(`${this.label} is truncated at ${field}`);
    }
    const value = reflectApply(uint8ArraySubarray, this.bytes, [
      this.offset,
      this.offset + length,
    ]) as Uint8Array;
    this.offset += length;
    return value;
  }

  private validateLength(
    length: number,
    field: string,
    minimum: number,
    maximum: number,
  ): void {
    if (length < minimum || length > maximum) {
      throw new Error(`${field} has an invalid length ${length}`);
    }
  }
}
