/**
 * Protocol-neutral group-security contracts.
 *
 * Implementations may wrap a reviewed group-security protocol. These types do
 * not implement or claim interoperability with any particular protocol.
 */

const ENCRYPTED_GROUP_STATE_MAGIC = new Uint8Array([
  0x53, 0x57, 0x4d, 0x47, 0x53, 0x30, 0x30, 0x31,
]);
const ENCRYPTED_KEY_PACKAGE_STATE_MAGIC = new Uint8Array([
  0x53, 0x57, 0x4d, 0x4b, 0x50, 0x30, 0x30, 0x31,
]);
const APPLIED_MEMBERSHIP_DELTA_DOMAIN = asciiBytes(
  'peerborne/group-security-applied-membership-delta/v1\0',
);

function asciiBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit > 0x7f) {
      throw new TypeError('group-security domain separators must be ASCII');
    }
    bytes[index] = codeUnit;
  }
  return bytes;
}

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
const MAX_U64 = (1n << 64n) - 1n;
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
const uint8ArraySet = Uint8Array.prototype.set;
const typedArrayPrototype = objectGetPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthValue = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)?.get;
const typedArrayByteOffsetValue = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteOffset',
)?.get;
const typedArrayBufferValue = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const typedArrayTagValue = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const sharedArrayBufferByteLength =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : objectGetOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )?.get;

if (
  typedArrayByteLengthValue === undefined ||
  typedArrayByteOffsetValue === undefined ||
  typedArrayBufferValue === undefined ||
  typedArrayTagValue === undefined
) {
  throw new Error('group-security Uint8Array intrinsics are unavailable');
}
const typedArrayByteLength = typedArrayByteLengthValue;
const typedArrayByteOffset = typedArrayByteOffsetValue;
const typedArrayBuffer = typedArrayBufferValue;
const typedArrayTag = typedArrayTagValue;

export interface GroupSecurityProtocol {
  readonly id: string;
  readonly version: number;
}

export interface GroupSecurityPublicState {
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
  readonly epoch: bigint;
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

export interface GroupSecurityApplyResult {
  readonly status: 'applied' | 'duplicate';
  readonly state: GroupSecurityPublicState;
  readonly appliedMembership: AppliedGroupMembershipDelta;
}

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
  /** Received Add/Update credentials must be authenticated before applying. */
  applyCommit(commit: GroupSecurityCommit): Promise<GroupSecurityApplyResult>;
  exportSecret(input: ExportGroupSecretInput): Promise<Uint8Array>;
  getPublicState(): Promise<GroupSecurityPublicState>;
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
    const privateStateSnapshot = snapshotBoundedBytes(
      privateState,
      'private KeyPackage state',
      1,
      MAX_CIPHERTEXT_BYTES,
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
    return snapshotBoundedBytes(
      plaintext,
      'opened private KeyPackage state',
      1,
      MAX_CIPHERTEXT_BYTES,
    );
  }

  serialize(): Uint8Array {
    return concat([
      encodeKeyPackageAssociatedData(
        this.#keyPackageValue,
        this.#algorithm,
        this.#keyId,
      ),
      u16(this.#nonceValue.byteLength),
      this.#nonceValue,
      u32(this.#ciphertextValue.byteLength),
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
    Object.getPrototypeOf(value) === encryptedKeyPackageStatePrototype &&
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
    Object.getOwnPropertyDescriptor(
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
    const privateStateSnapshot = snapshotBoundedBytes(
      privateState,
      'privateState',
      1,
      MAX_CIPHERTEXT_BYTES,
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
    return snapshotBoundedBytes(
      plaintext,
      'opened private group state',
      1,
      MAX_CIPHERTEXT_BYTES,
    );
  }

  serialize(): Uint8Array {
    const associatedData = encodeAssociatedData(
      this.#stateValue,
      this.#algorithm,
      this.#keyId,
    );
    return concat([
      associatedData,
      u16(this.#nonceValue.byteLength),
      this.#nonceValue,
      u32(this.#ciphertextValue.byteLength),
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
    const state: GroupSecurityPublicState = {
      protocol: {
        id: reader.string16('protocol.id'),
        version: reader.u16('protocol.version'),
      },
      groupId: reader.bytes16('groupId', 1, MAX_GROUP_ID_BYTES),
      epoch: reader.u64('epoch'),
      confirmedTranscriptHash: reader.bytes16(
        'confirmedTranscriptHash',
        1,
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
    Object.getPrototypeOf(value) === encryptedGroupStatePrototype &&
    !hasOwnEnvelopeOverride(value, [
      'state',
      'algorithm',
      'keyId',
      'nonce',
      'ciphertext',
      'open',
      'serialize',
    ]) &&
    Object.getOwnPropertyDescriptor(
      encryptedGroupStatePrototype,
      'serialize',
    )?.value === encryptedGroupStateSerialize
  );
}

function hasOwnEnvelopeOverride(
  value: object,
  properties: ReadonlyArray<string>,
): boolean {
  return properties.some((property) =>
    Object.prototype.hasOwnProperty.call(value, property),
  );
}

/** Canonical, protocol-neutral encoding used to bind provider-applied changes. */
export function canonicalAppliedGroupMembershipDelta(
  delta: AppliedGroupMembershipDelta,
): Uint8Array {
  const snapshot = snapshotAppliedGroupMembershipDelta(delta);
  const parts: Uint8Array[] = [
    APPLIED_MEMBERSHIP_DELTA_DOMAIN,
    u16(snapshot.changes.length),
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
      parts.push(new Uint8Array([2]), bytes16(change.memberId));
      continue;
    }
    const keyPackageRef = byteKey(change.keyPackageRef);
    if (keyPackageRefs.has(keyPackageRef)) {
      throw new Error(`${label} duplicates a keyPackageRef`);
    }
    keyPackageRefs.add(keyPackageRef);
    parts.push(
      new Uint8Array([change.kind === 'add' ? 1 : 3]),
      bytes16(change.memberId),
      bytes16(change.keyPackageRef),
    );
  }
  return concat(parts);
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
    nonce: snapshotBoundedBytes(
      raw.nonce,
      'nonce',
      1,
      MAX_SHORT_BYTES,
    ),
    ciphertext: snapshotBoundedBytes(
      raw.ciphertext,
      'ciphertext',
      1,
      MAX_CIPHERTEXT_BYTES,
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
    1,
    MAX_MEMBERSHIP_CHANGES,
  );
  const changes: AppliedGroupMembershipChange[] = new Array(values.length);
  for (let index = 0; index < values.length; index++) {
    changes[index] = snapshotAppliedMembershipChange(
      values[index],
      `applied membership change ${index}`,
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
  const memberId = snapshotBoundedBytes(
    descriptorDataValue(descriptors, 'memberId', label),
    `${label} memberId`,
    1,
    MAX_MEMBER_ID_BYTES,
  );
  if (kind === 'remove') return { kind, memberId };
  return {
    kind: kind as 'add' | 'update',
    memberId,
    keyPackageRef: snapshotBoundedBytes(
      descriptorDataValue(descriptors, 'keyPackageRef', label),
      `${label} keyPackageRef`,
      1,
      MAX_KEY_PACKAGE_REFERENCE_BYTES,
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
  for (const key of expectedKeys) {
    result[key] = descriptorDataValue(descriptors, key, label);
  }
  return result;
}

function plainDataDescriptors(
  value: unknown,
  label: string,
): Record<PropertyKey, PropertyDescriptor> {
  if (
    value === null ||
    typeof value !== 'object' ||
    objectGetPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label} must be a plain object`);
  }
  return objectGetOwnPropertyDescriptors(value);
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
  const keys = Reflect.ownKeys(descriptors);
  const expected = new Set(expectedKeys);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== 'string' || !expected.has(key))
  ) {
    throw new Error(`${label} has unexpected or missing fields`);
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
    isArray = Array.isArray(value);
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
    prototype !== Array.prototype ||
    !Number.isSafeInteger(length) ||
    (length as number) < minimum ||
    (length as number) > maximum
  ) {
    throw new Error('applied membership delta has an invalid change count');
  }
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value as object);
  } catch {
    throw new Error(`${label} must be a bounded plain array`);
  }
  if (keys.length !== (length as number) + 1 || !keys.includes('length')) {
    throw new Error(`${label} must not be sparse or contain extra properties`);
  }
  const result = new Array<unknown>(length as number);
  for (let index = 0; index < result.length; index++) {
    const descriptor = objectGetOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${label} must contain only own data properties`);
    }
    result[index] = descriptor.value;
  }
  return result;
}

function snapshotBoundedBytes(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): Uint8Array {
  let length: number;
  let byteOffset: number;
  let buffer: ArrayBufferLike;
  let tag: unknown;
  try {
    length = Reflect.apply(typedArrayByteLength, value, []) as number;
    byteOffset = Reflect.apply(typedArrayByteOffset, value, []) as number;
    buffer = Reflect.apply(typedArrayBuffer, value, []) as ArrayBufferLike;
    tag = Reflect.apply(typedArrayTag, value, []);
  } catch {
    throw new Error(`${field} must be a genuine Uint8Array`);
  }
  let shared = false;
  if (sharedArrayBufferByteLength !== undefined) {
    try {
      Reflect.apply(sharedArrayBufferByteLength, buffer, []);
      shared = true;
    } catch {
      shared = false;
    }
  }
  if (tag !== 'Uint8Array' || length < minimum || length > maximum || shared) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  try {
    const stableView = new Uint8Array(buffer, byteOffset, length);
    const result = new Uint8Array(length);
    Reflect.apply(uint8ArraySet, result, [stableView]);
    return result;
  } catch {
    throw new Error(`${field} could not be copied safely`);
  }
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
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  const result: Record<string, unknown> = {};
  for (const field of fields) {
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
    result[field] = descriptor.value;
  }
  return result;
}

function byteKey(value: Uint8Array): string {
  let result = '';
  for (let index = 0; index < value.byteLength; index++) {
    result += value[index].toString(16).padStart(2, '0');
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
  return concat([
    ENCRYPTED_GROUP_STATE_MAGIC,
    u16(ENCRYPTED_GROUP_STATE_VERSION),
    bytes16(new TextEncoder().encode(state.protocol.id)),
    u16(state.protocol.version),
    bytes16(state.groupId),
    u64(state.epoch),
    bytes16(state.confirmedTranscriptHash),
    bytes16(state.treeHash),
    bytes16(new TextEncoder().encode(algorithm)),
    bytes16(new TextEncoder().encode(keyId)),
  ]);
}

function encodeKeyPackageAssociatedData(
  keyPackage: GroupKeyPackage,
  algorithm: string,
  keyId: string,
): Uint8Array {
  validateKeyPackage(keyPackage);
  validateProtectorIdentity(algorithm, keyId);
  return concat([
    ENCRYPTED_KEY_PACKAGE_STATE_MAGIC,
    u16(ENCRYPTED_KEY_PACKAGE_STATE_VERSION),
    bytes16(new TextEncoder().encode(keyPackage.protocol.id)),
    u16(keyPackage.protocol.version),
    bytes16(keyPackage.groupId),
    bytes16(keyPackage.reference),
    bytes32(keyPackage.payload),
    bytes16(new TextEncoder().encode(algorithm)),
    bytes16(new TextEncoder().encode(keyId)),
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
    groupId: snapshotBoundedBytes(
      raw.groupId,
      'KeyPackage groupId',
      1,
      MAX_GROUP_ID_BYTES,
    ),
    reference: snapshotBoundedBytes(
      raw.reference,
      'KeyPackage reference',
      1,
      MAX_KEY_PACKAGE_REFERENCE_BYTES,
    ),
    payload: snapshotBoundedBytes(
      raw.payload,
      'KeyPackage payload',
      1,
      MAX_KEY_PACKAGE_PAYLOAD_BYTES,
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
    groupId: snapshotBoundedBytes(
      raw.groupId,
      'groupId',
      1,
      MAX_GROUP_ID_BYTES,
    ),
    epoch: raw.epoch as bigint,
    confirmedTranscriptHash: snapshotBoundedBytes(
      raw.confirmedTranscriptHash,
      'confirmedTranscriptHash',
      1,
      MAX_HASH_BYTES,
    ),
    treeHash: snapshotBoundedBytes(
      raw.treeHash,
      'treeHash',
      1,
      MAX_HASH_BYTES,
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
  validateU64(state.epoch, 'epoch');
  validateBytes(
    state.confirmedTranscriptHash,
    'confirmedTranscriptHash',
    1,
    MAX_HASH_BYTES,
  );
  validateBytes(state.treeHash, 'treeHash', 1, MAX_HASH_BYTES);
}

function validateProtocol(protocol: GroupSecurityProtocol): void {
  if (
    protocol === null ||
    typeof protocol !== 'object' ||
    typeof protocol.id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(protocol.id) ||
    !Number.isInteger(protocol.version) ||
    protocol.version < 0 ||
    protocol.version > 0xffff
  ) {
    throw new Error('invalid canonical group-security protocol identifier');
  }
}

function validateProtectorIdentity(algorithm: string, keyId: string): void {
  if (
    typeof algorithm !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(algorithm) ||
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
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < minimum ||
    value.byteLength > maximum
  ) {
    throw new Error(`${field} has an invalid length`);
  }
}

function validateU64(value: bigint, field: string): void {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
}

function bytes16(value: Uint8Array): Uint8Array {
  if (value.byteLength > 0xffff) throw new Error('value does not fit in u16');
  return concat([u16(value.byteLength), value]);
}

function bytes32(value: Uint8Array): Uint8Array {
  if (value.byteLength > 0xffffffff) {
    throw new Error('value does not fit in u32');
  }
  return concat([u32(value.byteLength), value]);
}

function u16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('value does not fit in u16');
  }
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}

function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('value does not fit in u32');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64(value: bigint): Uint8Array {
  validateU64(value, 'epoch');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

class ByteReader {
  private offset = 0;
  private readonly bytes: Uint8Array;

  constructor(
    value: Uint8Array,
    private readonly label: string,
    maximumLength: number,
  ) {
    this.bytes = snapshotBoundedBytes(value, label, 0, maximumLength);
  }

  expect(expected: Uint8Array, field: string): void {
    const actual = this.take(expected.byteLength, field);
    if (!equalBytes(actual, expected)) throw new Error(`invalid ${field}`);
  }

  u16(field: string): number {
    const value = new DataView(
      this.take(2, field).buffer,
      this.bytes.byteOffset + this.offset - 2,
      2,
    );
    return value.getUint16(0, false);
  }

  u32(field: string): number {
    const start = this.offset;
    this.take(4, field);
    return new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset + start,
      4,
    ).getUint32(0, false);
  }

  u64(field: string): bigint {
    const start = this.offset;
    this.take(8, field);
    return new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset + start,
      8,
    ).getBigUint64(0, false);
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
    if (this.offset !== this.bytes.byteLength) {
      throw new Error(`${this.label} has trailing bytes`);
    }
  }

  private take(length: number, field: string): Uint8Array {
    if (length < 0 || this.offset + length > this.bytes.byteLength) {
      throw new Error(`${this.label} is truncated at ${field}`);
    }
    const value = this.bytes.subarray(this.offset, this.offset + length);
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

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let different = 0;
  for (let i = 0; i < a.byteLength; i++) different |= a[i] ^ b[i];
  return different === 0;
}
