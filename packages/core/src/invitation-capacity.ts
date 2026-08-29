import type { CRDTSyncMessage } from './crdt-sync-message.js';
import type { CRDTSnapshotNode } from './snapshot-node.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import type { BeeKEMWelcome } from './beekem/types.js';
import { MAX_INVITATION_OPAQUE_PAYLOAD_BYTES } from './invitation-wire.js';

/** Tested/attested provider combination with a founder-plus-one size bound. */
export const INITIAL_INVITATION_CAPACITY_PROFILE =
  'peerborne-automerge-json-subtle-p384-v1' as const;

/**
 * Maximum growth of the serialized sync-message bytes caused by the attested
 * founder-plus-editor ACL nodes and their resulting served frontier. The
 * adversarial maximum-cross-link fixture measures 4,033 bytes; retain
 * versioning margin.
 */
export const INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES = 16 * 1024;

/** WebCrypto P-384 emits a fixed-width 96-byte ECDSA signature. */
export const INITIAL_INVITATION_MAX_SIGNATURE_BYTES = 96;

/** 32-byte epoch prefix + 12-byte nonce + 16-byte AES-GCM tag. */
export const INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES = 60;

/** Two-member BeeKEM JSON plus ECIES framing measures 845 bytes. */
export const INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES = 4 * 1024;

/** Additional margin for framing and future compatible wire additions. */
export const INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES = 128 * 1024;

export interface InitialInvitationCapacityProfileDeclaration {
  readonly initialInvitationCapacityProfile: typeof INITIAL_INVITATION_CAPACITY_PROFILE;
}

export interface InitialInvitationAuthCapacityDeclaration<
  PrivateKey,
  PublicKey,
> extends InitialInvitationCapacityProfileDeclaration {
  supportsInitialInvitationCapacity(
    privateKey: PrivateKey,
    publicKey: PublicKey,
  ): boolean;
}

export interface InitialInvitationCapacityComponents<PrivateKey, PublicKey> {
  readonly crdtProvider: unknown;
  readonly aclProvider: unknown;
  readonly keychainProvider: { readonly keyIDLength: number };
  readonly changesSerializer: unknown;
  readonly syncMessageSerializer: unknown;
  readonly authProvider: unknown;
  readonly privateKey: PrivateKey;
  readonly publicKey: PublicKey;
}

function declaresCapacityProfile(
  value: unknown,
): value is InitialInvitationCapacityProfileDeclaration {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Partial<InitialInvitationCapacityProfileDeclaration>)
      .initialInvitationCapacityProfile ===
      INITIAL_INVITATION_CAPACITY_PROFILE
  );
}

/**
 * Fail closed unless every size-sensitive provider attests to the one profile
 * whose invitation growth is bounded and covered by tests.
 */
export function assertInitialInvitationCapacityProfile<PrivateKey, PublicKey>(
  components: InitialInvitationCapacityComponents<PrivateKey, PublicKey>,
): void {
  const profileComponents: ReadonlyArray<readonly [string, unknown]> = [
    ['CRDT provider', components.crdtProvider],
    ['ACL provider', components.aclProvider],
    ['keychain provider', components.keychainProvider],
    ['changes serializer', components.changesSerializer],
    ['sync-message serializer', components.syncMessageSerializer],
    ['authentication provider', components.authProvider],
  ];
  const unsupported = profileComponents.find(
    ([, component]) => !declaresCapacityProfile(component),
  );
  if (unsupported) {
    throw new Error(
      `Initial-release invitations require the tested/attested Automerge JSON ` +
        `and SubtleCrypto capacity profile; unsupported ${unsupported[0]}`,
    );
  }
  if (components.keychainProvider.keyIDLength !== 32) {
    throw new Error(
      'Initial-release invitations require the attested 32-byte key-ID profile',
    );
  }

  const auth = components.authProvider as Partial<
    InitialInvitationAuthCapacityDeclaration<PrivateKey, PublicKey>
  >;
  if (
    typeof auth.supportsInitialInvitationCapacity !== 'function' ||
    !auth.supportsInitialInvitationCapacity(
      components.privateKey,
      components.publicKey,
    )
  ) {
    throw new Error(
      'Initial-release invitations require P-384 signing keys and the supported SubtleCrypto profile',
    );
  }
}

/** @internal Reject Welcome trees outside the measured founder-plus-one shape. */
export function assertInitialInvitationBeeKEMWelcomeShape(
  welcome: BeeKEMWelcome,
): void {
  const pathKey = welcome.pathKeys[0];
  const founderLeaf = welcome.treeNodePublicKeys[0];
  if (
    welcome.leafIndex !== 2 ||
    welcome.pathKeys.length !== 1 ||
    pathKey?.nodeIndex !== 1 ||
    welcome.treeNodePublicKeys.length !== 1 ||
    founderLeaf?.nodeIndex !== 0 ||
    founderLeaf.publicKey === null ||
    welcome.treeHash.byteLength !== 32
  ) {
    throw new Error(
      'Invitation BeeKEM Welcome is outside the bounded founder-plus-one topology',
    );
  }
}

/** @internal Keep the sealed-Welcome proof within its tested tree shape. */
export function assertInitialInvitationBeeKEMCapacity(
  memberCount: number | undefined,
  readerAlreadyPresent: boolean,
  documentPath: string,
  hasRetryLeaf = false,
  hasRetryWelcome = false,
): void {
  if (memberCount === undefined || memberCount === 1) return;
  if (
    memberCount === 2 &&
    readerAlreadyPresent &&
    hasRetryLeaf &&
    hasRetryWelcome
  ) {
    return;
  }
  if (memberCount === 2 && readerAlreadyPresent) {
    throw new Error(
      `Invitation bootstrap for ${documentPath} cannot safely retry because ` +
        'the existing BeeKEM leaf or cached Welcome is unavailable',
    );
  }
  throw new Error(
    `Invitation bootstrap for ${documentPath} cannot use a BeeKEM tree ` +
      'beyond the bounded initial founder-plus-one topology',
  );
}

export interface InitialInvitationCapacityProjection {
  readonly serializedBaselineBytes: number;
  readonly membershipGrowthBytes: number;
  readonly encryptionOverheadBytes: number;
  readonly reserveBytes: number;
  readonly projectedEncryptedBootstrapBytes: number;
}

export interface ProjectInitialInvitationCapacityOptions<
  ChangesType,
  PublicKey,
> {
  readonly currentMessage: CRDTSyncMessage<ChangesType, PublicKey>;
  readonly keychainChanges: ChangesType;
  readonly snapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  readonly tips: readonly string[];
  readonly serializer: SyncMessageSerializer<ChangesType, PublicKey>;
}

function base64Length(rawBytes: number): number {
  return 4 * Math.ceil(rawBytes / 3);
}

/** Build and size the complete pre-membership bootstrap baseline once. */
export function projectInitialInvitationBootstrapCapacity<
  ChangesType,
  PublicKey,
>(
  options: ProjectInitialInvitationCapacityOptions<ChangesType, PublicKey>,
): InitialInvitationCapacityProjection {
  const projected: CRDTSyncMessage<ChangesType, PublicKey> = {
    ...options.currentMessage,
    keychainChanges: options.keychainChanges,
    tips: Array.from(options.tips),
    signature: 'A'.repeat(
      base64Length(INITIAL_INVITATION_MAX_SIGNATURE_BYTES),
    ),
  };
  if (options.snapshot !== undefined) {
    projected.snapshot = options.snapshot;
  } else {
    delete projected.snapshot;
  }

  const serializedBaselineBytes =
    options.serializer.serializeSyncMessage(projected).byteLength;
  const projectedEncryptedBootstrapBytes =
    serializedBaselineBytes +
    INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES +
    INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES +
    INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES;

  return {
    serializedBaselineBytes,
    membershipGrowthBytes:
      INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
    encryptionOverheadBytes:
      INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
    reserveBytes: INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES,
    projectedEncryptedBootstrapBytes,
  };
}

export function assertProjectedInitialInvitationBootstrapCapacity(
  projection: InitialInvitationCapacityProjection,
  documentPath: string,
): void {
  if (
    projection.projectedEncryptedBootstrapBytes >
    MAX_INVITATION_OPAQUE_PAYLOAD_BYTES
  ) {
    throw new Error(
      `Invitation bootstrap for ${documentPath} is too large before onboarding`,
    );
  }
}

/** Bound the full-history Welcome before BeeKEM membership is changed. */
export function assertProjectedInitialInvitationWelcomeCapacity(
  welcomeWithoutBeeKEMBytes: number,
  documentPath: string,
): void {
  const projectedSealedWelcomeBytes =
    welcomeWithoutBeeKEMBytes +
    INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES +
    INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES;
  if (projectedSealedWelcomeBytes > MAX_INVITATION_OPAQUE_PAYLOAD_BYTES) {
    throw new Error(
      `Invitation Welcome for ${documentPath} is too large before onboarding`,
    );
  }
}

/** Final defense-in-depth check over the exact opaque wire field. */
export function assertInvitationOpaquePayloadCapacity(
  payload: Uint8Array,
  label: 'Welcome' | 'bootstrap',
  documentPath: string,
): void {
  if (payload.byteLength > MAX_INVITATION_OPAQUE_PAYLOAD_BYTES) {
    throw new Error(
      `Invitation ${label} for ${documentPath} exceeds the ` +
        `${MAX_INVITATION_OPAQUE_PAYLOAD_BYTES}-byte wire limit`,
    );
  }
}
