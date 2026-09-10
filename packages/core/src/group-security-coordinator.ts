import {
  AppliedGroupMembershipChange,
  AppliedGroupMembershipDelta,
  CreateGroupCommitInput,
  CreateGroupInput,
  CreateKeyPackageInput,
  EncryptedGroupState,
  EncryptedKeyPackageState,
  GroupSecurityApplyResult,
  GroupSecurityCommit,
  GroupSecurityCommitResult,
  GroupKeyPackage,
  GroupSecurityProvider,
  GroupSecurityPublicState,
  GroupSecurityProtocol,
  GroupStateProtector,
  GroupWelcome,
  JoinGroupInput,
  appliedGroupMembershipDeltaHash,
  canonicalAppliedGroupMembershipDelta,
  isEncryptedGroupState,
  isEncryptedKeyPackageState,
} from './group-security-provider.js';
import {
  DurableGroupStateStore,
  GroupStateForkEvidence,
  GroupStateOutboxEntry,
  GroupStateReplayEntry,
  GroupStateStoreKey,
  GroupStateStoreSnapshot,
  GroupStateStoreTransaction,
  MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
} from './group-state-store.js';
import {
  DurableGroupSecurityRollbackAnchor,
  GroupSecurityRollbackForkPoison,
  GroupSecurityRollbackAnchorValue,
  cloneGroupSecurityRollbackAnchor,
  groupSecurityRollbackAnchorsEqual,
} from './group-security-rollback-anchor.js';
import {
  GroupSecurityDurableAcceptance,
  validateGroupSecurityDurableAcceptance,
} from './group-security-durable-acceptance.js';
import {
  groupSecurityStoreSnapshotCommitment,
  validateAndCloneGroupStateStoreSnapshot,
} from './group-security-store-commitment.js';
import {
  MEMBERSHIP_CONTROL_VERSION,
  MembershipControlAction,
  MembershipControlAuthorizationContext,
  MembershipControlAuthorizer,
  MembershipControlChain,
  MembershipControlRecord,
  MembershipControlSignatureVerifier,
  MembershipControlSigner,
  UnsignedMembershipControlRecord,
  canonicalMembershipControlPayload,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
  signMembershipControlRecord,
} from './membership-control-record.js';

const COMMIT_DOMAIN = asciiBytes(
  'peerborne/group-security-commit/v1\0',
);
const CONTROL_BINDING_DOMAIN = asciiBytes(
  'peerborne/group-security-control-binding/v2\0',
);
const GENESIS_DOMAIN = asciiBytes(
  'peerborne/group-security-genesis/v1\0',
);
const WELCOME_SET_DOMAIN = asciiBytes(
  'peerborne/group-security-welcome-set/v1\0',
);
const KEY_PACKAGE_REQUEST_DOMAIN = asciiBytes(
  'peerborne/group-security-key-package-request/v1\0',
);
const FORK_POISON_DOMAIN = asciiBytes(
  'peerborne/group-security-fork-poison/v1\0',
);
const FORK_AMBIGUITY_DOMAIN = asciiBytes(
  'peerborne/group-security-fork-ambiguity/v1\0',
);
const FIRST_ANCHOR_AMBIGUITY_DOMAIN = asciiBytes(
  'peerborne/group-security-first-anchor-ambiguity/v1\0',
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

export const GROUP_SECURITY_OUTBOX_KIND = 'group-security.transition.v1';
export const DEFAULT_GROUP_SECURITY_MAX_OUTBOX_ENTRIES = 256;
export const DEFAULT_GROUP_SECURITY_MAX_REPLAY_ENTRIES = 2048;
export const DEFAULT_GROUP_SECURITY_REPLAY_WINDOW_EPOCHS = 1024n;
export const DEFAULT_GROUP_SECURITY_OUTBOX_DELIVERY_TIMEOUT_MS = 30_000;

const MAX_CONFIGURED_ENTRIES = 65_536;
const MAX_OUTBOX_DELIVERY_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_GROUP_ID_BYTES = 1024;
const MAX_IDENTITY_BYTES = 512;
const MAX_PROTOCOL_PAYLOAD_BYTES = 1024 * 1024;
const MAX_CONTROL_PAYLOAD_BYTES = 2 * 1024 * 1024;
const MAX_CONTROL_SIGNATURE_BYTES = 4096;
const MAX_OUTBOX_PAYLOAD_BYTES = 16 * 1024 * 1024;
const MAX_WELCOMES = 4096;
const MAX_MEMBERSHIP_CHANGES = 4096;
const MAX_CANONICAL_WELCOME_SET_BYTES = 1024 * 1024;
const MAX_CONTROL_PREFIX_BYTES = MAX_GROUP_STATE_STORE_COMMITTED_BYTES;
const FIXED_ID_LENGTH = 32;
const GENESIS_FORK_PARENT_ID = new Uint8Array(FIXED_ID_LENGTH);
const MAX_U64 = (1n << 64n) - 1n;
const mapSizeGetterValue = Object.getOwnPropertyDescriptor(
  Map.prototype,
  'size',
)?.get;
const mapEntries = Map.prototype.entries;
const uint8ArraySet = Uint8Array.prototype.set;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)?.get;
const typedArrayByteOffsetGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteOffset',
)?.get;
const typedArrayBufferGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const typedArrayTagGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const sharedArrayBufferByteLengthGetter =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )?.get;

if (
  mapSizeGetterValue === undefined ||
  typedArrayByteLengthGetterValue === undefined ||
  typedArrayByteOffsetGetterValue === undefined ||
  typedArrayBufferGetterValue === undefined ||
  typedArrayTagGetterValue === undefined
) {
  throw new Error('required collection/byte intrinsics are unavailable');
}
const mapSizeGetter = mapSizeGetterValue;
const typedArrayByteLengthGetter = typedArrayByteLengthGetterValue;
const typedArrayByteOffsetGetter = typedArrayByteOffsetGetterValue;
const typedArrayBufferGetter = typedArrayBufferGetterValue;
const typedArrayTagGetter = typedArrayTagGetterValue;

export interface GroupSecurityDelivery {
  readonly controlRecord: MembershipControlRecord;
  readonly commit?: GroupSecurityCommit;
  readonly welcomes: ReadonlyArray<GroupWelcome>;
}

/** Injected durable/network encoding; the coordinator defines no wire format. */
export interface GroupSecurityOutboxCodec {
  encode(delivery: GroupSecurityDelivery): Uint8Array;
  decode(payload: Uint8Array): GroupSecurityDelivery;
}

export interface GroupSecurityCoordinatorConfig {
  readonly provider: GroupSecurityProvider;
  readonly store: DurableGroupStateStore;
  readonly storeKey: GroupStateStoreKey;
  readonly rollbackAnchor: DurableGroupSecurityRollbackAnchor;
  readonly protector: GroupStateProtector;
  readonly actorId: Uint8Array;
  readonly signControlRecord: MembershipControlSigner;
  readonly verifyControlSignature: MembershipControlSignatureVerifier;
  readonly authorizeControl: MembershipControlAuthorizer;
  readonly outboxCodec: GroupSecurityOutboxCodec;
  readonly maxOutboxEntries?: number;
  readonly maxReplayEntries?: number;
  readonly replayWindowEpochs?: bigint;
  readonly outboxDeliveryTimeoutMs?: number;
  readonly now?: () => number;
}

/**
 * Metadata for exactly one cryptographic add/remove/update. A role-only change
 * that produces no provider membership delta is intentionally not accepted.
 */
export interface GroupSecurityControlInput {
  readonly operationId: Uint8Array;
  /** Caller-computed digest of the exact opaque commit request/intent. */
  readonly requestDigest: Uint8Array;
  readonly action: Exclude<MembershipControlAction, 'create'>;
  readonly subjectId: Uint8Array;
}

export interface GroupSecurityBootstrapControlInput {
  readonly operationId: Uint8Array;
  readonly subjectId: Uint8Array;
}

/** Caller-stable request used to resume an ambiguous KeyPackage write. */
export interface CreatePendingKeyPackageInput
  extends Omit<CreateKeyPackageInput, 'requestCommitment'> {
  readonly operationId: Uint8Array;
}

/** Authenticated material required for a one-time recipient join. */
export interface GroupSecurityJoinInvitation {
  readonly subjectId: Uint8Array;
  readonly keyPackageRef: Uint8Array;
  readonly controlPrefix: ReadonlyArray<MembershipControlRecord>;
  readonly commit: GroupSecurityCommit;
  readonly welcome: GroupWelcome;
  readonly authenticatedData?: Uint8Array;
}

export type GroupSecurityTransitionResult =
  | {
      readonly status: 'committed';
      readonly recordId: Uint8Array;
      readonly controlRecord: MembershipControlRecord;
      readonly state: GroupSecurityPublicState;
    }
  | { readonly status: 'duplicate'; readonly recordId: Uint8Array };

export interface GroupSecurityFlushResult {
  readonly delivered: number;
  readonly remaining: number;
}

export type GroupSecurityCoordinatorFailure =
  | 'not-initialized'
  | 'already-initialized'
  | 'protocol-mismatch'
  | 'group-mismatch'
  | 'epoch-mismatch'
  | 'control-mismatch'
  | 'bad-signature'
  | 'unauthorized-control'
  | 'operation-conflict'
  | 'stale-replay'
  | 'fork-detected'
  | 'outbox-overflow'
  | 'replay-overflow'
  | 'store-conflict'
  | 'malformed-state'
  | 'delivery-failed'
  | 'rollback-detected'
  | 'rollback-unavailable'
  | 'rollback-failed'
  | 'poisoned';

export class GroupSecurityCoordinatorError extends Error {
  constructor(
    readonly code: GroupSecurityCoordinatorFailure,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'GroupSecurityCoordinatorError';
  }
}

interface CoordinatorView {
  publicState: GroupSecurityPublicState;
  replay: GroupStateReplayEntry[];
  operationToRecord: Map<string, string>;
  recordsById: Map<string, MembershipControlRecord>;
  recordIds: Set<string>;
  headRecordId: Uint8Array;
  lastControlRecord: MembershipControlRecord;
}

interface ValidatedControl {
  status: 'new' | 'duplicate';
  recordId: Uint8Array;
  stateCommitment: GroupSecurityStateCommitment;
}

interface GroupSecurityStateCommitment {
  confirmedTranscriptHash: Uint8Array;
  treeHash: Uint8Array;
  appliedMembershipDeltaHash: Uint8Array;
  welcomeSetHash: Uint8Array;
}

interface VerifiedJoinInvitation {
  readonly records: ReadonlyArray<MembershipControlRecord>;
  readonly recordIds: ReadonlyArray<Uint8Array>;
  readonly finalRecord: MembershipControlRecord;
  readonly finalRecordId: Uint8Array;
  readonly stateCommitment: GroupSecurityStateCommitment;
}

interface AmbiguousStoreFailure {
  readonly cause: unknown;
}

const providerLifecycleTails = new WeakMap<object, Promise<void>>();
const permanentlyOwnedProviders = new WeakSet<object>();
const observedProviderLifecycleIdentities = new WeakMap<
  GroupSecurityProvider,
  object
>();

/**
 * Serializes one group's state transitions and enforces bounded durable
 * outbox/replay retention. The injected store is otherwise intentionally
 * unbounded.
 */
export class GroupSecurityCoordinator {
  private mutationTail: Promise<unknown> = Promise.resolve();
  private view!: CoordinatorView;
  private storeRevision = 0;
  private rollbackAnchorValue?: GroupSecurityRollbackAnchorValue;
  private poisonedReason?: Error;
  private forkReason?: GroupSecurityCoordinatorError;

  private readonly provider: GroupSecurityProvider;
  private readonly store: DurableGroupStateStore;
  private readonly storeKey: GroupStateStoreKey;
  private readonly rollbackAnchor: DurableGroupSecurityRollbackAnchor;
  private readonly protector: GroupStateProtector;
  private readonly actorId: Uint8Array;
  private readonly signControlRecord: MembershipControlSigner;
  private readonly verifyControlSignature: MembershipControlSignatureVerifier;
  private readonly authorizeControl: MembershipControlAuthorizer;
  private readonly outboxCodec: GroupSecurityOutboxCodec;
  private readonly maxOutboxEntries: number;
  private readonly maxReplayEntries: number;
  private readonly replayWindowEpochs: bigint;
  private readonly outboxDeliveryTimeoutMs: number;
  private readonly now: () => number;

  private constructor(config: GroupSecurityCoordinatorConfig) {
    const snapshot = snapshotCoordinatorConfig(config);
    this.provider = snapshot.provider;
    this.store = snapshot.store;
    this.storeKey = snapshot.storeKey;
    this.rollbackAnchor = snapshot.rollbackAnchor;
    this.protector = snapshot.protector;
    this.actorId = snapshot.actorId;
    this.signControlRecord = snapshot.signControlRecord;
    this.verifyControlSignature = snapshot.verifyControlSignature;
    this.authorizeControl = snapshot.authorizeControl;
    this.outboxCodec = snapshot.outboxCodec;
    this.maxOutboxEntries =
      snapshot.maxOutboxEntries ?? DEFAULT_GROUP_SECURITY_MAX_OUTBOX_ENTRIES;
    this.maxReplayEntries =
      snapshot.maxReplayEntries ?? DEFAULT_GROUP_SECURITY_MAX_REPLAY_ENTRIES;
    this.replayWindowEpochs =
      snapshot.replayWindowEpochs ??
      DEFAULT_GROUP_SECURITY_REPLAY_WINDOW_EPOCHS;
    this.outboxDeliveryTimeoutMs =
      snapshot.outboxDeliveryTimeoutMs ??
      DEFAULT_GROUP_SECURITY_OUTBOX_DELIVERY_TIMEOUT_MS;
    this.now = snapshot.now ?? Date.now;
  }

  /** Claims exclusive ownership of `config.provider` after a successful restore. */
  static async restore(
    config: GroupSecurityCoordinatorConfig,
  ): Promise<GroupSecurityCoordinator> {
    const coordinator = new GroupSecurityCoordinator(config);
    return withProviderLifecycle(coordinator.provider, true, async () => {
      await coordinator.restoreInternal();
      return coordinator;
    });
  }

  /** Claims exclusive ownership of `config.provider` after bootstrap. */
  static async bootstrap(
    config: GroupSecurityCoordinatorConfig,
    groupInput: CreateGroupInput,
    control: GroupSecurityBootstrapControlInput,
  ): Promise<GroupSecurityCoordinator> {
    const coordinator = new GroupSecurityCoordinator(config);
    const groupInputSnapshot = cloneCreateGroupInput(groupInput);
    const controlSnapshot = cloneBootstrapControlInput(control);
    return withProviderLifecycle(coordinator.provider, true, async () => {
      await coordinator.bootstrapInternal(groupInputSnapshot, controlSnapshot);
      return coordinator;
    });
  }

  /** Serializes transient KeyPackage mutation without claiming the provider. */
  static async createPendingKeyPackage(
    config: GroupSecurityCoordinatorConfig,
    input: CreatePendingKeyPackageInput,
  ): Promise<GroupKeyPackage> {
    const coordinator = new GroupSecurityCoordinator(config);
    const inputSnapshot = cloneCreatePendingKeyPackageInput(
      input,
      coordinator.storeKey,
    );
    return withProviderLifecycle(coordinator.provider, false, () =>
      coordinator.createPendingKeyPackageInternal(inputSnapshot),
    );
  }

  /** Claims exclusive ownership of a fresh `config.provider` after joining. */
  static async joinFromInvitation(
    config: GroupSecurityCoordinatorConfig,
    invitation: GroupSecurityJoinInvitation,
  ): Promise<GroupSecurityCoordinator> {
    const coordinator = new GroupSecurityCoordinator(config);
    const invitationSnapshot = cloneJoinInvitation(
      invitation,
      coordinator.maxReplayEntries,
    );
    return withProviderLifecycle(coordinator.provider, true, async () => {
      await coordinator.joinFromInvitationInternal(invitationSnapshot);
      return coordinator;
    });
  }

  get publicState(): GroupSecurityPublicState {
    this.assertUsable();
    return clonePublicState(this.view.publicState);
  }

  pendingOutboxCount(): Promise<number> {
    return this.runExclusive(async () => {
      const snapshot = await this.verifyCurrentStoreSnapshot();
      await this.rejectPersistedFork(snapshot);
      this.assertOutboxBound(snapshot.outbox.length);
      return snapshot.outbox.length;
    });
  }

  createCommit(
    input: CreateGroupCommitInput,
    control: GroupSecurityControlInput,
  ): Promise<GroupSecurityTransitionResult> {
    try {
      this.assertUsable();
      const inputSnapshot = cloneCreateGroupCommitInput(input, this.storeKey);
      const controlSnapshot = cloneGroupSecurityControlInput(control);
      validateControlInput(controlSnapshot);
      return this.runExclusive(() =>
        this.createCommitInternal(inputSnapshot, controlSnapshot),
      );
    } catch (error) {
      return Promise.reject(error);
    }
  }

  applyCommit(
    commit: GroupSecurityCommit,
    controlRecord: MembershipControlRecord,
    welcomes: ReadonlyArray<GroupWelcome> = [],
  ): Promise<GroupSecurityTransitionResult> {
    try {
      this.assertUsable();
      const controlSnapshot = snapshotControlRecord(
        controlRecord,
        'incoming control record',
      );
      serializeMembershipControlRecord(controlSnapshot);
      let commitSnapshot: GroupSecurityCommit | undefined;
      let welcomeSnapshots: GroupWelcome[] | undefined;
      let attachmentError: unknown;
      try {
        commitSnapshot = cloneCommit(commit);
        welcomeSnapshots = validateWelcomes(welcomes, commitSnapshot);
      } catch (error) {
        attachmentError = error;
      }
      return this.runExclusive(() =>
        this.applyCommitInternal(
          commitSnapshot,
          controlSnapshot,
          welcomeSnapshots,
          attachmentError,
        ),
      );
    } catch (error) {
      return Promise.reject(
        new GroupSecurityCoordinatorError(
          'control-mismatch',
          'commit delivery is malformed',
          { cause: error },
        ),
      );
    }
  }

  flushOutbox(
    send: (
      delivery: GroupSecurityDelivery,
      signal: AbortSignal,
    ) => Promise<GroupSecurityDurableAcceptance>,
  ): Promise<GroupSecurityFlushResult> {
    return this.runExclusive(() => this.flushOutboxInternal(send));
  }

  private async createPendingKeyPackageInternal(
    input: CreatePendingKeyPackageInput,
  ): Promise<GroupKeyPackage> {
    const snapshot = await this.loadValidatedStoreSnapshot();
    const baseRevision = this.requireAbsentGroupRevision(snapshot);
    await this.requireAbsentRollbackAnchor();
    const requestCommitment =
      await pendingKeyPackageRequestCommitment(input, this.storeKey);
    const durableRequest = snapshot?.pendingKeyPackageRequests.find(
      (request) => equalBytes(request.operationId, input.operationId),
    );
    if (durableRequest !== undefined) {
      if (
        !equalBytes(
          durableRequest.requestCommitment,
          requestCommitment,
        )
      ) {
        fail(
          'operation-conflict',
          'pending KeyPackage operationId was reused with a different request',
        );
      }
      const pending = snapshot!.pendingKeyPackages.find((state) =>
        equalBytes(
          validateEncryptedKeyPackage(state, undefined, this.storeKey)
            .keyPackage.reference,
          durableRequest.keyPackageReference,
        ),
      );
      if (pending === undefined) {
        fail(
          'malformed-state',
          'pending KeyPackage request has no matching encrypted state',
        );
      }
      const pendingSnapshot = validateEncryptedKeyPackage(
        pending,
        undefined,
        this.storeKey,
      );
      await this.requireAuthenticatedKeyPackageMember(
        pendingSnapshot.keyPackage,
        input.memberId,
        'durably pending KeyPackage',
      );
      await this.requireAuthenticatedKeyPackageRequestCommitment(
        pendingSnapshot.keyPackage,
        requestCommitment,
        'durably pending KeyPackage',
      );
      const requireCurrentPair = (
        current: GroupStateStoreSnapshot | undefined,
      ): EncryptedKeyPackageState => {
        if (
          current === undefined ||
          current.revision !== baseRevision ||
          current.encryptedState !== undefined
        ) {
          fail(
            'store-conflict',
            'durably pending KeyPackage changed during retry authentication',
          );
        }
        const currentRequest = current.pendingKeyPackageRequests.find(
          (request) => equalBytes(request.operationId, input.operationId),
        );
        const currentPending = current.pendingKeyPackages.find((state) =>
          equalBytes(
            state.keyPackage.reference,
            durableRequest.keyPackageReference,
          ),
        );
        if (
          currentRequest === undefined ||
          currentPending === undefined ||
          !equalBytes(
            currentRequest.requestCommitment,
            requestCommitment,
          ) ||
          !equalBytes(
            currentRequest.keyPackageReference,
            durableRequest.keyPackageReference,
          ) ||
          !equalBytes(
            currentPending.serialize(),
            pendingSnapshot.serialize(),
          )
        ) {
          fail(
            'store-conflict',
            'durably pending KeyPackage request pair changed during retry authentication',
          );
        }
        return currentPending;
      };
      await this.requireAbsentRollbackAnchor();
      requireCurrentPair(await this.loadValidatedStoreSnapshot());
      await this.requireAbsentRollbackAnchor();
      const currentPending = requireCurrentPair(
        await this.loadValidatedStoreSnapshot(),
      );
      return cloneKeyPackage(currentPending.keyPackage);
    }
    if (await this.providerHasActiveGroup()) {
      fail(
        'already-initialized',
        'pending KeyPackage creation requires a provider with no active group',
      );
    }

    let keyPackage: GroupKeyPackage | undefined;
    let keyPackageCreationAttempted = false;
    try {
      keyPackageCreationAttempted = true;
      keyPackage = cloneKeyPackage(
        await this.provider.createKeyPackage({
          ...cloneCreateKeyPackageInput(input, this.storeKey),
          requestCommitment: new Uint8Array(requestCommitment),
        }),
      );
      validateKeyPackage(keyPackage, this.storeKey);
      await this.requireAuthenticatedKeyPackageMember(
        keyPackage,
        input.memberId,
        'created KeyPackage',
      );
      await this.requireAuthenticatedKeyPackageRequestCommitment(
        keyPackage,
        requestCommitment,
        'created KeyPackage',
      );
      const encrypted = validateEncryptedKeyPackage(
        await this.provider.exportEncryptedKeyPackage(
          new Uint8Array(keyPackage.reference),
          this.protector,
        ),
        keyPackage,
        this.storeKey,
      );
      const expectedRequest = {
        operationId: new Uint8Array(input.operationId),
        requestCommitment: new Uint8Array(requestCommitment),
        keyPackageReference: new Uint8Array(keyPackage.reference),
      };
      const expectedPendingCommitment =
        await groupSecurityStoreSnapshotCommitment({
          revision: baseRevision + 1,
          encryptedState: undefined,
          pendingKeyPackages: [
            ...(snapshot?.pendingKeyPackages ?? []),
            encrypted,
          ],
          pendingKeyPackageRequests: [
            ...(snapshot?.pendingKeyPackageRequests ?? []),
            expectedRequest,
          ],
          consumedKeyPackageRefs:
            snapshot?.consumedKeyPackageRefs ?? [],
          outbox: snapshot?.outbox ?? [],
          replay: snapshot?.replay ?? [],
          forkEvidence: snapshot?.forkEvidence,
        }, this.storeKey);
      let transactionInvoked = false;
      let intendedStoreCommitment: Uint8Array | undefined;
      await this.store.transaction(this.storeKey, async (transaction) => {
        if (transactionInvoked) {
          fail(
            'store-conflict',
            'pending KeyPackage transaction was invoked more than once',
          );
        }
        transactionInvoked = true;
        if (
          transaction.baseRevision !== baseRevision ||
          transaction.encryptedState !== undefined
        ) {
          fail(
            'store-conflict',
            'group state changed while persisting a pending KeyPackage',
          );
        }
        if (transaction.forkEvidence !== undefined) {
          fail(
            'malformed-state',
            'fork evidence exists without encrypted group state',
          );
        }
        const racedRequest = transaction.getPendingKeyPackageRequest(
          input.operationId,
        );
        if (racedRequest !== undefined) {
          if (
            !equalBytes(
              racedRequest.requestCommitment,
              requestCommitment,
            )
          ) {
            fail(
              'operation-conflict',
              'pending KeyPackage operationId raced with a different request',
            );
          }
          fail(
            'store-conflict',
            'pending KeyPackage request appeared during persistence; retry it',
          );
        }
        if (transaction.putPendingKeyPackage(encrypted) !== true) {
          fail(
            'store-conflict',
            'pending KeyPackage appeared during persistence',
          );
        }
        if (
          transaction.bindPendingKeyPackageRequest({
            operationId: input.operationId,
            requestCommitment,
            keyPackageReference: keyPackage!.reference,
          }) !== true
        ) {
          fail(
            'store-conflict',
            'pending KeyPackage request appeared during persistence',
          );
        }
        const transactionCommitment =
          await groupStateTransactionCommitment(transaction, this.storeKey);
        if (!equalBytes(transactionCommitment, expectedPendingCommitment)) {
          fail(
            'store-conflict',
            'pending KeyPackage transaction produced an unexpected durable delta',
          );
        }
        intendedStoreCommitment = new Uint8Array(
          expectedPendingCommitment,
        );
      });
      if (intendedStoreCommitment === undefined) {
        fail(
          'store-conflict',
          'durable store did not invoke the pending KeyPackage transaction',
        );
      }
      const committedSnapshot = await this.loadValidatedStoreSnapshot();
      if (
        committedSnapshot === undefined ||
        committedSnapshot.revision !== baseRevision + 1 ||
        committedSnapshot.encryptedState !== undefined
      ) {
        fail(
          'store-conflict',
          'pending KeyPackage post-commit snapshot has an unexpected revision or group state',
        );
      }
      const committedCommitment =
        await groupSecurityStoreSnapshotCommitment(
          committedSnapshot,
          this.storeKey,
        );
      if (!equalBytes(committedCommitment, intendedStoreCommitment)) {
        fail(
          'store-conflict',
          'pending KeyPackage post-commit snapshot differs from the intended transaction',
        );
      }
      const committedRequest =
        committedSnapshot.pendingKeyPackageRequests.find((request) =>
          equalBytes(request.operationId, expectedRequest.operationId),
        );
      const committedPending = committedSnapshot.pendingKeyPackages.find(
        (state) =>
          equalBytes(
            state.keyPackage.reference,
            expectedRequest.keyPackageReference,
          ),
      );
      if (
        committedRequest === undefined ||
        committedPending === undefined ||
        !equalBytes(
          committedRequest.requestCommitment,
          expectedRequest.requestCommitment,
        ) ||
        !equalBytes(
          committedRequest.keyPackageReference,
          expectedRequest.keyPackageReference,
        ) ||
        !equalBytes(committedPending.serialize(), encrypted.serialize())
      ) {
        fail(
          'store-conflict',
          'pending KeyPackage post-commit state does not contain the intended request pair',
        );
      }
      return cloneKeyPackage(committedPending.keyPackage);
    } catch (error) {
      if (keyPackage === undefined) {
        if (keyPackageCreationAttempted) {
          throw new GroupSecurityCoordinatorError(
            'rollback-unavailable',
            'pending KeyPackage creation failed before a trustworthy reference was available; discard this provider instance',
            { cause: error },
          );
        }
        throw error;
      }
      await this.rollbackPendingKeyPackage(keyPackage.reference, error);
      throw error;
    }
  }

  private async joinFromInvitationInternal(
    invitation: GroupSecurityJoinInvitation,
  ): Promise<void> {
    const snapshot = await this.loadValidatedStoreSnapshot();
    if (
      snapshot?.consumedKeyPackageRefs.some((reference) =>
        equalBytes(reference, invitation.keyPackageRef),
      )
    ) {
      fail('stale-replay', 'recipient KeyPackage has already been consumed');
    }
    const baseRevision = this.requireAbsentGroupRevision(snapshot);
    await this.requireAbsentRollbackAnchor();
    const pendingSnapshot = snapshot?.pendingKeyPackages
      .map((state) =>
        validateEncryptedKeyPackage(state, undefined, this.storeKey),
      )
      .find((state) =>
        equalBytes(state.keyPackage.reference, invitation.keyPackageRef),
      );
    if (pendingSnapshot === undefined) {
      fail(
        'control-mismatch',
        'invitation does not address a durably pending KeyPackage',
      );
    }
    const pendingRequest = snapshot!.pendingKeyPackageRequests.find(
      (request) =>
        equalBytes(
          request.keyPackageReference,
          invitation.keyPackageRef,
        ),
    );
    if (pendingRequest === undefined) {
      fail(
        'malformed-state',
        'invitation pending KeyPackage has no request binding',
      );
    }
    await this.requireAuthenticatedKeyPackageRequestCommitment(
      pendingSnapshot.keyPackage,
      pendingRequest.requestCommitment,
      'invitation pending KeyPackage',
    );
    const verified = await this.verifyJoinInvitation(
      invitation,
      pendingSnapshot.keyPackage,
    );
    if (await this.providerHasActiveGroup()) {
      fail(
        'already-initialized',
        'recipient join requires a fresh provider with no active group',
      );
    }

    let providerTouched = false;
    let joinAttempted = false;
    let storeCommitted = false;
    let firstAnchorCandidate: GroupSecurityRollbackAnchorValue | undefined;
    try {
      providerTouched = true;
      const importedPackage = cloneKeyPackage(
        await this.provider.importEncryptedKeyPackage(
          EncryptedKeyPackageState.deserialize(pendingSnapshot.serialize()),
          this.protector,
        ),
      );
      if (!sameKeyPackage(importedPackage, pendingSnapshot.keyPackage)) {
        fail(
          'control-mismatch',
          'provider restored a different pending KeyPackage',
        );
      }

      const joinInput: JoinGroupInput = {
        welcome: cloneWelcome(invitation.welcome),
        keyPackageRef: new Uint8Array(invitation.keyPackageRef),
        authenticatedData:
          invitation.authenticatedData === undefined
            ? undefined
            : new Uint8Array(invitation.authenticatedData),
      };
      joinAttempted = true;
      const joinedState = clonePublicState(
        await this.provider.joinGroup(joinInput),
      );
      this.validateJoinedState(joinedState, verified);
      assertSamePublicState(
        await this.providerPublicStateSnapshot(),
        joinedState,
      );
      const encryptedState = await this.exportAndValidateState(joinedState);
      const unprunedJoinReplay: GroupStateReplayEntry[] =
        verified.records.map((record, index) => ({
          recordId: new Uint8Array(verified.recordIds[index]),
          operationId: new Uint8Array(record.operationId),
          epoch: record.epoch,
          controlRecord: serializeMembershipControlRecord(record),
        }));
      const joinPruneSet = new Set(
        replayIdsToPrune(
          unprunedJoinReplay,
          snapshot?.outbox ?? [],
          joinedState.epoch,
          this.replayWindowEpochs,
        ).map(toHex),
      );
      const expectedJoinSnapshot: GroupStateStoreSnapshot = {
        revision: baseRevision + 1,
        encryptedState,
        pendingKeyPackages: (snapshot?.pendingKeyPackages ?? []).filter(
          (state) =>
            !equalBytes(
              state.keyPackage.reference,
              invitation.keyPackageRef,
            ),
        ),
        pendingKeyPackageRequests: (
          snapshot?.pendingKeyPackageRequests ?? []
        ).filter(
          (request) =>
            !equalBytes(
              request.keyPackageReference,
              invitation.keyPackageRef,
            ),
        ),
        consumedKeyPackageRefs: [
          ...(snapshot?.consumedKeyPackageRefs ?? []),
          new Uint8Array(invitation.keyPackageRef),
        ],
        outbox: snapshot?.outbox ?? [],
        replay: unprunedJoinReplay.filter(
          (entry) => !joinPruneSet.has(toHex(entry.recordId)),
        ),
        forkEvidence: snapshot?.forkEvidence,
      };
      const expectedJoinCommitment =
        await groupSecurityStoreSnapshotCommitment(
          expectedJoinSnapshot,
          this.storeKey,
        );
      firstAnchorCandidate = rollbackAnchorValue(
        baseRevision + 1,
        joinedState,
        verified.finalRecordId,
        expectedJoinCommitment,
      );

      let transactionInvoked = false;
      let intendedStoreCommitment: Uint8Array | undefined;
      let ambiguousStoreFailure: AmbiguousStoreFailure | undefined;
      try {
        await this.store.transaction(
          this.storeKey,
          async (transaction) => {
            if (transactionInvoked) {
              fail(
                'store-conflict',
                'recipient join transaction was invoked more than once',
              );
            }
            transactionInvoked = true;
            if (
              transaction.baseRevision !== baseRevision ||
              transaction.encryptedState !== undefined
            ) {
              fail('store-conflict', 'group state changed during recipient join');
            }
            if (transaction.forkEvidence !== undefined) {
              fail(
                'malformed-state',
                'fork evidence exists without encrypted group state',
              );
            }
            const durablePending = transaction.getPendingKeyPackage(
              invitation.keyPackageRef,
            );
            if (
              durablePending === undefined ||
              !equalBytes(durablePending.serialize(), pendingSnapshot.serialize())
            ) {
              fail(
                'store-conflict',
                'pending KeyPackage changed during recipient join',
              );
            }
            const consumed = transaction.consumePendingKeyPackage(
              invitation.keyPackageRef,
            );
            if (!equalBytes(consumed.serialize(), pendingSnapshot.serialize())) {
              fail(
                'malformed-state',
                'consumed KeyPackage differs from the verified pending package',
              );
            }
            transaction.setEncryptedState(encryptedState);
            for (let index = 0; index < verified.records.length; index++) {
              const record = verified.records[index];
              if (
                transaction.markReplay({
                  recordId: verified.recordIds[index],
                  operationId: record.operationId,
                  epoch: record.epoch,
                  controlRecord: serializeMembershipControlRecord(record),
                }) !== true
              ) {
                fail(
                  'store-conflict',
                  'recipient control prefix already exists in replay metadata',
                );
              }
            }
            pruneReplayTransaction(
              transaction,
              joinedState.epoch,
              this.replayWindowEpochs,
            );
            this.assertReplayBound(transaction.replay.length);
            this.assertOutboxBound(transaction.outbox.length);
            await this.buildVerifiedView(
              joinedState,
              transaction.replay,
              transaction.outbox,
            );
            const transactionCommitment =
              await groupStateTransactionCommitment(
                transaction,
                this.storeKey,
              );
            if (!equalBytes(transactionCommitment, expectedJoinCommitment)) {
              fail(
                'store-conflict',
                'recipient join transaction produced an unexpected durable delta',
              );
            }
            intendedStoreCommitment = new Uint8Array(expectedJoinCommitment);
          },
        );
        storeCommitted = true;
      } catch (error) {
        ambiguousStoreFailure = { cause: error };
      }
      const revision = baseRevision + 1;
      const committed = await this.loadCommittedCoordinatorView(
        revision,
        joinedState,
        verified.finalRecordId,
        intendedStoreCommitment,
        'recipient join',
        ambiguousStoreFailure,
      );
      storeCommitted = true;
      const anchorValue = rollbackAnchorValue(
        revision,
        committed.view.publicState,
        committed.view.headRecordId,
        committed.storeCommitment,
      );
      await this.advanceRollbackAnchor(undefined, anchorValue);
      this.view = committed.view;
      this.storeRevision = revision;
      this.rollbackAnchorValue = cloneGroupSecurityRollbackAnchor(anchorValue);
    } catch (error) {
      if (this.poisonedReason !== undefined) throw error;
      if (storeCommitted) {
        const reason = normalizeFailure(
          error,
          'recipient join publication failed with a non-Error value',
        );
        this.poisonedReason = reason;
        throw new GroupSecurityCoordinatorError(
          'rollback-failed',
          'recipient join committed but publication failed; coordinator is poisoned',
          { cause: reason },
        );
      }
      let reconciliationError: unknown;
      try {
        await this.reconcileControlFork(
          verified.records,
          verified.recordIds,
          firstAnchorCandidate,
        );
      } catch (forkError) {
        reconciliationError = forkError;
      }
      if (providerTouched) {
        await this.rollbackJoinProvider(
          invitation.keyPackageRef,
          joinAttempted,
          error,
        );
      }
      if (reconciliationError !== undefined) throw reconciliationError;
      throw error;
    }
  }

  private async restoreInternal(): Promise<void> {
    const loadedAnchor = await this.loadRollbackAnchor();
    this.rejectRollbackForkPoison(loadedAnchor);
    const snapshot = await this.requireSnapshot();
    if (snapshot.encryptedState === undefined) {
      fail('malformed-state', 'stored group has no encrypted provider state');
    }
    const encryptedState = snapshotEncryptedGroupState(
      snapshot.encryptedState,
    );
    assertEnvelopeMatchesKey(encryptedState, this.storeKey);
    let anchorValue = await this.loadAndVerifyRollbackSnapshot(
      snapshot,
      encryptedState.state,
    );
    this.assertOutboxBound(snapshot.outbox.length);
    this.assertReplayBound(snapshot.replay.length);
    for (const entry of snapshot.outbox) validateOutboxEntry(entry);
    for (const entry of snapshot.replay) validateReplayEntry(entry);

    const pruneIds = replayIdsToPrune(
      snapshot.replay,
      snapshot.outbox,
      encryptedState.state.epoch,
      this.replayWindowEpochs,
    );
    const pruneSet = new Set(pruneIds.map(toHex));
    const projectedReplay = snapshot.replay.filter(
      (entry) => !pruneSet.has(toHex(entry.recordId)),
    );
    let effectiveView = await this.buildVerifiedView(
      encryptedState.state,
      projectedReplay,
      snapshot.outbox,
      true,
    );
    if (!equalBytes(effectiveView.headRecordId, anchorValue.controlHead)) {
      fail(
        'rollback-detected',
        'durable control head does not match its rollback anchor',
      );
    }
    if (snapshot.forkEvidence !== undefined) {
      await this.validatePersistedForkEvidence(
        snapshot.forkEvidence,
        effectiveView,
      );
      const error = new GroupSecurityCoordinatorError(
        'fork-detected',
        'durable group state contains a same-parent control fork',
      );
      this.forkReason = error;
      throw error;
    }

    let revision = snapshot.revision;
    if (pruneIds.length > 0) {
      const expectedPrunedCommitment =
        await groupSecurityStoreSnapshotCommitment({
          revision: snapshot.revision + 1,
          encryptedState: snapshot.encryptedState,
          pendingKeyPackages: snapshot.pendingKeyPackages,
          pendingKeyPackageRequests: snapshot.pendingKeyPackageRequests,
          consumedKeyPackageRefs: snapshot.consumedKeyPackageRefs,
          outbox: snapshot.outbox,
          replay: projectedReplay,
          forkEvidence: snapshot.forkEvidence,
        }, this.storeKey);
      let transactionInvoked = false;
      let intendedStoreCommitment: Uint8Array | undefined;
      let ambiguousStoreFailure: AmbiguousStoreFailure | undefined;
      try {
        await this.store.transaction(
          this.storeKey,
          async (transaction) => {
            if (transactionInvoked) {
              fail(
                'store-conflict',
                'restore pruning transaction was invoked more than once',
              );
            }
            transactionInvoked = true;
            await this.verifyTransactionSnapshotAgainstRollbackAnchor(
              transaction,
              anchorValue,
            );
            if (transaction.baseRevision !== snapshot.revision) {
              fail('store-conflict', 'group state changed during restore');
            }
            for (const recordId of pruneIds) {
              if (transaction.removeReplay(recordId) !== true) {
                fail(
                  'store-conflict',
                  'replay record disappeared during restore pruning',
                );
              }
            }
            this.assertReplayBound(transaction.replay.length);
            await this.buildVerifiedView(
              encryptedState.state,
              transaction.replay,
              transaction.outbox,
            );
            const transactionCommitment =
              await groupStateTransactionCommitment(
                transaction,
                this.storeKey,
              );
            if (!equalBytes(transactionCommitment, expectedPrunedCommitment)) {
              fail(
                'store-conflict',
                'restore pruning transaction produced an unexpected durable delta',
              );
            }
            intendedStoreCommitment = new Uint8Array(
              expectedPrunedCommitment,
            );
          },
        );
      } catch (error) {
        ambiguousStoreFailure = { cause: error };
      }
      revision += 1;
      const committed = await this.loadCommittedCoordinatorView(
        revision,
        encryptedState.state,
        effectiveView.headRecordId,
        intendedStoreCommitment,
        'restore pruning',
        ambiguousStoreFailure,
      );
      effectiveView = committed.view;
      const nextAnchor = rollbackAnchorValue(
        revision,
        effectiveView.publicState,
        effectiveView.headRecordId,
        committed.storeCommitment,
      );
      await this.advanceRollbackAnchor(anchorValue, nextAnchor);
      anchorValue = nextAnchor;
    }
    const restoreEnvelope = snapshotEncryptedGroupState(encryptedState);
    const restoreExpected = clonePublicState(restoreEnvelope.state);
    const checkpoint = await this.providerCheckpoint();
    let providerImportVerified = false;
    try {
      const imported = clonePublicState(
        await this.provider.importEncryptedState(
          restoreEnvelope,
          this.protector,
        ),
      );
      assertPublicStateMatchesKey(imported, this.storeKey);
      assertSamePublicState(imported, restoreExpected);
      assertSamePublicState(
        await this.providerPublicStateSnapshot(),
        restoreExpected,
      );
      providerImportVerified = true;
      await this.verifyRestoreSnapshotStillCurrent(
        anchorValue,
        effectiveView,
      );
    } catch (error) {
      await this.rollbackInitialization(checkpoint, error, 'restore');
      if (providerImportVerified) {
        const reason = normalizeFailure(
          error,
          'restore final verification failed with a non-Error value',
        );
        this.poisonedReason = reason;
        throw new GroupSecurityCoordinatorError(
          'rollback-failed',
          'restore state changed after provider import; provider lifecycle is permanently retired',
          { cause: reason },
        );
      }
      throw error;
    }
    this.view = effectiveView;
    this.storeRevision = revision;
    this.rollbackAnchorValue = cloneGroupSecurityRollbackAnchor(anchorValue);
  }

  private async bootstrapInternal(
    groupInput: CreateGroupInput,
    control: GroupSecurityBootstrapControlInput,
  ): Promise<void> {
    const existing = await this.loadValidatedStoreSnapshot();
    const baseRevision = this.requireAbsentGroupRevision(existing);
    if ((await this.loadRollbackAnchor()) !== undefined) {
      fail(
        'rollback-detected',
        'rollback anchor exists while durable group state is absent',
      );
    }
    validateFixedId(control.operationId, 'operationId');
    validateIdentity(control.subjectId, 'subjectId');
    if (!equalBytes(groupInput.creatorMemberId, control.subjectId)) {
      fail(
        'control-mismatch',
        'bootstrap control subject does not match the intended creator member',
      );
    }
    if (await this.providerHasActiveGroup()) {
      fail(
        'already-initialized',
        'group bootstrap requires a fresh provider with no active group',
      );
    }
    try {
      await this.bootstrapProviderAndPersist(
        groupInput,
        control,
        baseRevision,
        existing,
      );
    } catch (error) {
      if (this.poisonedReason !== undefined) throw error;
      await this.rollbackInitialization(
        undefined,
        error,
        'bootstrap',
      );
      throw error;
    }
  }

  private async bootstrapProviderAndPersist(
    groupInput: CreateGroupInput,
    control: GroupSecurityBootstrapControlInput,
    baseRevision: number,
    existing: GroupStateStoreSnapshot | undefined,
  ): Promise<void> {
    const created = exactOwnDataValues(
      await this.provider.createGroup(groupInput),
      ['state', 'authenticatedCreatorMemberId'],
      'provider create-group result',
      [],
      true,
    );
    const state = clonePublicState(
      created.state as GroupSecurityPublicState,
    );
    const authenticatedCreatorMemberId = copyControlRecordBytes(
      created.authenticatedCreatorMemberId,
      'provider authenticated creator memberId',
      1,
      MAX_IDENTITY_BYTES,
    );
    if (
      !equalBytes(
        authenticatedCreatorMemberId,
        groupInput.creatorMemberId,
      ) ||
      !equalBytes(authenticatedCreatorMemberId, control.subjectId)
    ) {
      fail(
        'control-mismatch',
        'provider creator credential is authenticated for a different member',
      );
    }
    assertPublicStateMatchesKey(state, this.storeKey);
    assertSamePublicState(await this.providerPublicStateSnapshot(), state);
    if (state.epoch !== 0n) {
      fail('epoch-mismatch', 'new groups must begin at epoch zero');
    }
    const unsigned: UnsignedMembershipControlRecord = {
      version: MEMBERSHIP_CONTROL_VERSION,
      protocol: { ...state.protocol },
      groupId: new Uint8Array(state.groupId),
      epoch: state.epoch,
      operationId: new Uint8Array(control.operationId),
      action: 'create',
      actorId: new Uint8Array(this.actorId),
      subjectId: new Uint8Array(control.subjectId),
      controlPayload: canonicalGroupSecurityState(state),
    };
    const record = await signMembershipControlRecord(
      unsigned,
      this.signControlRecord,
    );
    const recordId = await this.verifyGenesisControl(record, state);
    const encryptedState = await this.exportAndValidateState(state);
    const outbox = await this.makeOutboxEntry({
      controlRecord: record,
      welcomes: [],
    });
    const serializedRecord = serializeMembershipControlRecord(record);
    const expectedBootstrapCommitment =
      await groupSecurityStoreSnapshotCommitment({
        revision: baseRevision + 1,
        encryptedState,
        pendingKeyPackages: existing?.pendingKeyPackages ?? [],
        pendingKeyPackageRequests:
          existing?.pendingKeyPackageRequests ?? [],
        consumedKeyPackageRefs: existing?.consumedKeyPackageRefs ?? [],
        outbox: [...(existing?.outbox ?? []), outbox],
        replay: [
          ...(existing?.replay ?? []),
          {
            recordId: new Uint8Array(recordId),
            operationId: new Uint8Array(record.operationId),
            epoch: record.epoch,
            controlRecord: new Uint8Array(serializedRecord),
          },
        ],
        forkEvidence: existing?.forkEvidence,
      }, this.storeKey);
    const firstAnchorCandidate = rollbackAnchorValue(
      baseRevision + 1,
      state,
      recordId,
      expectedBootstrapCommitment,
    );

    try {
      let transactionInvoked = false;
      let intendedStoreCommitment: Uint8Array | undefined;
      let ambiguousStoreFailure: AmbiguousStoreFailure | undefined;
      try {
        await this.store.transaction(
          this.storeKey,
          async (transaction) => {
            if (transactionInvoked) {
              fail(
                'store-conflict',
                'bootstrap transaction was invoked more than once',
              );
            }
            transactionInvoked = true;
            if (
              transaction.baseRevision !== baseRevision ||
              transaction.encryptedState !== undefined
            ) {
              fail('store-conflict', 'group state appeared during bootstrap');
            }
            transaction.setEncryptedState(encryptedState);
            if (
              transaction.markReplay({
                recordId,
                operationId: record.operationId,
                epoch: record.epoch,
                controlRecord: serializedRecord,
              }) !== true
            ) {
              fail('store-conflict', 'genesis replay record already exists');
            }
            this.enqueueBounded(transaction, outbox);
            this.assertReplayBound(transaction.replay.length);
            await this.buildVerifiedView(
              state,
              transaction.replay,
              transaction.outbox,
            );
            const transactionCommitment =
              await groupStateTransactionCommitment(
                transaction,
                this.storeKey,
              );
            if (!equalBytes(transactionCommitment, expectedBootstrapCommitment)) {
              fail(
                'store-conflict',
                'bootstrap transaction produced an unexpected durable delta',
              );
            }
            intendedStoreCommitment = new Uint8Array(
              expectedBootstrapCommitment,
            );
          },
        );
      } catch (error) {
        ambiguousStoreFailure = { cause: error };
      }
      const revision = baseRevision + 1;
      const committed = await this.loadCommittedCoordinatorView(
        revision,
        state,
        recordId,
        intendedStoreCommitment,
        'bootstrap',
        ambiguousStoreFailure,
      );
      const anchorValue = rollbackAnchorValue(
        revision,
        committed.view.publicState,
        committed.view.headRecordId,
        committed.storeCommitment,
      );
      await this.advanceRollbackAnchor(undefined, anchorValue);
      this.view = committed.view;
      this.storeRevision = revision;
      this.rollbackAnchorValue =
        cloneGroupSecurityRollbackAnchor(anchorValue);
    } catch (error) {
      await this.reconcileControlFork(
        [record],
        [recordId],
        firstAnchorCandidate,
      );
      throw error;
    }
  }

  private async createCommitInternal(
    inputValue: CreateGroupCommitInput,
    controlValue: GroupSecurityControlInput,
  ): Promise<GroupSecurityTransitionResult> {
    await this.verifyCurrentStoreSnapshot();
    validateControlInput(controlValue);
    const control = cloneGroupSecurityControlInput(controlValue);
    const existingRecordHex = this.view.operationToRecord.get(
      toHex(control.operationId),
    );
    if (existingRecordHex !== undefined) {
      const existing = this.view.recordsById.get(existingRecordHex);
      if (existing === undefined) {
        fail('malformed-state', 'operation replay record is missing');
      }
      const existingDigest = requestDigestFromControlRecord(existing);
      if (
        existing.action !== control.action ||
        !equalBytes(existing.subjectId, control.subjectId) ||
        !equalBytes(existing.actorId, this.actorId) ||
        !equalBytes(existingDigest, control.requestDigest)
      ) {
        fail(
          'operation-conflict',
          'operationId retry does not match its original action, subject, or request digest',
        );
      }
      return {
        status: 'duplicate',
        recordId: fromHex(existingRecordHex),
      };
    }
    const requestedMembership = validateRequestedMembershipIntent(
      inputValue,
      control,
      this.storeKey,
    );
    const input = cloneCreateGroupCommitInput(inputValue, this.storeKey);
    const requestedChange = input.changes[0];
    if (requestedChange.kind === 'add' || requestedChange.kind === 'update') {
      await this.requireAuthenticatedKeyPackageMember(
        requestedChange.keyPackage,
        requestedChange.memberId,
        `requested ${requestedChange.kind} KeyPackage`,
      );
    }

    const priorState = clonePublicState(this.view.publicState);
    const checkpoint = await this.exportProviderStateSnapshot();
    assertSamePublicState(checkpoint.state, priorState);
    return this.withProviderRollback(checkpoint, priorState, async () => {
      const result = cloneGroupSecurityCommitResult(
        await this.provider.createCommit(input),
      );
      await this.validateCommitResult(
        result,
        priorState,
        requestedMembership,
      );
      const unsigned: UnsignedMembershipControlRecord = {
        version: MEMBERSHIP_CONTROL_VERSION,
        protocol: { ...result.commit.protocol },
        groupId: new Uint8Array(result.commit.groupId),
        epoch: result.commit.epoch,
        parentRecordId: new Uint8Array(this.view.headRecordId),
        operationId: new Uint8Array(control.operationId),
        action: control.action,
        actorId: new Uint8Array(this.actorId),
        subjectId: new Uint8Array(control.subjectId),
        controlPayload: await canonicalGroupSecurityControlPayload(
          result.commit,
          control.requestDigest,
          result.state,
          result.appliedMembership,
          result.welcomes,
        ),
      };
      const record = await signMembershipControlRecord(
        unsigned,
        this.signControlRecord,
      );
      const validated = await this.verifyControl(
        record,
        result.commit,
        result.welcomes,
      );
      if (validated.status !== 'new') {
        fail('operation-conflict', 'new local commit matched an existing record');
      }
      const encryptedState = await this.exportAndValidateState(result.state);
      const outbox = await this.makeOutboxEntry({
        controlRecord: record,
        commit: result.commit,
        welcomes: result.welcomes,
      });
      try {
        await this.persistTransition(
          encryptedState,
          outbox,
          record,
          validated.recordId,
          result.state,
        );
      } catch (error) {
        await this.reconcileControlFork(
          [record],
          [validated.recordId],
        );
        throw error;
      }
      return {
        status: 'committed',
        recordId: new Uint8Array(validated.recordId),
        controlRecord: cloneControlRecord(record),
        state: clonePublicState(result.state),
      };
    });
  }

  private async applyCommitInternal(
    commitValue: GroupSecurityCommit | undefined,
    controlRecordValue: MembershipControlRecord,
    welcomeValues: ReadonlyArray<GroupWelcome> | undefined,
    attachmentError?: unknown,
  ): Promise<GroupSecurityTransitionResult> {
    await this.verifyCurrentStoreSnapshot();
    const controlRecord = cloneControlRecord(controlRecordValue);
    const validated = await this.verifyControl(
      controlRecord,
      commitValue,
      welcomeValues,
      attachmentError,
    );
    if (commitValue === undefined || welcomeValues === undefined) {
      fail('control-mismatch', 'commit delivery is malformed', attachmentError);
    }
    const commit = cloneCommit(commitValue);
    const welcomes = welcomeValues.map(cloneWelcome);
    if (validated.status === 'duplicate') {
      return {
        status: 'duplicate',
        recordId: new Uint8Array(validated.recordId),
      };
    }
    const priorState = clonePublicState(this.view.publicState);
    const checkpoint = await this.exportProviderStateSnapshot();
    assertSamePublicState(checkpoint.state, priorState);
    return this.withProviderRollback(checkpoint, priorState, async () => {
      const applied = cloneGroupSecurityApplyResult(
        await this.provider.applyCommit(cloneCommit(commit)),
      );
      if (applied.status !== 'applied') {
        fail('control-mismatch', 'provider rejected a new authenticated record');
      }
      await this.validateApplyResult(
        applied,
        commit,
        controlRecord,
        validated.stateCommitment,
        welcomes,
      );
      const encryptedState = await this.exportAndValidateState(applied.state);
      const outbox = await this.makeOutboxEntry({
        controlRecord,
        commit,
        welcomes,
      });
      try {
        await this.persistTransition(
          encryptedState,
          outbox,
          controlRecord,
          validated.recordId,
          applied.state,
        );
      } catch (error) {
        await this.reconcileControlFork(
          [controlRecord],
          [validated.recordId],
        );
        throw error;
      }
      return {
        status: 'committed',
        recordId: new Uint8Array(validated.recordId),
        controlRecord: cloneControlRecord(controlRecord),
        state: clonePublicState(applied.state),
      };
    });
  }

  private async persistTransition(
    encryptedState: EncryptedGroupState,
    outbox: GroupStateOutboxEntry,
    record: MembershipControlRecord,
    recordId: Uint8Array,
    publicState: GroupSecurityPublicState,
  ): Promise<void> {
    const serializedRecord = serializeMembershipControlRecord(record);
    const baseSnapshot = await this.verifyCurrentStoreSnapshot();
    await this.rejectPersistedFork(baseSnapshot);
    if (baseSnapshot.encryptedState === undefined) {
      fail('malformed-state', 'encrypted state disappeared before transition');
    }
    const expectedOutbox = [...baseSnapshot.outbox, outbox];
    const addedReplay: GroupStateReplayEntry = {
      recordId: new Uint8Array(recordId),
      operationId: new Uint8Array(record.operationId),
      epoch: record.epoch,
      controlRecord: new Uint8Array(serializedRecord),
    };
    const unprunedReplay = [...baseSnapshot.replay, addedReplay];
    const expectedPruneSet = new Set(
      replayIdsToPrune(
        unprunedReplay,
        expectedOutbox,
        publicState.epoch,
        this.replayWindowEpochs,
      ).map(toHex),
    );
    const expectedTransitionCommitment =
      await groupSecurityStoreSnapshotCommitment({
        revision: this.storeRevision + 1,
        encryptedState,
        pendingKeyPackages: baseSnapshot.pendingKeyPackages,
        pendingKeyPackageRequests: baseSnapshot.pendingKeyPackageRequests,
        consumedKeyPackageRefs: baseSnapshot.consumedKeyPackageRefs,
        outbox: expectedOutbox,
        replay: unprunedReplay.filter(
          (entry) => !expectedPruneSet.has(toHex(entry.recordId)),
        ),
        forkEvidence: baseSnapshot.forkEvidence,
      }, this.storeKey);
    let transactionInvoked = false;
    let intendedStoreCommitment: Uint8Array | undefined;
    let ambiguousStoreFailure: AmbiguousStoreFailure | undefined;
    try {
      await this.store.transaction(
        this.storeKey,
        async (transaction) => {
          if (transactionInvoked) {
            fail(
              'store-conflict',
              'group transition transaction was invoked more than once',
            );
          }
          transactionInvoked = true;
          await this.assertTransactionBase(transaction, this.view.publicState);
          transaction.setEncryptedState(encryptedState);
          if (
            transaction.markReplay({
              recordId,
              operationId: record.operationId,
              epoch: record.epoch,
              controlRecord: serializedRecord,
            }) !== true
          ) {
            fail('store-conflict', 'replay record already exists');
          }
          this.enqueueBounded(transaction, outbox);
          pruneReplayTransaction(
            transaction,
            publicState.epoch,
            this.replayWindowEpochs,
          );
          this.assertReplayBound(transaction.replay.length);
          await this.buildVerifiedView(
            publicState,
            transaction.replay,
            transaction.outbox,
          );
          const transactionCommitment =
            await groupStateTransactionCommitment(
              transaction,
              this.storeKey,
            );
          if (!equalBytes(transactionCommitment, expectedTransitionCommitment)) {
            fail(
              'store-conflict',
              'group transition transaction produced an unexpected durable delta',
            );
          }
          intendedStoreCommitment = new Uint8Array(
            expectedTransitionCommitment,
          );
        },
      );
    } catch (error) {
      ambiguousStoreFailure = { cause: error };
    }
    const revision = this.storeRevision + 1;
    const committed = await this.loadCommittedCoordinatorView(
      revision,
      publicState,
      recordId,
      intendedStoreCommitment,
      'group transition',
      ambiguousStoreFailure,
    );
    const anchorValue = rollbackAnchorValue(
      revision,
      committed.view.publicState,
      committed.view.headRecordId,
      committed.storeCommitment,
    );
    await this.advanceRollbackAnchor(
      this.requireCurrentRollbackAnchor(),
      anchorValue,
    );
    this.view = committed.view;
    this.storeRevision = revision;
    this.rollbackAnchorValue = cloneGroupSecurityRollbackAnchor(anchorValue);
  }

  private async reconcileControlFork(
    candidates: ReadonlyArray<MembershipControlRecord>,
    candidateIds: ReadonlyArray<Uint8Array>,
    firstAnchorCandidate?: GroupSecurityRollbackAnchorValue,
  ): Promise<void> {
    if (
      candidates.length === 0 ||
      candidates.length !== candidateIds.length
    ) {
      const reason = new Error('fork reconciliation candidate set is invalid');
      this.poisonedReason = reason;
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        'authenticated control reconciliation could not be completed',
        { cause: reason },
      );
    }
    const terminalCandidate = candidates[candidates.length - 1];
    const terminalCandidateId = candidateIds[candidateIds.length - 1];
    let snapshot: GroupStateStoreSnapshot | undefined;
    try {
      snapshot = await this.loadValidatedStoreSnapshot();
    } catch (error) {
      return this.persistReconciliationAmbiguity(
        terminalCandidate,
        terminalCandidateId,
        error,
        firstAnchorCandidate,
      );
    }
    if (snapshot?.encryptedState === undefined) {
      return this.persistReconciliationAmbiguity(
        terminalCandidate,
        terminalCandidateId,
        new Error('durable winner snapshot is unavailable'),
      );
    }
    let winnerView: CoordinatorView;
    let initial: GroupSecurityRollbackAnchorValue;
    try {
      winnerView = await this.buildVerifiedView(
        snapshot.encryptedState.state,
        snapshot.replay,
        snapshot.outbox,
        true,
      );
      initial = rollbackAnchorValue(
        snapshot.revision,
        winnerView.publicState,
        winnerView.headRecordId,
        await groupSecurityStoreSnapshotCommitment(snapshot, this.storeKey),
      );
    } catch (error) {
      return this.persistReconciliationAmbiguity(
        terminalCandidate,
        terminalCandidateId,
        error,
        firstAnchorCandidate,
      );
    }
    for (let index = 0; index < candidates.length; index++) {
      const candidate = candidates[index];
      const candidateId = candidateIds[index];
      const acceptedEntry = winnerView.replay.find(
        (entry) => entry.epoch === candidate.epoch,
      );
      if (
        acceptedEntry === undefined ||
        equalBytes(acceptedEntry.recordId, candidateId)
      ) {
        continue;
      }
      const accepted = winnerView.recordsById.get(
        toHex(acceptedEntry.recordId),
      );
      if (
        accepted === undefined ||
        !optionalBytesEqual(
          accepted.parentRecordId,
          candidate.parentRecordId,
        )
      ) {
        continue;
      }
      const evidence = makeForkEvidence(
        accepted,
        acceptedEntry.recordId,
        candidate,
        candidateId,
      );
      await this.persistRollbackForkPoison(evidence, initial);
      const error = new GroupSecurityCoordinatorError(
        'fork-detected',
        'same-parent control fork was irreversibly recorded after a concurrent store conflict',
      );
      this.forkReason = error;
      throw error;
    }
  }

  private async persistReconciliationAmbiguity(
    candidate: MembershipControlRecord,
    candidateId: Uint8Array,
    reconciliationError: unknown,
    firstAnchorCandidate?: GroupSecurityRollbackAnchorValue,
  ): Promise<never> {
    const base = this.rollbackAnchorValue;
    if (base === undefined) {
      if (
        firstAnchorCandidate === undefined ||
        firstAnchorCandidate.forkPoison !== undefined ||
        firstAnchorCandidate.epoch !== candidate.epoch ||
        !equalBytes(firstAnchorCandidate.controlHead, candidateId)
      ) {
        const reason =
          reconciliationError instanceof Error
            ? reconciliationError
            : new Error('authenticated control reconciliation failed');
        this.poisonedReason = reason;
        throw new GroupSecurityCoordinatorError(
          'rollback-failed',
          'authenticated first-anchor reconciliation failed without a poisonable candidate anchor; coordinator is poisoned',
          { cause: reason },
        );
      }
      const initial = cloneGroupSecurityRollbackAnchor(firstAnchorCandidate);
      const ambiguity = await rollbackFirstAnchorAmbiguityPoison(
        candidate,
        candidateId,
        initial,
      );
      try {
        const poisoned = cloneGroupSecurityRollbackAnchor(
          await this.rollbackAnchor.poison(
            cloneStoreKey(this.storeKey),
            ambiguity,
            initial,
          ),
        );
        if (poisoned.forkPoison === undefined) {
          throw new Error(
            'rollback anchor poison did not return a terminal value',
          );
        }
        this.rollbackAnchorValue = cloneGroupSecurityRollbackAnchor(poisoned);
      } catch (error) {
        const reason = normalizeFailure(
          error,
          'first-anchor ambiguity poison failed with a non-Error value',
        );
        this.poisonedReason = reason;
        throw new GroupSecurityCoordinatorError(
          'rollback-failed',
          'authenticated first-anchor ambiguity could not be durably marked; coordinator is poisoned',
          { cause: reason },
        );
      }
      const error = new GroupSecurityCoordinatorError(
        'fork-detected',
        'an authenticated first-anchor candidate could not be reconciled; the rollback anchor is terminally poisoned',
        {
          cause:
            reconciliationError instanceof Error
              ? reconciliationError
              : new Error('authenticated control reconciliation failed'),
        },
      );
      this.forkReason = error;
      throw error;
    }
    if (
      candidate.parentRecordId === undefined ||
      !equalBytes(candidate.parentRecordId, base.controlHead)
    ) {
      const reason =
        reconciliationError instanceof Error
          ? reconciliationError
          : new Error('authenticated control reconciliation failed');
      this.poisonedReason = reason;
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        'authenticated control reconciliation candidate does not extend the active anchor; coordinator is poisoned',
        { cause: reason },
      );
    }
    const ambiguity = await rollbackAmbiguityPoison(
      candidate,
      candidateId,
      base,
    );
    try {
      const poisoned = cloneGroupSecurityRollbackAnchor(
        await this.rollbackAnchor.poison(
          cloneStoreKey(this.storeKey),
          ambiguity,
        ),
      );
      if (poisoned.forkPoison === undefined) {
        throw new Error(
          'rollback anchor poison did not return a terminal value',
        );
      }
    } catch (error) {
      const reason =
        error instanceof Error
          ? error
          : new Error('rollback anchor poison failed');
      this.poisonedReason = reason;
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        'authenticated control ambiguity could not be durably marked; coordinator is poisoned',
        { cause: reason },
      );
    }
    const error = new GroupSecurityCoordinatorError(
      'fork-detected',
      'an authenticated control candidate could not be reconciled after a durable write conflict; the rollback anchor is terminally poisoned',
      {
        cause:
          reconciliationError instanceof Error
            ? reconciliationError
            : new Error('authenticated control reconciliation failed'),
      },
    );
    this.forkReason = error;
    throw error;
  }

  private async flushOutboxInternal(
    send: (
      delivery: GroupSecurityDelivery,
      signal: AbortSignal,
    ) => Promise<GroupSecurityDurableAcceptance>,
  ): Promise<GroupSecurityFlushResult> {
    const snapshot = await this.verifyCurrentStoreSnapshot();
    await this.rejectPersistedFork(snapshot);
    this.assertOutboxBound(snapshot.outbox.length);
    const entries = [...snapshot.outbox].sort(compareOutboxEntries);
    let delivered = 0;
    let remaining = entries.length;

    for (const entry of entries) {
      let delivery: GroupSecurityDelivery;
      try {
        delivery = await this.validateDelivery(
          entry,
          this.outboxCodec.decode(new Uint8Array(entry.payload)),
        );
        await this.verifyControlSignatureOnly(delivery.controlRecord);
        const accepted = this.view.recordsById.get(toHex(entry.id));
        if (
          accepted === undefined ||
          !equalBytes(
            serializeMembershipControlRecord(accepted),
            serializeMembershipControlRecord(delivery.controlRecord),
          )
        ) {
          throw new Error('outbox control record is not the accepted replay record');
        }
      } catch (error) {
        fail(
          'malformed-state',
          `durable outbox entry ${toHex(entry.id)} is malformed`,
          error,
        );
      }
      try {
        const acceptance = await this.sendOutboxDeliveryWithDeadline(
          send,
          delivery,
        );
        await validateGroupSecurityDurableAcceptance(
          acceptance,
          delivery,
        );
      } catch (error) {
        throw new GroupSecurityCoordinatorError(
          'delivery-failed',
          `delivery was not durably accepted for outbox entry ${toHex(entry.id)}`,
          { cause: error },
        );
      }

      const ackBaseSnapshot = await this.verifyCurrentStoreSnapshot();
      await this.rejectPersistedFork(ackBaseSnapshot);
      const ackEncryptedState = ackBaseSnapshot.encryptedState;
      if (ackEncryptedState === undefined) {
        fail('malformed-state', 'encrypted state disappeared before ACK');
      }
      const expectedAckOutbox = ackBaseSnapshot.outbox.filter(
        (candidate) => !equalBytes(candidate.id, entry.id),
      );
      if (expectedAckOutbox.length + 1 !== ackBaseSnapshot.outbox.length) {
        fail('store-conflict', 'outbox entry disappeared before ACK');
      }
      const expectedAckPruneSet = new Set(
        replayIdsToPrune(
          ackBaseSnapshot.replay,
          expectedAckOutbox,
          ackEncryptedState.state.epoch,
          this.replayWindowEpochs,
        ).map(toHex),
      );
      const expectedAckCommitment =
        await groupSecurityStoreSnapshotCommitment({
          revision: this.storeRevision + 1,
          encryptedState: ackEncryptedState,
          pendingKeyPackages: ackBaseSnapshot.pendingKeyPackages,
          pendingKeyPackageRequests:
            ackBaseSnapshot.pendingKeyPackageRequests,
          consumedKeyPackageRefs: ackBaseSnapshot.consumedKeyPackageRefs,
          outbox: expectedAckOutbox,
          replay: ackBaseSnapshot.replay.filter(
            (candidate) =>
              !expectedAckPruneSet.has(toHex(candidate.recordId)),
          ),
          forkEvidence: ackBaseSnapshot.forkEvidence,
        }, this.storeKey);

      let transactionInvoked = false;
      let intendedStoreCommitment: Uint8Array | undefined;
      let ambiguousStoreFailure: AmbiguousStoreFailure | undefined;
      try {
        await this.store.transaction(
          this.storeKey,
          async (transaction) => {
            if (transactionInvoked) {
              fail(
                'store-conflict',
                'outbox ACK transaction was invoked more than once',
              );
            }
            transactionInvoked = true;
            await this.assertTransactionBase(
              transaction,
              this.view.publicState,
            );
            if (transaction.removeOutbox(entry.id) !== true) {
              fail('store-conflict', 'outbox entry disappeared before ACK');
            }
            const encryptedState = transaction.encryptedState;
            if (encryptedState === undefined) {
              fail('malformed-state', 'encrypted state disappeared during ACK');
            }
            pruneReplayTransaction(
              transaction,
              encryptedState.state.epoch,
              this.replayWindowEpochs,
            );
            this.assertReplayBound(transaction.replay.length);
            await this.buildVerifiedView(
              encryptedState.state,
              transaction.replay,
              transaction.outbox,
            );
            const transactionCommitment =
              await groupStateTransactionCommitment(
                transaction,
                this.storeKey,
              );
            if (!equalBytes(transactionCommitment, expectedAckCommitment)) {
              fail(
                'store-conflict',
                'outbox ACK transaction produced an unexpected durable delta',
              );
            }
            intendedStoreCommitment = new Uint8Array(expectedAckCommitment);
          },
        );
      } catch (error) {
        ambiguousStoreFailure = { cause: error };
      }
      const revision = this.storeRevision + 1;
      const committed = await this.loadCommittedCoordinatorView(
        revision,
        this.view.publicState,
        this.view.headRecordId,
        intendedStoreCommitment,
        'outbox ACK',
        ambiguousStoreFailure,
      );
      const anchorValue = rollbackAnchorValue(
        revision,
        committed.view.publicState,
        committed.view.headRecordId,
        committed.storeCommitment,
      );
      await this.advanceRollbackAnchor(
        this.requireCurrentRollbackAnchor(),
        anchorValue,
      );
      this.view = committed.view;
      this.storeRevision = revision;
      this.rollbackAnchorValue = cloneGroupSecurityRollbackAnchor(anchorValue);
      delivered += 1;
      remaining -= 1;
    }

    return { delivered, remaining };
  }

  private async sendOutboxDeliveryWithDeadline(
    send: (
      delivery: GroupSecurityDelivery,
      signal: AbortSignal,
    ) => Promise<GroupSecurityDurableAcceptance>,
    delivery: GroupSecurityDelivery,
  ): Promise<GroupSecurityDurableAcceptance> {
    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const deliveryResult = Promise.resolve().then(() =>
      send(cloneDelivery(delivery), controller.signal),
    );
    const deadline = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        reject(new Error('group-security outbox delivery timed out'));
        controller.abort();
      }, this.outboxDeliveryTimeoutMs);
    });
    try {
      return await Promise.race([deliveryResult, deadline]);
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
    }
  }

  private async verifyJoinInvitation(
    invitation: GroupSecurityJoinInvitation,
    pendingPackage: GroupKeyPackage,
  ): Promise<VerifiedJoinInvitation> {
    validateKeyPackage(pendingPackage, this.storeKey);
    validateIdentity(invitation.subjectId, 'invitation subjectId');
    validateBytes(
      invitation.keyPackageRef,
      'invitation keyPackageRef',
      1,
      MAX_IDENTITY_BYTES,
    );
    if (!equalBytes(invitation.keyPackageRef, pendingPackage.reference)) {
      fail(
        'control-mismatch',
        'invitation KeyPackage reference does not match pending state',
      );
    }

    const chain = new MembershipControlChain({
      protocol: this.storeKey.protocol,
      groupId: this.storeKey.groupId,
      verifySignature: this.verifyControlSignature,
      authorize: this.authorizeControl,
    });
    for (const record of invitation.controlPrefix) {
      const result = await chain.ingest(record);
      if (result.status === 'accepted') continue;
      if (result.status === 'duplicate') {
        fail(
          'operation-conflict',
          'invitation control prefix contains a duplicate record',
        );
      }
      switch (result.reason) {
        case 'bad-signature':
          fail('bad-signature', result.message);
        case 'unauthorized-actor':
          fail('unauthorized-control', result.message);
        case 'protocol-mismatch':
          fail('protocol-mismatch', result.message);
        case 'group-mismatch':
          fail('group-mismatch', result.message);
        case 'operation-id-conflict':
          fail('operation-conflict', result.message);
        case 'fork-detected':
          fail('fork-detected', result.message);
        default:
          fail('control-mismatch', result.message);
      }
    }
    const records = chain.records();
    if (records.length < 2) {
      fail(
        'control-mismatch',
        'recipient invitation must contain genesis through an Add record',
      );
    }
    validateGenesisControlPayload(records[0], this.storeKey);
    for (let index = 1; index < records.length - 1; index++) {
      try {
        parseControlBinding(records[index]);
      } catch (error) {
        fail(
          'control-mismatch',
          `invitation control at epoch ${records[index].epoch} has an invalid binding`,
          error,
        );
      }
    }

    const finalRecord = records.at(-1)!;
    if (
      finalRecord.action !== 'add' ||
      !equalBytes(finalRecord.subjectId, invitation.subjectId)
    ) {
      fail(
        'control-mismatch',
        'terminal invitation control is not an Add for the expected subject',
      );
    }
    let stateCommitment: GroupSecurityStateCommitment;
    try {
      validateCommit(invitation.commit);
      validateWelcomes([invitation.welcome], invitation.commit);
      stateCommitment = parseControlBinding(
        finalRecord,
        invitation.commit,
      );
    } catch (error) {
      fail(
        'control-mismatch',
        'terminal invitation control does not bind its Commit and Welcome',
        error,
      );
    }
    if (
      !sameProtocol(invitation.commit.protocol, this.storeKey.protocol) ||
      !sameProtocol(invitation.welcome.protocol, this.storeKey.protocol)
    ) {
      fail('protocol-mismatch', 'invitation protocol does not match group');
    }
    if (
      !equalBytes(invitation.commit.groupId, this.storeKey.groupId) ||
      !equalBytes(invitation.welcome.groupId, this.storeKey.groupId)
    ) {
      fail('group-mismatch', 'invitation is bound to another group');
    }
    if (
      finalRecord.epoch === 0n ||
      invitation.commit.priorEpoch !== finalRecord.epoch - 1n ||
      invitation.commit.epoch !== finalRecord.epoch ||
      invitation.welcome.epoch !== finalRecord.epoch
    ) {
      fail(
        'epoch-mismatch',
        'invitation Commit and Welcome do not match the terminal Add epoch',
      );
    }
    if (
      !equalBytes(
        invitation.welcome.recipientKeyPackageRef,
        invitation.keyPackageRef,
      )
    ) {
      fail(
        'control-mismatch',
        'invitation Welcome addresses another KeyPackage',
      );
    }
    const expectedMembership: AppliedGroupMembershipDelta = {
      changes: [
        {
          kind: 'add',
          memberId: new Uint8Array(invitation.subjectId),
          keyPackageRef: new Uint8Array(invitation.keyPackageRef),
        },
      ],
    };
    if (
      !equalBytes(
        stateCommitment.appliedMembershipDeltaHash,
        await appliedGroupMembershipDeltaHash(expectedMembership),
      ) ||
      !equalBytes(
        stateCommitment.welcomeSetHash,
        await welcomeSetHash([invitation.welcome], invitation.commit),
      )
    ) {
      fail(
        'control-mismatch',
        'terminal Add does not bind the expected subject, KeyPackage, or Welcome',
      );
    }
    await this.requireAuthenticatedKeyPackageMember(
      pendingPackage,
      invitation.subjectId,
      'invitation KeyPackage',
    );
    const recordIds = await Promise.all(
      records.map((record) => membershipControlRecordId(record)),
    );
    const finalRecordId = recordIds.at(-1)!;
    if (!equalBytes(chain.headRecordId!, finalRecordId)) {
      fail('control-mismatch', 'invitation control head is inconsistent');
    }
    return {
      records,
      recordIds,
      finalRecord,
      finalRecordId,
      stateCommitment,
    };
  }

  private validateJoinedState(
    state: GroupSecurityPublicState,
    verified: VerifiedJoinInvitation,
  ): void {
    assertPublicStateMatchesKey(state, this.storeKey);
    if (
      state.epoch !== verified.finalRecord.epoch ||
      !equalBytes(
        state.confirmedTranscriptHash,
        verified.stateCommitment.confirmedTranscriptHash,
      ) ||
      !equalBytes(state.treeHash, verified.stateCommitment.treeHash)
    ) {
      fail(
        'control-mismatch',
        'joined provider state does not match the signed terminal Add',
      );
    }
  }

  private async verifyGenesisControl(
    record: MembershipControlRecord,
    state: GroupSecurityPublicState,
  ): Promise<Uint8Array> {
    serializeMembershipControlRecord(record);
    if (record.action !== 'create' || record.parentRecordId !== undefined) {
      fail('control-mismatch', 'genesis control has invalid linkage');
    }
    if (
      !sameProtocol(record.protocol, state.protocol) ||
      !equalBytes(record.groupId, state.groupId) ||
      record.epoch !== 0n ||
      !equalBytes(record.controlPayload, canonicalGroupSecurityState(state))
    ) {
      fail('control-mismatch', 'genesis control does not bind group state');
    }
    await this.verifyControlSignatureOnly(record);
    const recordId = await membershipControlRecordId(record);
    await this.authorizeControlRecord(record, recordId, undefined, undefined);
    return recordId;
  }

  private async verifyControl(
    record: MembershipControlRecord,
    commit: GroupSecurityCommit | undefined,
    welcomes: ReadonlyArray<GroupWelcome> | undefined,
    attachmentError?: unknown,
  ): Promise<ValidatedControl> {
    try {
      serializeMembershipControlRecord(record);
    } catch (error) {
      fail('control-mismatch', 'control record is malformed', error);
    }
    if (!sameProtocol(record.protocol, this.storeKey.protocol)) {
      fail('protocol-mismatch', 'control protocol does not match group');
    }
    if (!equalBytes(record.groupId, this.storeKey.groupId)) {
      fail('group-mismatch', 'control group does not match');
    }
    const recordId = await membershipControlRecordId(record);
    await this.verifyControlSignatureOnly(record);
    try {
      if (record.action === 'create') {
        validateGenesisControlPayload(record, this.storeKey);
      } else {
        parseControlBinding(record);
      }
    } catch (error) {
      if (error instanceof GroupSecurityCoordinatorError) throw error;
      fail('control-mismatch', 'signed control semantics are malformed', error);
    }
    const recordHex = toHex(recordId);
    const acceptedAtEpoch = this.view.replay.find(
      (entry) => entry.epoch === record.epoch,
    );
    if (acceptedAtEpoch !== undefined) {
      const acceptedRecord = this.view.recordsById.get(
        toHex(acceptedAtEpoch.recordId),
      );
      if (
        acceptedRecord !== undefined &&
        !equalBytes(acceptedAtEpoch.recordId, recordId) &&
        optionalBytesEqual(
          acceptedRecord.parentRecordId,
          record.parentRecordId,
        )
      ) {
        const parentId = record.parentRecordId;
        const parentRecord =
          parentId === undefined
            ? undefined
            : this.view.recordsById.get(toHex(parentId));
        if (parentId !== undefined && parentRecord === undefined) {
          fail(
            'malformed-state',
            'retained fork candidate has no authorization parent',
          );
        }
        await this.authorizeControlRecord(
          record,
          recordId,
          parentRecord,
          parentId,
        );
        await this.persistForkEvidence(
          acceptedRecord,
          acceptedAtEpoch.recordId,
          record,
          recordId,
        );
      }
    }
    if (
      attachmentError !== undefined ||
      commit === undefined ||
      welcomes === undefined
    ) {
      fail('control-mismatch', 'commit delivery is malformed', attachmentError);
    }
    let binding: GroupSecurityStateCommitment;
    try {
      validateCommit(commit);
      if (!sameProtocol(commit.protocol, this.storeKey.protocol)) {
        fail('protocol-mismatch', 'commit protocol does not match group');
      }
      if (!equalBytes(commit.groupId, this.storeKey.groupId)) {
        fail('group-mismatch', 'commit group does not match');
      }
      binding = parseControlBinding(record, commit);
      validateWelcomes(welcomes, commit);
      if (
        !equalBytes(
          binding.welcomeSetHash,
          await welcomeSetHash(welcomes, commit),
        )
      ) {
        throw new Error('Welcome set does not match signed commitment');
      }
    } catch (error) {
      if (error instanceof GroupSecurityCoordinatorError) throw error;
      fail('control-mismatch', 'control record does not bind the commit', error);
    }
    if (record.action === 'create' || record.epoch !== commit.epoch) {
      fail('control-mismatch', 'control record does not bind the commit');
    }
    if (this.view.recordIds.has(recordHex)) {
      if (
        this.view.operationToRecord.get(toHex(record.operationId)) !== recordHex
      ) {
        fail('operation-conflict', 'duplicate has inconsistent operationId');
      }
      return {
        status: 'duplicate',
        recordId,
        stateCommitment: binding,
      };
    }
    if (this.view.operationToRecord.has(toHex(record.operationId))) {
      fail('operation-conflict', 'operationId belongs to another record');
    }
    const expectedEpoch = incrementEpoch(this.view.publicState.epoch);
    if (record.epoch < expectedEpoch) {
      fail('stale-replay', 'control record is outside replay retention');
    }
    if (
      record.epoch !== expectedEpoch ||
      commit.priorEpoch !== this.view.publicState.epoch ||
      commit.epoch !== expectedEpoch
    ) {
      fail('epoch-mismatch', 'commit/control does not advance one epoch');
    }
    if (
      record.parentRecordId === undefined ||
      !equalBytes(record.parentRecordId, this.view.headRecordId)
    ) {
      fail('control-mismatch', 'control parent is not the current head');
    }
    await this.authorizeControlRecord(
      record,
      recordId,
      this.view.lastControlRecord,
      this.view.headRecordId,
    );
    return { status: 'new', recordId, stateCommitment: binding };
  }

  private async verifyControlSignatureOnly(
    record: MembershipControlRecord,
  ): Promise<void> {
    const canonical = canonicalMembershipControlPayload(record);
    let valid: unknown = false;
    try {
      valid = await this.verifyControlSignature(
        new Uint8Array(canonical),
        new Uint8Array(record.signature),
        new Uint8Array(record.actorId),
      );
    } catch (error) {
      fail('bad-signature', 'control signature verifier failed', error);
    }
    if (valid !== true) fail('bad-signature', 'control signature is invalid');
  }

  private async authorizeControlRecord(
    record: MembershipControlRecord,
    recordId: Uint8Array,
    previousRecord: MembershipControlRecord | undefined,
    previousRecordId: Uint8Array | undefined,
  ): Promise<void> {
    const context: MembershipControlAuthorizationContext = {
      record: cloneControlRecord(record),
      recordId: new Uint8Array(recordId),
      previousRecord:
        previousRecord === undefined
          ? undefined
          : cloneControlRecord(previousRecord),
      previousRecordId:
        previousRecordId === undefined
          ? undefined
          : new Uint8Array(previousRecordId),
    };
    let authorized: unknown = false;
    try {
      authorized = await this.authorizeControl(context);
    } catch (error) {
      fail('unauthorized-control', 'control authorizer failed', error);
    }
    if (authorized !== true) {
      fail('unauthorized-control', 'control is unauthorized');
    }
  }

  private async buildVerifiedView(
    publicState: GroupSecurityPublicState,
    replayInput: ReadonlyArray<GroupStateReplayEntry>,
    outbox: ReadonlyArray<GroupStateOutboxEntry>,
    reauthorize = false,
  ): Promise<CoordinatorView> {
    assertPublicStateMatchesKey(publicState, this.storeKey);
    this.assertReplayBound(replayInput.length);
    this.assertOutboxBound(outbox.length);
    for (const entry of outbox) validateOutboxEntry(entry);
    if (replayInput.length === 0) {
      fail('malformed-state', 'durable replay metadata is empty');
    }
    const replay: GroupStateReplayEntry[] = [];
    const replayRecordIds = new Set<string>();
    const replayOperationIds = new Set<string>();
    const replayEpochs = new Set<string>();
    let replayBytes = 0;
    for (const entry of replayInput) {
      validateReplayEntry(entry);
      replayBytes +=
        FIXED_ID_LENGTH +
        FIXED_ID_LENGTH +
        8 +
        4 +
        entry.controlRecord.byteLength;
      if (
        !Number.isSafeInteger(replayBytes) ||
        replayBytes > MAX_GROUP_STATE_STORE_COMMITTED_BYTES
      ) {
        fail(
          'malformed-state',
          'durable replay metadata exceeds its aggregate byte bound',
        );
      }
      const recordId = toHex(entry.recordId);
      const operationId = toHex(entry.operationId!);
      const epoch = entry.epoch.toString();
      if (
        replayRecordIds.has(recordId) ||
        replayOperationIds.has(operationId) ||
        replayEpochs.has(epoch)
      ) {
        fail('malformed-state', 'duplicate durable replay identity or epoch');
      }
      replayRecordIds.add(recordId);
      replayOperationIds.add(operationId);
      replayEpochs.add(epoch);
      replay.push(cloneReplayEntry(entry));
    }
    replay.sort(compareReplayEntries);
    const operationToRecord = new Map<string, string>();
    const recordsById = new Map<string, MembershipControlRecord>();
    const commitmentsById = new Map<string, GroupSecurityStateCommitment>();
    const recordIds = new Set<string>();
    const byEpoch = new Map<string, GroupStateReplayEntry>();
    const pending = new Set(outbox.map((entry) => toHex(entry.id)));

    for (const entry of replay) {
      validateReplayEntry(entry);
      let record: MembershipControlRecord;
      try {
        record = deserializeMembershipControlRecord(entry.controlRecord);
        if (
          !equalBytes(
            serializeMembershipControlRecord(record),
            entry.controlRecord,
          )
        ) {
          throw new Error('control record is not canonical');
        }
      } catch (error) {
        fail('malformed-state', 'persisted control record is malformed', error);
      }
      const computedId = await membershipControlRecordId(record);
      if (
        !equalBytes(computedId, entry.recordId) ||
        !equalBytes(record.operationId, entry.operationId ?? new Uint8Array()) ||
        record.epoch !== entry.epoch
      ) {
        fail('malformed-state', 'replay metadata does not match control record');
      }
      if (
        !sameProtocol(record.protocol, this.storeKey.protocol) ||
        !equalBytes(record.groupId, this.storeKey.groupId)
      ) {
        fail('malformed-state', 'persisted control record belongs elsewhere');
      }
      if (record.action !== 'create') {
        try {
          commitmentsById.set(
            toHex(entry.recordId),
            parseControlBinding(record),
          );
        } catch (error) {
          fail(
            'malformed-state',
            'persisted control binding is malformed',
            error,
          );
        }
      }
      await this.verifyControlSignatureOnly(record);

      const recordHex = toHex(entry.recordId);
      const operationHex = toHex(record.operationId);
      const epochKey = entry.epoch.toString();
      if (
        recordIds.has(recordHex) ||
        operationToRecord.has(operationHex) ||
        byEpoch.has(epochKey)
      ) {
        fail('malformed-state', 'duplicate durable replay identity or epoch');
      }
      recordIds.add(recordHex);
      operationToRecord.set(operationHex, recordHex);
      recordsById.set(recordHex, cloneControlRecord(record));
      byEpoch.set(epochKey, entry);
    }

    const authorizationFloor = replayWindowFloor(
      publicState.epoch,
      this.replayWindowEpochs,
    );
    const retainedFloor = authorizationAnchorFloor(
      publicState.epoch,
      this.replayWindowEpochs,
    );
    for (let epoch = retainedFloor; epoch <= publicState.epoch; epoch += 1n) {
      if (!byEpoch.has(epoch.toString())) {
        fail('malformed-state', `missing replay metadata for epoch ${epoch}`);
      }
    }
    for (const entry of replay) {
      if (entry.epoch > publicState.epoch) {
        fail('malformed-state', 'replay metadata is newer than provider state');
      }
      if (
        entry.epoch < retainedFloor &&
        !pending.has(toHex(entry.recordId))
      ) {
        fail('malformed-state', 'stale replay metadata was not pruned');
      }
    }

    for (let index = 0; index < replay.length; index++) {
      const entry = replay[index];
      const record = recordsById.get(toHex(entry.recordId))!;
      if (record.action === 'create') {
        if (record.epoch !== 0n || record.parentRecordId !== undefined) {
          fail('malformed-state', 'persisted genesis linkage is invalid');
        }
      } else if (record.parentRecordId === undefined) {
        fail('malformed-state', 'non-genesis control has no parent');
      }
      const previous = replay[index - 1];
      if (
        previous !== undefined &&
        previous.epoch + 1n === entry.epoch &&
        !equalBytes(record.parentRecordId!, previous.recordId)
      ) {
        fail('malformed-state', 'persisted control chain linkage is broken');
      }
    }

    if (reauthorize) {
      for (const entry of replay) {
        if (entry.epoch < authorizationFloor) continue;
        const record = recordsById.get(toHex(entry.recordId))!;
        if (record.action === 'create') {
          await this.authorizeControlRecord(
            record,
            entry.recordId,
            undefined,
            undefined,
          );
          continue;
        }
        const previousEntry = byEpoch.get((entry.epoch - 1n).toString());
        if (previousEntry === undefined) {
          fail(
            'malformed-state',
            'authorization window is missing its previous-record anchor',
          );
        }
        const previousRecord = recordsById.get(toHex(previousEntry.recordId));
        if (previousRecord === undefined) {
          fail('malformed-state', 'authorization anchor record is missing');
        }
        await this.authorizeControlRecord(
          record,
          entry.recordId,
          previousRecord,
          previousEntry.recordId,
        );
      }
    }

    const head = byEpoch.get(publicState.epoch.toString());
    if (head === undefined) {
      fail('malformed-state', 'replay metadata has no current head');
    }
    const lastControlRecord = recordsById.get(toHex(head.recordId));
    if (lastControlRecord === undefined) {
      fail('malformed-state', 'current control record is unavailable');
    }
    if (lastControlRecord.action === 'create') {
      if (
        !equalBytes(
          lastControlRecord.controlPayload,
          canonicalGroupSecurityState(publicState),
        )
      ) {
        fail('malformed-state', 'genesis does not bind restored public state');
      }
    } else {
      const commitment = commitmentsById.get(toHex(head.recordId));
      if (
        commitment === undefined ||
        !equalBytes(
          commitment.confirmedTranscriptHash,
          publicState.confirmedTranscriptHash,
        ) ||
        !equalBytes(commitment.treeHash, publicState.treeHash)
      ) {
        fail(
          'malformed-state',
          'control head does not bind restored public state',
        );
      }
    }
    return {
      publicState: clonePublicState(publicState),
      replay,
      operationToRecord,
      recordsById,
      recordIds,
      headRecordId: new Uint8Array(head.recordId),
      lastControlRecord: cloneControlRecord(lastControlRecord),
    };
  }

  private async validateCommitResult(
    result: GroupSecurityCommitResult,
    prior: GroupSecurityPublicState,
    requestedMembership: AppliedGroupMembershipChange,
  ): Promise<void> {
    validateCommit(result.commit);
    const expectedEpoch = incrementEpoch(prior.epoch);
    if (
      !sameProtocol(result.commit.protocol, prior.protocol) ||
      !equalBytes(result.commit.groupId, prior.groupId) ||
      result.commit.priorEpoch !== prior.epoch ||
      result.commit.epoch !== expectedEpoch
    ) {
      fail('epoch-mismatch', 'provider commit does not advance current epoch');
    }
    assertSamePublicStateShape(
      result.state,
      result.commit.protocol,
      result.commit.groupId,
    );
    if (result.state.epoch !== result.commit.epoch) {
      fail('epoch-mismatch', 'provider state does not match commit epoch');
    }
    validateWelcomes(result.welcomes, result.commit);
    validateProviderMembershipAgainstRequest(
      result.appliedMembership,
      requestedMembership,
      result.welcomes,
    );
    assertSamePublicState(
      await this.providerPublicStateSnapshot(),
      result.state,
    );
  }

  private async validateApplyResult(
    result: GroupSecurityApplyResult,
    commit: GroupSecurityCommit,
    controlRecord: MembershipControlRecord,
    expected: GroupSecurityStateCommitment,
    welcomes: ReadonlyArray<GroupWelcome>,
  ): Promise<void> {
    assertSamePublicStateShape(result.state, commit.protocol, commit.groupId);
    if (result.state.epoch !== commit.epoch) {
      fail('epoch-mismatch', 'applied state does not match commit epoch');
    }
    if (
      !equalBytes(
        result.state.confirmedTranscriptHash,
        expected.confirmedTranscriptHash,
      ) ||
      !equalBytes(result.state.treeHash, expected.treeHash)
    ) {
      fail(
        'control-mismatch',
        'applied provider state does not match signed state commitment',
      );
    }
    validateProviderMembershipAgainstControl(
      result.appliedMembership,
      controlRecord,
      welcomes,
    );
    if (
      !equalBytes(
        await appliedGroupMembershipDeltaHash(result.appliedMembership),
        expected.appliedMembershipDeltaHash,
      )
    ) {
      fail(
        'control-mismatch',
        'provider-applied membership delta does not match signed commitment',
      );
    }
    assertSamePublicState(
      await this.providerPublicStateSnapshot(),
      result.state,
    );
  }

  private async exportAndValidateState(
    expected: GroupSecurityPublicState,
  ): Promise<EncryptedGroupState> {
    const snapshot = await this.exportProviderStateSnapshot();
    assertEnvelopeMatchesKey(snapshot, this.storeKey);
    assertSamePublicState(snapshot.state, expected);
    return snapshot;
  }

  private async exportProviderStateSnapshot(): Promise<EncryptedGroupState> {
    return snapshotEncryptedGroupState(
      await this.provider.exportEncryptedState(this.protector),
    );
  }

  private async requireAuthenticatedKeyPackageMember(
    keyPackage: GroupKeyPackage,
    expectedMemberId: Uint8Array,
    context: string,
  ): Promise<void> {
    let authenticatedMemberId: Uint8Array;
    try {
      authenticatedMemberId = copyControlRecordBytes(
        await this.provider.authenticateKeyPackageMember(
          cloneKeyPackage(keyPackage),
        ),
        `${context} authenticated memberId`,
        1,
        MAX_IDENTITY_BYTES,
      );
    } catch (error) {
      fail(
        'control-mismatch',
        `${context} credential-to-member binding is invalid`,
        error,
      );
    }
    if (!equalBytes(authenticatedMemberId, expectedMemberId)) {
      fail(
        'control-mismatch',
        `${context} is authenticated for a different member`,
      );
    }
  }

  private async requireAuthenticatedKeyPackageRequestCommitment(
    keyPackage: GroupKeyPackage,
    expectedCommitment: Uint8Array,
    context: string,
  ): Promise<void> {
    let authenticatedCommitment: Uint8Array;
    try {
      authenticatedCommitment = copyControlRecordBytes(
        await this.provider.authenticateKeyPackageRequestCommitment(
          cloneKeyPackage(keyPackage),
        ),
        `${context} authenticated request commitment`,
        FIXED_ID_LENGTH,
        FIXED_ID_LENGTH,
      );
    } catch (error) {
      fail(
        'control-mismatch',
        `${context} request binding is invalid`,
        error,
      );
    }
    if (!equalBytes(authenticatedCommitment, expectedCommitment)) {
      fail(
        'operation-conflict',
        `${context} is authenticated for a different pending request`,
      );
    }
  }

  private async makeOutboxEntry(
    delivery: GroupSecurityDelivery,
  ): Promise<GroupStateOutboxEntry> {
    const expectedDelivery = cloneDelivery(delivery);
    const recordId = await membershipControlRecordId(
      expectedDelivery.controlRecord,
    );
    let payload: Uint8Array;
    try {
      payload = copyControlRecordBytes(
        this.outboxCodec.encode(cloneDelivery(expectedDelivery)),
        'outbox payload',
        1,
        MAX_OUTBOX_PAYLOAD_BYTES,
      );
    } catch (error) {
      fail('control-mismatch', 'outbox codec failed to encode', error);
    }
    const createdAt = this.now();
    if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
      fail('control-mismatch', 'outbox timestamp is invalid');
    }
    const entry: GroupStateOutboxEntry = {
      id: recordId,
      kind: GROUP_SECURITY_OUTBOX_KIND,
      epoch: expectedDelivery.controlRecord.epoch,
      payload: new Uint8Array(payload),
      createdAt,
    };
    try {
      const first = await this.validateDelivery(
        entry,
        this.outboxCodec.decode(new Uint8Array(payload)),
      );
      const second = await this.validateDelivery(
        entry,
        this.outboxCodec.decode(new Uint8Array(payload)),
      );
      await this.verifyControlSignatureOnly(first.controlRecord);
      if (
        !sameDelivery(first, expectedDelivery) ||
        !sameDelivery(second, expectedDelivery)
      ) {
        throw new Error('outbox codec does not round-trip exactly');
      }
    } catch (error) {
      fail('control-mismatch', 'outbox codec round-trip failed', error);
    }
    return entry;
  }

  private async validateDelivery(
    entry: GroupStateOutboxEntry,
    deliveryValue: GroupSecurityDelivery,
  ): Promise<GroupSecurityDelivery> {
    const delivery = cloneDelivery(deliveryValue);
    if (entry.kind !== GROUP_SECURITY_OUTBOX_KIND) {
      throw new Error('unexpected outbox kind');
    }
    serializeMembershipControlRecord(delivery.controlRecord);
    const recordId = await membershipControlRecordId(delivery.controlRecord);
    if (
      !equalBytes(recordId, entry.id) ||
      delivery.controlRecord.epoch !== entry.epoch ||
      !sameProtocol(delivery.controlRecord.protocol, this.storeKey.protocol) ||
      !equalBytes(delivery.controlRecord.groupId, this.storeKey.groupId)
    ) {
      throw new Error('outbox metadata does not match control record');
    }
    if (!Array.isArray(delivery.welcomes)) {
      throw new Error('outbox welcomes must be an array');
    }
    if (delivery.commit === undefined) {
      if (
        delivery.controlRecord.action !== 'create' ||
        delivery.welcomes.length !== 0
      ) {
        throw new Error('only genesis without Welcomes may omit a commit');
      }
      return delivery;
    }
    validateCommit(delivery.commit);
    const binding = parseControlBinding(
      delivery.controlRecord,
      delivery.commit,
    );
    if (
      delivery.controlRecord.action === 'create' ||
      delivery.controlRecord.epoch !== delivery.commit.epoch ||
      !sameProtocol(
        delivery.controlRecord.protocol,
        delivery.commit.protocol,
      ) ||
      !equalBytes(delivery.controlRecord.groupId, delivery.commit.groupId)
    ) {
      throw new Error('outbox control does not bind commit');
    }
    validateWelcomes(delivery.welcomes, delivery.commit);
    if (
      !equalBytes(
        binding.welcomeSetHash,
        await welcomeSetHash(delivery.welcomes, delivery.commit),
      )
    ) {
      throw new Error('outbox Welcome set does not match signed commitment');
    }
    return delivery;
  }

  private async persistForkEvidence(
    acceptedRecord: MembershipControlRecord,
    acceptedRecordId: Uint8Array,
    conflictingRecord: MembershipControlRecord,
    conflictingRecordId: Uint8Array,
  ): Promise<never> {
    const evidence = makeForkEvidence(
      acceptedRecord,
      acceptedRecordId,
      conflictingRecord,
      conflictingRecordId,
    );
    const poisonedAnchor = await this.persistRollbackForkPoison(evidence);
    this.forkReason = new GroupSecurityCoordinatorError(
      'fork-detected',
      'same-parent control fork is terminally recorded in the rollback anchor',
    );
    let cause: unknown;
    try {
      await this.store.transaction(
        this.storeKey,
        async (transaction) => {
          if (transaction.baseRevision !== poisonedAnchor.revision) {
            fail('store-conflict', 'group state changed before fork audit');
          }
          const baseSnapshot = groupStateTransactionSnapshot(
            transaction,
            transaction.baseRevision,
          );
          const baseCommitment =
            await groupSecurityStoreSnapshotCommitment(
              baseSnapshot,
              this.storeKey,
            );
          if (!equalBytes(baseCommitment, poisonedAnchor.storeCommitment)) {
            fail(
              'rollback-detected',
              'fork audit transaction base does not match the poisoned rollback anchor',
            );
          }
          const encryptedState = baseSnapshot.encryptedState;
          if (encryptedState === undefined) {
            fail('malformed-state', 'durable encrypted state is missing');
          }
          assertSamePublicState(encryptedState.state, this.view.publicState);
          if (transaction.hasReplayRecord(acceptedRecordId) !== true) {
            fail(
              'malformed-state',
              'accepted fork record is not durably retained',
            );
          }
          if (transaction.markFork(evidence) !== true) {
            fail('store-conflict', 'fork audit evidence was not durably marked');
          }
        },
      );
    } catch (error) {
      cause = error;
    }
    const forkError = new GroupSecurityCoordinatorError(
      'fork-detected',
      cause === undefined
        ? 'same-parent control fork: two authorized records share one epoch'
        : 'same-parent control fork detected but durable evidence failed to commit',
      cause === undefined ? undefined : { cause },
    );
    this.forkReason = forkError;
    throw forkError;
  }

  private async persistRollbackForkPoison(
    evidence: GroupStateForkEvidence,
    initial?: GroupSecurityRollbackAnchorValue,
  ): Promise<GroupSecurityRollbackAnchorValue> {
    const forkPoison = await rollbackForkPoison(evidence);
    try {
      const poisoned = cloneGroupSecurityRollbackAnchor(
        await this.rollbackAnchor.poison(
          cloneStoreKey(this.storeKey),
          forkPoison,
          initial,
        ),
      );
      if (poisoned.forkPoison === undefined) {
        throw new Error('rollback anchor poison did not return a terminal value');
      }
      this.rollbackAnchorValue = cloneGroupSecurityRollbackAnchor(poisoned);
      return poisoned;
    } catch (error) {
      const reason = normalizeFailure(
        error,
        'fork poison failed with a non-Error value',
      );
      this.poisonedReason = reason;
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        'authenticated fork could not be durably recorded in the rollback anchor; coordinator is poisoned',
        { cause: reason },
      );
    }
  }

  private async rejectPersistedFork(
    snapshot: GroupStateStoreSnapshot,
  ): Promise<void> {
    if (snapshot.forkEvidence === undefined) return;
    await this.validatePersistedForkEvidence(snapshot.forkEvidence, this.view);
    const error = new GroupSecurityCoordinatorError(
      'fork-detected',
      'durable group state is stopped after a same-parent control fork',
    );
    this.forkReason = error;
    throw error;
  }

  private async validatePersistedForkEvidence(
    evidence: GroupStateForkEvidence,
    view: CoordinatorView,
  ): Promise<void> {
    try {
      validateU64(evidence.epoch, 'fork epoch');
      validateFixedId(evidence.parentRecordId, 'fork parentRecordId');
      validateFixedId(evidence.firstRecordId, 'fork firstRecordId');
      validateFixedId(evidence.secondRecordId, 'fork secondRecordId');
      if (equalBytes(evidence.firstRecordId, evidence.secondRecordId)) {
        throw new Error('fork evidence record IDs are invalid');
      }
      const first = deserializeMembershipControlRecord(
        evidence.firstControlRecord,
      );
      const second = deserializeMembershipControlRecord(
        evidence.secondControlRecord,
      );
      const genesisFork =
        first.action === 'create' &&
        second.action === 'create' &&
        first.epoch === 0n &&
        second.epoch === 0n &&
        first.parentRecordId === undefined &&
        second.parentRecordId === undefined &&
        equalBytes(evidence.parentRecordId, GENESIS_FORK_PARENT_ID);
      const ordinaryFork =
        first.action !== 'create' &&
        second.action !== 'create' &&
        first.parentRecordId !== undefined &&
        second.parentRecordId !== undefined &&
        equalBytes(first.parentRecordId, evidence.parentRecordId) &&
        equalBytes(second.parentRecordId, evidence.parentRecordId);
      if (
        !equalBytes(
          serializeMembershipControlRecord(first),
          evidence.firstControlRecord,
        ) ||
        !equalBytes(
          serializeMembershipControlRecord(second),
          evidence.secondControlRecord,
        ) ||
        !equalBytes(await membershipControlRecordId(first), evidence.firstRecordId) ||
        !equalBytes(
          await membershipControlRecordId(second),
          evidence.secondRecordId,
        ) ||
        first.epoch !== evidence.epoch ||
        second.epoch !== evidence.epoch ||
        (!genesisFork && !ordinaryFork) ||
        !sameProtocol(first.protocol, this.storeKey.protocol) ||
        !sameProtocol(second.protocol, this.storeKey.protocol) ||
        !equalBytes(first.groupId, this.storeKey.groupId) ||
        !equalBytes(second.groupId, this.storeKey.groupId)
      ) {
        throw new Error('fork evidence does not contain canonical siblings');
      }
      if (genesisFork) {
        validateGenesisControlPayload(first, this.storeKey);
        validateGenesisControlPayload(second, this.storeKey);
      } else {
        parseControlBinding(first);
        parseControlBinding(second);
      }
      await this.verifyControlSignatureOnly(first);
      await this.verifyControlSignatureOnly(second);

      const acceptedEntry = view.replay.find(
        (entry) => entry.epoch === evidence.epoch,
      );
      if (acceptedEntry === undefined) {
        throw new Error('fork evidence has no retained accepted record');
      }
      const acceptedIsFirst = equalBytes(
        acceptedEntry.recordId,
        evidence.firstRecordId,
      );
      const acceptedIsSecond = equalBytes(
        acceptedEntry.recordId,
        evidence.secondRecordId,
      );
      if (acceptedIsFirst === acceptedIsSecond) {
        throw new Error('fork evidence does not include the accepted record');
      }
      const conflicting = acceptedIsFirst ? second : first;
      const conflictingId = acceptedIsFirst
        ? evidence.secondRecordId
        : evidence.firstRecordId;
      const parent = genesisFork
        ? undefined
        : view.recordsById.get(toHex(evidence.parentRecordId));
      if (!genesisFork && parent === undefined) {
        throw new Error('fork evidence authorization parent is unavailable');
      }
      await this.authorizeControlRecord(
        conflicting,
        conflictingId,
        parent,
        genesisFork ? undefined : evidence.parentRecordId,
      );
    } catch (error) {
      if (error instanceof GroupSecurityCoordinatorError) throw error;
      fail('malformed-state', 'durable same-parent fork evidence is malformed', error);
    }
  }

  private enqueueBounded(
    transaction: GroupStateStoreTransaction,
    outbox: GroupStateOutboxEntry,
  ): void {
    if (transaction.outbox.length >= this.maxOutboxEntries) {
      fail('outbox-overflow', 'durable outbox capacity reached');
    }
    if (transaction.enqueueOutbox(outbox) !== true) {
      fail('store-conflict', 'outbox record already exists');
    }
    this.assertOutboxBound(transaction.outbox.length);
  }

  private async assertTransactionBase(
    transaction: GroupStateStoreTransaction,
    expected: GroupSecurityPublicState,
  ): Promise<void> {
    const snapshot =
      await this.verifyTransactionSnapshotAgainstRollbackAnchor(
        transaction,
        this.requireCurrentRollbackAnchor(),
      );
    if (snapshot.forkEvidence !== undefined) {
      const error = new GroupSecurityCoordinatorError(
        'fork-detected',
        'durable group state is stopped after a same-parent control fork',
      );
      this.forkReason = error;
      throw error;
    }
    const current = snapshot.encryptedState;
    if (current === undefined) {
      fail('malformed-state', 'durable encrypted state is missing');
    }
    assertSamePublicState(current.state, expected);
  }

  private async verifyTransactionSnapshotAgainstRollbackAnchor(
    transaction: GroupStateStoreTransaction,
    expected: GroupSecurityRollbackAnchorValue,
  ): Promise<GroupStateStoreSnapshot> {
    const baseRevision = transaction.baseRevision;
    if (baseRevision !== expected.revision) {
      fail('store-conflict', 'durable group-state revision changed');
    }
    let snapshot: GroupStateStoreSnapshot;
    try {
      snapshot = groupStateTransactionSnapshot(transaction, baseRevision);
    } catch (error) {
      fail(
        'rollback-detected',
        'durable group-state transaction base cannot be verified',
        error,
      );
    }
    await this.verifySnapshotAgainstRollbackAnchor(snapshot, expected);
    return snapshot;
  }

  private requireAbsentGroupRevision(
    snapshot: GroupStateStoreSnapshot | undefined,
  ): number {
    if (snapshot === undefined) return 0;
    if (!Number.isSafeInteger(snapshot.revision) || snapshot.revision < 1) {
      fail('malformed-state', 'pending group-state revision is invalid');
    }
    if (snapshot.encryptedState !== undefined) {
      fail('already-initialized', 'group security state already exists');
    }
    if (
      snapshot.outbox.length !== 0 ||
      snapshot.replay.length !== 0 ||
      snapshot.consumedKeyPackageRefs.length !== 0 ||
      snapshot.forkEvidence !== undefined
    ) {
      fail(
        'malformed-state',
        'active-group metadata exists without encrypted group state',
      );
    }
    return snapshot.revision;
  }

  private async requireAbsentRollbackAnchor(): Promise<void> {
    if ((await this.loadRollbackAnchor()) !== undefined) {
      fail(
        'rollback-detected',
        'rollback anchor exists while durable group state is absent',
      );
    }
  }

  private async rollbackPendingKeyPackage(
    reference: Uint8Array,
    originalError: unknown,
  ): Promise<void> {
    if (this.provider.clearKeyPackageState === undefined) {
      throw new GroupSecurityCoordinatorError(
        'rollback-unavailable',
        'pending KeyPackage persistence failed; discard this provider instance',
        { cause: originalError },
      );
    }
    try {
      await this.provider.clearKeyPackageState(new Uint8Array(reference));
    } catch (error) {
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        'pending KeyPackage cleanup failed; discard this provider instance',
        { cause: error },
      );
    }
  }

  private async rollbackJoinProvider(
    reference: Uint8Array,
    joinAttempted: boolean,
    originalError: unknown,
  ): Promise<void> {
    let unavailable = false;
    try {
      if (joinAttempted) {
        if (this.provider.clearGroupState === undefined) {
          unavailable = true;
        } else {
          await this.provider.clearGroupState();
          if (await this.providerHasActiveGroup()) {
            throw new Error(
              'recipient join cleanup left the provider group active',
            );
          }
        }
      }
      if (this.provider.clearKeyPackageState === undefined) {
        unavailable = true;
      } else {
        await this.provider.clearKeyPackageState(new Uint8Array(reference));
      }
    } catch (error) {
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        'recipient join cleanup failed; discard this provider instance',
        { cause: error },
      );
    }
    if (unavailable) {
      throw new GroupSecurityCoordinatorError(
        'rollback-unavailable',
        'recipient join failed after provider mutation; discard this provider instance',
        { cause: originalError },
      );
    }
  }

  private async providerHasActiveGroup(): Promise<boolean> {
    let active: boolean;
    try {
      active = await this.provider.hasActiveGroup();
    } catch (error) {
      fail(
        'malformed-state',
        'provider active-group lifecycle status is unavailable',
        error,
      );
    }
    if (typeof active !== 'boolean') {
      fail(
        'malformed-state',
        'provider returned an invalid active-group lifecycle status',
      );
    }
    return active;
  }

  private async providerPublicStateSnapshot(): Promise<
    GroupSecurityPublicState
  > {
    return clonePublicState(await this.provider.getPublicState());
  }

  private async providerCheckpoint(): Promise<EncryptedGroupState | undefined> {
    if (!(await this.providerHasActiveGroup())) return undefined;
    const checkpoint = await this.exportProviderStateSnapshot();
    assertSamePublicState(
      await this.providerPublicStateSnapshot(),
      checkpoint.state,
    );
    return checkpoint;
  }

  private async rollbackInitialization(
    checkpoint: EncryptedGroupState | undefined,
    originalError: unknown,
    phase: 'bootstrap' | 'restore',
  ): Promise<void> {
    if (
      checkpoint === undefined &&
      this.provider.clearGroupState === undefined
    ) {
      throw new GroupSecurityCoordinatorError(
        'rollback-unavailable',
        `${phase} failed after provider mutation; discard this provider instance`,
        { cause: originalError },
      );
    }
    try {
      if (checkpoint !== undefined) {
        const expected = clonePublicState(checkpoint.state);
        const rollbackEnvelope = snapshotEncryptedGroupState(checkpoint);
        const restored = clonePublicState(
          await this.provider.importEncryptedState(
            rollbackEnvelope,
            this.protector,
          ),
        );
        assertSamePublicState(restored, expected);
        assertSamePublicState(
          await this.providerPublicStateSnapshot(),
          expected,
        );
      } else {
        await this.provider.clearGroupState!();
        if (await this.providerHasActiveGroup()) {
          throw new Error(`${phase} cleanup left the provider group active`);
        }
      }
    } catch (rollbackError) {
      throw new GroupSecurityCoordinatorError(
        'rollback-failed',
        `${phase} provider rollback failed; discard this provider instance`,
        { cause: rollbackError },
      );
    }
  }

  private async withProviderRollback<T>(
    checkpoint: EncryptedGroupState,
    priorState: GroupSecurityPublicState,
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (this.poisonedReason !== undefined) throw error;
      try {
        const rollbackEnvelope = snapshotEncryptedGroupState(checkpoint);
        const restored = clonePublicState(
          await this.provider.importEncryptedState(
            rollbackEnvelope,
            this.protector,
          ),
        );
        assertSamePublicState(restored, priorState);
        assertSamePublicState(
          await this.providerPublicStateSnapshot(),
          priorState,
        );
      } catch (rollbackError) {
        this.poisonedReason = normalizeFailure(
          rollbackError,
          'provider rollback failed with a non-Error value',
        );
        throw new GroupSecurityCoordinatorError(
          'rollback-failed',
          'provider rollback failed; coordinator is poisoned',
          { cause: rollbackError },
        );
      }
      throw error;
    }
  }

  private async loadRollbackAnchor(): Promise<
    GroupSecurityRollbackAnchorValue | undefined
  > {
    let value: GroupSecurityRollbackAnchorValue | undefined;
    try {
      value = await this.rollbackAnchor.load(cloneStoreKey(this.storeKey));
    } catch (error) {
      fail('rollback-failed', 'rollback anchor could not be loaded', error);
    }
    if (value === undefined) return undefined;
    try {
      return cloneGroupSecurityRollbackAnchor(value);
    } catch (error) {
      fail('rollback-detected', 'rollback anchor is malformed', error);
    }
  }

  private rejectRollbackForkPoison(
    value: GroupSecurityRollbackAnchorValue | undefined,
  ): void {
    if (value?.forkPoison === undefined) return;
    const error = new GroupSecurityCoordinatorError(
      'fork-detected',
      'rollback anchor is irreversibly poisoned by an authenticated control fork or unresolved authenticated candidate',
    );
    this.forkReason = error;
    throw error;
  }

  private async loadAndVerifyRollbackSnapshot(
    snapshot: GroupStateStoreSnapshot,
    state: GroupSecurityPublicState,
  ): Promise<GroupSecurityRollbackAnchorValue> {
    let storeCommitment: Uint8Array;
    try {
      storeCommitment = await groupSecurityStoreSnapshotCommitment(
        snapshot,
        this.storeKey,
      );
    } catch (error) {
      fail(
        'rollback-detected',
        'durable group-state snapshot cannot be bound to its rollback anchor',
        error,
      );
    }
    const actual = await this.loadRollbackAnchor();
    this.rejectRollbackForkPoison(actual);
    if (
      actual === undefined ||
      actual.revision !== snapshot.revision ||
      actual.epoch !== state.epoch ||
      !equalBytes(actual.storeCommitment, storeCommitment)
    ) {
      fail(
        'rollback-detected',
        actual === undefined
          ? 'rollback anchor is missing for durable group state'
          : 'durable group state does not match its rollback anchor',
      );
    }
    return cloneGroupSecurityRollbackAnchor(actual);
  }

  private async advanceRollbackAnchor(
    expected: GroupSecurityRollbackAnchorValue | undefined,
    next: GroupSecurityRollbackAnchorValue,
  ): Promise<void> {
    const expectedSnapshot =
      expected === undefined
        ? undefined
        : cloneGroupSecurityRollbackAnchor(expected);
    const nextSnapshot = cloneGroupSecurityRollbackAnchor(next);
    await this.verifyCommittedStoreSnapshot(nextSnapshot);
    let advanced: unknown = false;
    let cause: unknown;
    try {
      advanced = await this.rollbackAnchor.advance(
        cloneStoreKey(this.storeKey),
        expectedSnapshot,
        nextSnapshot,
      );
      if (advanced !== true) {
        cause = new Error('rollback anchor compare-and-set was rejected');
      }
    } catch (error) {
      cause = error;
    }
    if (cause === undefined && advanced === true) return;
    const reason = normalizeFailure(
      cause,
      'rollback anchor advance failed with a non-Error value',
    );
    this.poisonedReason = reason;
    throw new GroupSecurityCoordinatorError(
      'rollback-failed',
      'durable group state committed but its rollback anchor did not advance; coordinator is poisoned',
      { cause: reason },
    );
  }

  private requireCurrentRollbackAnchor(): GroupSecurityRollbackAnchorValue {
    if (this.rollbackAnchorValue !== undefined) {
      return cloneGroupSecurityRollbackAnchor(this.rollbackAnchorValue);
    }
    const reason = new Error('coordinator has no verified rollback anchor');
    this.poisonedReason = reason;
    throw new GroupSecurityCoordinatorError(
      'rollback-failed',
      'coordinator has no verified rollback anchor and is poisoned',
      { cause: reason },
    );
  }

  private async verifyCurrentStoreSnapshot(): Promise<GroupStateStoreSnapshot> {
    const snapshot = await this.requireSnapshot();
    await this.verifySnapshotAgainstRollbackAnchor(
      snapshot,
      this.requireCurrentRollbackAnchor(),
    );
    return snapshot;
  }

  private async verifySnapshotAgainstRollbackAnchor(
    snapshot: GroupStateStoreSnapshot,
    expected: GroupSecurityRollbackAnchorValue,
  ): Promise<void> {
    if (snapshot.revision !== expected.revision) {
      fail('store-conflict', 'durable group-state revision changed');
    }
    let storeCommitment: Uint8Array;
    try {
      storeCommitment = await groupSecurityStoreSnapshotCommitment(
        snapshot,
        this.storeKey,
      );
    } catch (error) {
      fail(
        'rollback-detected',
        'durable group-state snapshot cannot be verified against its rollback anchor',
        error,
      );
    }
    const actual = await this.loadRollbackAnchor();
    this.rejectRollbackForkPoison(actual);
    const observed = cloneGroupSecurityRollbackAnchor({
      revision: snapshot.revision,
      epoch: expected.epoch,
      controlHead: expected.controlHead,
      storeCommitment,
      forkPoison: undefined,
    });
    if (
      !groupSecurityRollbackAnchorsEqual(actual, expected) ||
      !groupSecurityRollbackAnchorsEqual(observed, expected)
    ) {
      fail(
        'rollback-detected',
        'durable group state does not match its current rollback anchor',
      );
    }
  }

  private async verifyCommittedStoreSnapshot(
    expected: GroupSecurityRollbackAnchorValue,
  ): Promise<void> {
    let cause: unknown;
    try {
      const snapshot = await this.loadValidatedStoreSnapshot();
      if (
        snapshot === undefined ||
        snapshot.revision !== expected.revision ||
        snapshot.encryptedState === undefined ||
        snapshot.encryptedState.state.epoch !== expected.epoch
      ) {
        throw new Error(
          'committed group-state snapshot revision or epoch is inconsistent',
        );
      }
      const storeCommitment =
        await groupSecurityStoreSnapshotCommitment(snapshot, this.storeKey);
      if (!equalBytes(storeCommitment, expected.storeCommitment)) {
        throw new Error(
          'committed group-state snapshot has a different commitment',
        );
      }
    } catch (error) {
      cause = error;
    }
    if (cause === undefined) return;
    const reason = normalizeFailure(
      cause,
      'committed store verification failed with a non-Error value',
    );
    this.poisonedReason = reason;
    throw new GroupSecurityCoordinatorError(
      'rollback-failed',
      'durable group state committed but could not be verified before its rollback anchor advanced; coordinator is poisoned',
      { cause: reason },
    );
  }

  private async loadCommittedCoordinatorView(
    expectedRevision: number,
    expectedState: GroupSecurityPublicState,
    expectedHeadRecordId: Uint8Array,
    intendedStoreCommitment: Uint8Array | undefined,
    operation: string,
    ambiguousStoreFailure?: AmbiguousStoreFailure,
  ): Promise<{ view: CoordinatorView; storeCommitment: Uint8Array }> {
    let cause: unknown;
    try {
      if (intendedStoreCommitment === undefined) {
        throw new Error('durable store did not invoke its transaction callback');
      }
      const snapshot = await this.loadValidatedStoreSnapshot();
      if (
        snapshot === undefined ||
        snapshot.revision !== expectedRevision ||
        snapshot.encryptedState === undefined
      ) {
        throw new Error(
          'committed group-state snapshot has an unexpected revision or no encrypted state',
        );
      }
      assertSamePublicState(snapshot.encryptedState.state, expectedState);
      const actualStoreCommitment =
        await groupSecurityStoreSnapshotCommitment(snapshot, this.storeKey);
      if (!equalBytes(actualStoreCommitment, intendedStoreCommitment)) {
        throw new Error(
          'committed group-state snapshot differs from the intended transaction',
        );
      }
      const view = await this.buildVerifiedView(
        snapshot.encryptedState.state,
        snapshot.replay,
        snapshot.outbox,
        true,
      );
      assertSamePublicState(view.publicState, expectedState);
      if (!equalBytes(view.headRecordId, expectedHeadRecordId)) {
        throw new Error('committed group-state snapshot has an unexpected control head');
      }
      return {
        view,
        storeCommitment: new Uint8Array(actualStoreCommitment),
      };
    } catch (error) {
      cause = error;
    }
    if (ambiguousStoreFailure !== undefined) {
      throw ambiguousStoreFailure.cause;
    }
    const reason = normalizeFailure(
      cause,
      'post-commit view verification failed with a non-Error value',
    );
    this.poisonedReason = reason;
    throw new GroupSecurityCoordinatorError(
      'rollback-failed',
      `${operation} committed but its canonical post-commit view could not be verified; coordinator is poisoned`,
      { cause: reason },
    );
  }

  private async verifyRestoreSnapshotStillCurrent(
    expectedAnchor: GroupSecurityRollbackAnchorValue,
    expectedView: CoordinatorView,
  ): Promise<void> {
    const actualAnchor = await this.loadRollbackAnchor();
    this.rejectRollbackForkPoison(actualAnchor);
    if (
      !groupSecurityRollbackAnchorsEqual(actualAnchor, expectedAnchor) ||
      !equalBytes(expectedAnchor.controlHead, expectedView.headRecordId)
    ) {
      fail(
        'rollback-detected',
        'rollback anchor changed while provider state was being restored',
      );
    }
    const snapshot = await this.requireSnapshot();
    if (
      snapshot.revision !== expectedAnchor.revision ||
      snapshot.encryptedState === undefined ||
      snapshot.encryptedState.state.epoch !== expectedAnchor.epoch
    ) {
      fail(
        'rollback-detected',
        'durable group state changed while provider state was being restored',
      );
    }
    assertSamePublicState(
      snapshot.encryptedState.state,
      expectedView.publicState,
    );
    const commitment = await groupSecurityStoreSnapshotCommitment(
      snapshot,
      this.storeKey,
    );
    if (!equalBytes(commitment, expectedAnchor.storeCommitment)) {
      fail(
        'rollback-detected',
        'durable group state commitment changed while provider state was being restored',
      );
    }
    const finalAnchor = await this.loadRollbackAnchor();
    this.rejectRollbackForkPoison(finalAnchor);
    if (!groupSecurityRollbackAnchorsEqual(finalAnchor, expectedAnchor)) {
      fail(
        'rollback-detected',
        'rollback anchor changed while the restored store snapshot was being verified',
      );
    }
  }

  private async requireSnapshot(): Promise<GroupStateStoreSnapshot> {
    const snapshot = await this.loadValidatedStoreSnapshot();
    if (snapshot === undefined) {
      fail('not-initialized', 'group security state is not initialized');
    }
    if (!Number.isSafeInteger(snapshot.revision) || snapshot.revision < 1) {
      fail('malformed-state', 'store revision is invalid');
    }
    return snapshot;
  }

  private async loadValidatedStoreSnapshot(): Promise<
    GroupStateStoreSnapshot | undefined
  > {
    const loaded = await this.store.load(this.storeKey);
    if (loaded === undefined) return undefined;
    try {
      return validateAndCloneGroupStateStoreSnapshot(loaded, this.storeKey);
    } catch (error) {
      fail(
        'malformed-state',
        'durable group-state snapshot is malformed or exceeds its bound',
        error,
      );
    }
  }

  private assertOutboxBound(length: number): void {
    if (length > this.maxOutboxEntries) {
      fail('outbox-overflow', 'durable outbox exceeds configured capacity');
    }
  }

  private assertReplayBound(length: number): void {
    if (length > this.maxReplayEntries) {
      fail('replay-overflow', 'durable replay set exceeds configured capacity');
    }
  }

  private runExclusive<T>(task: () => Promise<T>): Promise<T> {
    const next = this.mutationTail.then(
      () => {
        this.assertUsable();
        return task();
      },
      () => {
        this.assertUsable();
        return task();
      },
    );
    this.mutationTail = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private assertUsable(): void {
    if (this.forkReason !== undefined) throw this.forkReason;
    if (this.poisonedReason !== undefined) {
      throw new GroupSecurityCoordinatorError(
        'poisoned',
        'coordinator is poisoned after rollback failure',
        { cause: this.poisonedReason },
      );
    }
    if (this.view === undefined) {
      fail('not-initialized', 'group security coordinator is not initialized');
    }
  }
}

export function canonicalGroupSecurityCommit(
  commit: GroupSecurityCommit,
): Uint8Array {
  const snapshot = cloneCommit(commit);
  return concat([
    COMMIT_DOMAIN,
    bytes16(new TextEncoder().encode(snapshot.protocol.id)),
    u16(snapshot.protocol.version),
    bytes16(snapshot.groupId),
    u64(snapshot.priorEpoch),
    u64(snapshot.epoch),
    bytes32(snapshot.payload),
  ]);
}

export async function canonicalGroupSecurityControlPayload(
  commit: GroupSecurityCommit,
  requestDigest: Uint8Array,
  resultingState: GroupSecurityPublicState,
  appliedMembership: AppliedGroupMembershipDelta,
  welcomes: ReadonlyArray<GroupWelcome> = [],
): Promise<Uint8Array> {
  const commitSnapshot = cloneCommit(commit);
  validateFixedId(requestDigest, 'requestDigest');
  validatePublicState(resultingState);
  if (
    !sameProtocol(commitSnapshot.protocol, resultingState.protocol) ||
    !equalBytes(commitSnapshot.groupId, resultingState.groupId) ||
    commitSnapshot.epoch !== resultingState.epoch
  ) {
    throw new Error('resulting state does not match the commit');
  }
  return concat([
    CONTROL_BINDING_DOMAIN,
    new Uint8Array(requestDigest),
    bytes16(resultingState.confirmedTranscriptHash),
    bytes16(resultingState.treeHash),
    await appliedGroupMembershipDeltaHash(appliedMembership),
    await welcomeSetHash(welcomes, commitSnapshot),
    canonicalGroupSecurityCommit(commitSnapshot),
  ]);
}

export function canonicalGroupSecurityState(
  state: GroupSecurityPublicState,
): Uint8Array {
  validatePublicState(state);
  return concat([
    GENESIS_DOMAIN,
    bytes16(new TextEncoder().encode(state.protocol.id)),
    u16(state.protocol.version),
    bytes16(state.groupId),
    u64(state.epoch),
    bytes16(state.confirmedTranscriptHash),
    bytes16(state.treeHash),
  ]);
}

function rollbackAnchorValue(
  revision: number,
  state: GroupSecurityPublicState,
  controlHead: Uint8Array,
  storeCommitment: Uint8Array,
): GroupSecurityRollbackAnchorValue {
  return cloneGroupSecurityRollbackAnchor({
    revision,
    epoch: state.epoch,
    controlHead: new Uint8Array(controlHead),
    storeCommitment: new Uint8Array(storeCommitment),
    forkPoison: undefined,
  });
}

async function groupStateTransactionCommitment(
  transaction: GroupStateStoreTransaction,
  storeKey: GroupStateStoreKey,
): Promise<Uint8Array> {
  const baseRevision = transaction.baseRevision;
  if (baseRevision === Number.MAX_SAFE_INTEGER) {
    throw new Error('group-state store revision limit reached');
  }
  return groupSecurityStoreSnapshotCommitment(
    groupStateTransactionSnapshot(transaction, baseRevision + 1),
    storeKey,
  );
}

function groupStateTransactionSnapshot(
  transaction: GroupStateStoreTransaction,
  revision: number,
): GroupStateStoreSnapshot {
  const snapshot: GroupStateStoreSnapshot = {
    revision,
    encryptedState: transaction.encryptedState,
    pendingKeyPackages: transaction.pendingKeyPackages,
    pendingKeyPackageRequests: transaction.pendingKeyPackageRequests,
    consumedKeyPackageRefs: transaction.consumedKeyPackageRefs,
    outbox: transaction.outbox,
    replay: transaction.replay,
    forkEvidence: transaction.forkEvidence,
  };
  return snapshot;
}

function validateGenesisControlPayload(
  record: MembershipControlRecord,
  storeKey: GroupStateStoreKey,
): void {
  try {
    if (
      record.action !== 'create' ||
      record.epoch !== 0n ||
      record.parentRecordId !== undefined
    ) {
      throw new Error('genesis record has invalid linkage');
    }
    const payload = record.controlPayload;
    if (
      payload.byteLength < GENESIS_DOMAIN.byteLength ||
      !equalBytes(
        payload.subarray(0, GENESIS_DOMAIN.byteLength),
        GENESIS_DOMAIN,
      )
    ) {
      throw new Error('genesis payload has an invalid domain');
    }
    let offset = GENESIS_DOMAIN.byteLength;
    const protocolId = readBoundedBytes16(
      payload,
      offset,
      'genesis protocol.id',
      1,
      128,
    );
    offset = protocolId.nextOffset;
    if (offset + 2 > payload.byteLength) {
      throw new Error('genesis payload is truncated at protocol.version');
    }
    const protocolVersion = new DataView(
      payload.buffer,
      payload.byteOffset + offset,
      2,
    ).getUint16(0, false);
    offset += 2;
    const group = readBoundedBytes16(
      payload,
      offset,
      'genesis groupId',
      1,
      MAX_GROUP_ID_BYTES,
    );
    offset = group.nextOffset;
    if (offset + 8 > payload.byteLength) {
      throw new Error('genesis payload is truncated at epoch');
    }
    const epoch = new DataView(
      payload.buffer,
      payload.byteOffset + offset,
      8,
    ).getBigUint64(0, false);
    offset += 8;
    const transcript = readBoundedBytes16(
      payload,
      offset,
      'genesis confirmedTranscriptHash',
      1,
      128,
    );
    offset = transcript.nextOffset;
    const tree = readBoundedBytes16(
      payload,
      offset,
      'genesis treeHash',
      1,
      128,
    );
    offset = tree.nextOffset;
    if (
      offset !== payload.byteLength ||
      !equalBytes(
        protocolId.value,
        new TextEncoder().encode(storeKey.protocol.id),
      ) ||
      protocolVersion !== storeKey.protocol.version ||
      !equalBytes(group.value, storeKey.groupId) ||
      epoch !== 0n
    ) {
      throw new Error('genesis payload does not bind the expected group');
    }
    const expected = canonicalGroupSecurityState({
      protocol: { ...storeKey.protocol },
      groupId: new Uint8Array(storeKey.groupId),
      epoch,
      confirmedTranscriptHash: transcript.value,
      treeHash: tree.value,
    });
    if (!equalBytes(payload, expected)) {
      throw new Error('genesis payload is not canonical');
    }
  } catch (error) {
    fail(
      'control-mismatch',
      'invitation genesis does not canonically bind the expected group',
      error,
    );
  }
}

function requestDigestFromControlRecord(
  record: MembershipControlRecord,
): Uint8Array {
  const minimum = CONTROL_BINDING_DOMAIN.byteLength + FIXED_ID_LENGTH;
  if (
    record.controlPayload.byteLength < minimum ||
    !equalBytes(
      record.controlPayload.subarray(0, CONTROL_BINDING_DOMAIN.byteLength),
      CONTROL_BINDING_DOMAIN,
    )
  ) {
    fail('control-mismatch', 'control payload has no request-digest binding');
  }
  return new Uint8Array(
    record.controlPayload.subarray(
      CONTROL_BINDING_DOMAIN.byteLength,
      CONTROL_BINDING_DOMAIN.byteLength + FIXED_ID_LENGTH,
    ),
  );
}

function parseControlBinding(
  record: MembershipControlRecord,
  commit?: GroupSecurityCommit,
): GroupSecurityStateCommitment {
  const payload = record.controlPayload;
  requestDigestFromControlRecord(record);
  let offset = CONTROL_BINDING_DOMAIN.byteLength + FIXED_ID_LENGTH;
  const transcript = readBoundedBytes16(
    payload,
    offset,
    'confirmedTranscriptHash',
    1,
    128,
  );
  offset = transcript.nextOffset;
  const tree = readBoundedBytes16(payload, offset, 'treeHash', 1, 128);
  offset = tree.nextOffset;
  if (offset + FIXED_ID_LENGTH * 2 > payload.byteLength) {
    throw new Error('control binding is truncated at membership/Welcome hashes');
  }
  const appliedMembershipDeltaHash = new Uint8Array(
    payload.subarray(offset, offset + FIXED_ID_LENGTH),
  );
  offset += FIXED_ID_LENGTH;
  const welcomeSetHash = new Uint8Array(
    payload.subarray(offset, offset + FIXED_ID_LENGTH),
  );
  offset += FIXED_ID_LENGTH;
  const encodedCommit = payload.subarray(offset);
  if (encodedCommit.byteLength === 0) {
    throw new Error('control binding is missing its canonical commit');
  }
  if (commit === undefined) {
    if (
      encodedCommit.byteLength < COMMIT_DOMAIN.byteLength ||
      !equalBytes(
        encodedCommit.subarray(0, COMMIT_DOMAIN.byteLength),
        COMMIT_DOMAIN,
      )
    ) {
      throw new Error('control binding has an invalid commit domain');
    }
  } else if (!equalBytes(encodedCommit, canonicalGroupSecurityCommit(commit))) {
    throw new Error('control binding does not match the supplied commit');
  }
  return {
    confirmedTranscriptHash: transcript.value,
    treeHash: tree.value,
    appliedMembershipDeltaHash,
    welcomeSetHash,
  };
}

function readBoundedBytes16(
  bytes: Uint8Array,
  offset: number,
  field: string,
  minimum: number,
  maximum: number,
): { value: Uint8Array; nextOffset: number } {
  if (offset + 2 > bytes.byteLength) {
    throw new Error(`control binding is truncated at ${field} length`);
  }
  const length = new DataView(
    bytes.buffer,
    bytes.byteOffset + offset,
    2,
  ).getUint16(0, false);
  offset += 2;
  if (
    length < minimum ||
    length > maximum ||
    offset + length > bytes.byteLength
  ) {
    throw new Error(`control binding has invalid ${field} length`);
  }
  return {
    value: new Uint8Array(bytes.subarray(offset, offset + length)),
    nextOffset: offset + length,
  };
}

function pruneReplayTransaction(
  transaction: GroupStateStoreTransaction,
  currentEpoch: bigint,
  window: bigint,
): void {
  const floor = authorizationAnchorFloor(currentEpoch, window);
  const pending = new Set(transaction.outbox.map((entry) => toHex(entry.id)));
  for (const entry of transaction.replay) {
    if (entry.epoch < floor && !pending.has(toHex(entry.recordId))) {
      if (transaction.removeReplay(entry.recordId) !== true) {
        fail('store-conflict', 'replay record disappeared during pruning');
      }
    }
  }
}

function replayIdsToPrune(
  replay: ReadonlyArray<GroupStateReplayEntry>,
  outbox: ReadonlyArray<GroupStateOutboxEntry>,
  currentEpoch: bigint,
  window: bigint,
): Uint8Array[] {
  const floor = authorizationAnchorFloor(currentEpoch, window);
  const pending = new Set(outbox.map((entry) => toHex(entry.id)));
  return replay
    .filter(
      (entry) =>
        entry.epoch < floor && !pending.has(toHex(entry.recordId)),
    )
    .map((entry) => new Uint8Array(entry.recordId));
}

function replayWindowFloor(currentEpoch: bigint, window: bigint): bigint {
  return currentEpoch + 1n > window ? currentEpoch - window + 1n : 0n;
}

function authorizationAnchorFloor(currentEpoch: bigint, window: bigint): bigint {
  const floor = replayWindowFloor(currentEpoch, window);
  return floor === 0n ? 0n : floor - 1n;
}

function snapshotCoordinatorConfig(
  config: GroupSecurityCoordinatorConfig,
): GroupSecurityCoordinatorConfig {
  const raw = exactOwnDataValues(
    config,
    [
      'provider',
      'store',
      'storeKey',
      'rollbackAnchor',
      'protector',
      'actorId',
      'signControlRecord',
      'verifyControlSignature',
      'authorizeControl',
      'outboxCodec',
    ],
    'group-security coordinator config',
    [
      'maxOutboxEntries',
      'maxReplayEntries',
      'replayWindowEpochs',
      'outboxDeliveryTimeoutMs',
      'now',
    ],
    true,
  );
  const rawConfig = raw as unknown as GroupSecurityCoordinatorConfig;
  const rawStoreKey = exactOwnDataValues(
    rawConfig.storeKey,
    ['protocol', 'groupId'],
    'group-security coordinator store key',
    [],
    true,
  ) as unknown as GroupStateStoreKey;
  const rawProtocol = exactOwnDataValues(
    rawStoreKey.protocol,
    ['id', 'version'],
    'group-security coordinator protocol',
    [],
    true,
  ) as unknown as GroupSecurityProtocol;
  validateBytes(
    rawStoreKey.groupId,
    'groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  validateIdentity(rawConfig.actorId, 'actorId');
  const snapshot: GroupSecurityCoordinatorConfig = {
    ...rawConfig,
    storeKey: {
      protocol: {
        id: rawProtocol.id,
        version: rawProtocol.version,
      },
      groupId: copyControlRecordBytes(
        rawStoreKey.groupId,
        'groupId',
        1,
        MAX_GROUP_ID_BYTES,
      ),
    },
    actorId: copyControlRecordBytes(
      rawConfig.actorId,
      'actorId',
      1,
      MAX_IDENTITY_BYTES,
    ),
  };
  validateCoordinatorConfig(snapshot);
  return snapshot;
}

function validateCoordinatorConfig(config: GroupSecurityCoordinatorConfig): void {
  validateProtocol(config.storeKey.protocol);
  validateBytes(config.storeKey.groupId, 'groupId', 1, MAX_GROUP_ID_BYTES);
  validateIdentity(config.actorId, 'actorId');
  if (
    config.rollbackAnchor === null ||
    typeof config.rollbackAnchor !== 'object' ||
    typeof config.rollbackAnchor.load !== 'function' ||
    typeof config.rollbackAnchor.advance !== 'function' ||
    typeof config.rollbackAnchor.poison !== 'function'
  ) {
    throw new Error(
      'rollbackAnchor must implement durable load, advance, and atomic poison',
    );
  }
  if (!sameProtocol(config.provider.protocol, config.storeKey.protocol)) {
    fail('protocol-mismatch', 'provider protocol does not match store key');
  }
  const maxOutbox =
    config.maxOutboxEntries ?? DEFAULT_GROUP_SECURITY_MAX_OUTBOX_ENTRIES;
  const maxReplay =
    config.maxReplayEntries ?? DEFAULT_GROUP_SECURITY_MAX_REPLAY_ENTRIES;
  const window =
    config.replayWindowEpochs ??
    DEFAULT_GROUP_SECURITY_REPLAY_WINDOW_EPOCHS;
  validateConfiguredCount(maxOutbox, 'maxOutboxEntries');
  validateConfiguredCount(maxReplay, 'maxReplayEntries');
  if (
    typeof window !== 'bigint' ||
    window < 1n ||
    window >= BigInt(MAX_CONFIGURED_ENTRIES)
  ) {
    throw new Error('replayWindowEpochs is outside configured bounds');
  }
  if (BigInt(maxReplay) < window + 1n) {
    throw new Error(
      'maxReplayEntries must cover replayWindowEpochs plus its authorization anchor',
    );
  }
  const deliveryTimeout =
    config.outboxDeliveryTimeoutMs ??
    DEFAULT_GROUP_SECURITY_OUTBOX_DELIVERY_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(deliveryTimeout) ||
    deliveryTimeout < 1 ||
    deliveryTimeout > MAX_OUTBOX_DELIVERY_TIMEOUT_MS
  ) {
    throw new Error('outboxDeliveryTimeoutMs is outside configured bounds');
  }
}

function validateConfiguredCount(value: number, field: string): void {
  if (
    !Number.isInteger(value) ||
    value < 1 ||
    value > MAX_CONFIGURED_ENTRIES
  ) {
    throw new Error(`${field} is outside configured bounds`);
  }
}

function validateControlInput(input: GroupSecurityControlInput): void {
  validateFixedId(input.operationId, 'operationId');
  validateFixedId(input.requestDigest, 'requestDigest');
  validateIdentity(input.subjectId, 'subjectId');
  if (!['add', 'remove', 'update'].includes(input.action)) {
    throw new Error('invalid non-genesis control action');
  }
}

function validateRequestedMembershipIntent(
  input: CreateGroupCommitInput,
  control: GroupSecurityControlInput,
  storeKey: GroupStateStoreKey,
): AppliedGroupMembershipChange {
  if (
    input === null ||
    typeof input !== 'object' ||
    !Array.isArray(input.changes) ||
    input.changes.length !== 1
  ) {
    fail(
      'control-mismatch',
      'each authenticated control must contain exactly one membership change',
    );
  }
  if (input.authenticatedData !== undefined) {
    validateBytes(
      input.authenticatedData,
      'commit authenticatedData',
      0,
      MAX_PROTOCOL_PAYLOAD_BYTES,
    );
  }
  const requested = input.changes[0];
  if (requested === null || typeof requested !== 'object') {
    fail('control-mismatch', 'membership change must be an object');
  }
  validateIdentity(requested.memberId, 'membership change memberId');
  if (
    requested.kind !== control.action ||
    !equalBytes(requested.memberId, control.subjectId)
  ) {
    fail(
      'control-mismatch',
      'requested membership change does not match control action/subject',
    );
  }
  if (requested.kind === 'add' || requested.kind === 'update') {
    validateKeyPackage(requested.keyPackage, storeKey);
    return {
      kind: requested.kind,
      memberId: new Uint8Array(requested.memberId),
      keyPackageRef: new Uint8Array(requested.keyPackage.reference),
    };
  }
  return {
    kind: 'remove',
    memberId: new Uint8Array(requested.memberId),
  };
}

function validateProviderMembershipAgainstRequest(
  delta: AppliedGroupMembershipDelta,
  requested: AppliedGroupMembershipChange,
  welcomes: ReadonlyArray<GroupWelcome>,
): void {
  const applied = requireSingleAppliedMembershipChange(delta);
  if (
    applied.kind !== requested.kind ||
    !equalBytes(applied.memberId, requested.memberId)
  ) {
    fail(
      'control-mismatch',
      'provider-applied membership change differs from requested action/subject',
    );
  }
  if (
    (applied.kind === 'add' || applied.kind === 'update') &&
    (requested.kind === 'add' || requested.kind === 'update') &&
    !equalBytes(applied.keyPackageRef, requested.keyPackageRef)
  ) {
    fail(
      'control-mismatch',
      'provider-applied key package differs from the requested change',
    );
  }
  validateWelcomeRecipients(applied, welcomes);
}

function cloneGroupSecurityControlInput(
  input: GroupSecurityControlInput,
): GroupSecurityControlInput {
  const snapshot = exactOwnDataValues(
    input,
    ['operationId', 'requestDigest', 'action', 'subjectId'],
    'group-security control input',
    [],
    true,
  );
  return {
    operationId: copyControlRecordBytes(
      snapshot.operationId,
      'group-security control operationId',
      FIXED_ID_LENGTH,
      FIXED_ID_LENGTH,
    ),
    requestDigest: copyControlRecordBytes(
      snapshot.requestDigest,
      'group-security control requestDigest',
      FIXED_ID_LENGTH,
      FIXED_ID_LENGTH,
    ),
    action: snapshot.action as GroupSecurityControlInput['action'],
    subjectId: copyControlRecordBytes(
      snapshot.subjectId,
      'group-security control subjectId',
      1,
      MAX_IDENTITY_BYTES,
    ),
  };
}

function cloneCreateKeyPackageInput(
  input: Omit<CreateKeyPackageInput, 'requestCommitment'>,
  storeKey: GroupStateStoreKey,
): Omit<CreateKeyPackageInput, 'requestCommitment'> {
  const snapshot = exactOwnDataValues(
    input,
    ['groupId', 'memberId', 'credential'],
    'create-KeyPackage input',
    ['extensions'],
    true,
  );
  const groupId = copyControlRecordBytes(
    snapshot.groupId,
    'create-KeyPackage groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  if (!equalBytes(groupId, storeKey.groupId)) {
    fail('group-mismatch', 'KeyPackage input is bound to another group');
  }
  const memberId = copyControlRecordBytes(
    snapshot.memberId,
    'create-KeyPackage memberId',
    1,
    MAX_IDENTITY_BYTES,
  );
  const credential = copyControlRecordBytes(
    snapshot.credential,
    'create-KeyPackage credential',
    1,
    MAX_PROTOCOL_PAYLOAD_BYTES,
  );
  let extensions: Map<number, Uint8Array> | undefined;
  const extensionValues = snapshot.extensions;
  if (extensionValues !== undefined) {
    let extensionCount: unknown;
    try {
      extensionCount = Reflect.apply(mapSizeGetter, extensionValues, []);
    } catch {
      throw new Error('create-KeyPackage extensions must be a bounded Map');
    }
    if (
      !Number.isSafeInteger(extensionCount) ||
      (extensionCount as number) < 0 ||
      (extensionCount as number) > 4096
    ) {
      throw new Error('create-KeyPackage extensions must be a bounded Map');
    }
    extensions = new Map();
    let totalBytes = 0;
    let observedEntries = 0;
    const seenTypes = new Set<number>();
    const entries = Reflect.apply(
      mapEntries,
      extensionValues,
      [],
    ) as IterableIterator<[number, Uint8Array]>;
    for (const [type, value] of entries) {
      observedEntries += 1;
      if (observedEntries > 4096 || seenTypes.has(type)) {
        throw new Error(
          'create-KeyPackage extensions contain duplicate or excess entries',
        );
      }
      seenTypes.add(type);
      if (!Number.isInteger(type) || type < 0 || type > 0xffff) {
        throw new Error('create-KeyPackage extension type is invalid');
      }
      const extension = copyControlRecordBytes(
        value,
        'create-KeyPackage extension value',
        0,
        MAX_PROTOCOL_PAYLOAD_BYTES,
      );
      totalBytes += extension.byteLength;
      if (totalBytes > MAX_PROTOCOL_PAYLOAD_BYTES) {
        throw new Error('create-KeyPackage extensions exceed their byte limit');
      }
      extensions.set(type, extension);
    }
    if (observedEntries !== extensionCount) {
      throw new Error('create-KeyPackage extensions changed while cloning');
    }
  }
  return {
    groupId,
    memberId,
    credential,
    extensions,
  };
}

function cloneCreatePendingKeyPackageInput(
  input: CreatePendingKeyPackageInput,
  storeKey: GroupStateStoreKey,
): CreatePendingKeyPackageInput {
  const snapshot = exactOwnDataValues(
    input,
    ['operationId', 'groupId', 'memberId', 'credential'],
    'create-pending-KeyPackage input',
    ['extensions'],
    true,
  );
  const operationId = copyControlRecordBytes(
    snapshot.operationId,
    'create-pending-KeyPackage operationId',
    FIXED_ID_LENGTH,
    FIXED_ID_LENGTH,
  );
  return {
    ...cloneCreateKeyPackageInput(
      {
        groupId: snapshot.groupId as Uint8Array,
        memberId: snapshot.memberId as Uint8Array,
        credential: snapshot.credential as Uint8Array,
        extensions: snapshot.extensions as ReadonlyMap<number, Uint8Array>,
      },
      storeKey,
    ),
    operationId,
  };
}

function cloneJoinInvitation(
  invitation: GroupSecurityJoinInvitation,
  maxReplayEntries: number,
): GroupSecurityJoinInvitation {
  const snapshot = exactOwnDataValues(
    invitation,
    ['subjectId', 'keyPackageRef', 'controlPrefix', 'commit', 'welcome'],
    'group-security invitation',
    ['authenticatedData'],
    true,
  );
  const subjectId = copyControlRecordBytes(
    snapshot.subjectId,
    'invitation subjectId',
    1,
    MAX_IDENTITY_BYTES,
  );
  const keyPackageRef = copyControlRecordBytes(
    snapshot.keyPackageRef,
    'invitation keyPackageRef',
    1,
    MAX_IDENTITY_BYTES,
  );
  const prefixRecords = snapshotExactArray(
    snapshot.controlPrefix,
    'invitation control prefix',
    2,
    maxReplayEntries,
  );
  const authenticatedData =
    snapshot.authenticatedData === undefined
      ? undefined
      : copyControlRecordBytes(
          snapshot.authenticatedData,
          'invitation authenticatedData',
          0,
          MAX_PROTOCOL_PAYLOAD_BYTES,
        );
  const commit = cloneCommit(snapshot.commit as GroupSecurityCommit);
  validateCommit(commit);
  const [welcome] = validateWelcomes(
    [snapshot.welcome as GroupWelcome],
    commit,
  );
  const controlPrefix: MembershipControlRecord[] = [];
  let controlPrefixBytes = 0;
  for (let index = 0; index < prefixRecords.length; index++) {
    const record = snapshotControlRecord(
      prefixRecords[index],
      `invitation control prefix record ${index}`,
    );
    const serialized = serializeMembershipControlRecord(record);
    controlPrefixBytes += serialized.byteLength;
    if (controlPrefixBytes > MAX_CONTROL_PREFIX_BYTES) {
      throw new Error('invitation control prefix exceeds its byte bound');
    }
    controlPrefix.push(deserializeMembershipControlRecord(serialized));
  }
  return {
    subjectId,
    keyPackageRef,
    controlPrefix,
    commit,
    welcome,
    authenticatedData,
  };
}

function snapshotExactArray(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): unknown[] {
  let isArray: boolean;
  let prototype: object | null;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = Array.isArray(value);
    prototype = isArray ? Object.getPrototypeOf(value) : null;
    lengthDescriptor = isArray
      ? Object.getOwnPropertyDescriptor(value, 'length')
      : undefined;
  } catch {
    throw new Error(`${field} must be a plain bounded array`);
  }
  const lengthValue =
    lengthDescriptor !== undefined && 'value' in lengthDescriptor
      ? lengthDescriptor.value
      : undefined;
  if (
    !isArray ||
    prototype !== Array.prototype ||
    !Number.isSafeInteger(lengthValue) ||
    (lengthValue as number) < minimum ||
    (lengthValue as number) > maximum
  ) {
    throw new Error(`${field} is outside configured bounds`);
  }
  const length = lengthValue as number;
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value as object);
  } catch {
    throw new Error(`${field} must be a plain bounded array`);
  }
  if (keys.length !== length + 1) {
    throw new Error(`${field} must not be sparse or have extra properties`);
  }
  const entries: unknown[] = new Array(length);
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new Error(`${field} must contain only own data properties`);
    }
    entries[index] = descriptor.value;
  }
  return entries;
}

function snapshotControlRecord(
  value: unknown,
  field: string,
): MembershipControlRecord {
  const record = exactOwnDataValues(
    value,
    [
      'version',
      'protocol',
      'groupId',
      'epoch',
      'operationId',
      'action',
      'actorId',
      'subjectId',
      'controlPayload',
      'signature',
    ],
    field,
    ['parentRecordId'],
    true,
  );
  const protocolValue = exactOwnDataValues(
    record.protocol,
    ['id', 'version'],
    `${field} protocol`,
    [],
    true,
  );
  return {
    version: record.version as number,
    protocol: {
      id: protocolValue.id as string,
      version: protocolValue.version as number,
    },
    groupId: copyControlRecordBytes(
      record.groupId,
      `${field} groupId`,
      1,
      MAX_GROUP_ID_BYTES,
    ),
    epoch: record.epoch as bigint,
    parentRecordId:
      record.parentRecordId === undefined
        ? undefined
        : copyControlRecordBytes(
            record.parentRecordId,
            `${field} parentRecordId`,
            FIXED_ID_LENGTH,
            FIXED_ID_LENGTH,
          ),
    operationId: copyControlRecordBytes(
      record.operationId,
      `${field} operationId`,
      FIXED_ID_LENGTH,
      FIXED_ID_LENGTH,
    ),
    action: record.action as MembershipControlAction,
    actorId: copyControlRecordBytes(
      record.actorId,
      `${field} actorId`,
      1,
      MAX_IDENTITY_BYTES,
    ),
    subjectId: copyControlRecordBytes(
      record.subjectId,
      `${field} subjectId`,
      1,
      MAX_IDENTITY_BYTES,
    ),
    controlPayload: copyControlRecordBytes(
      record.controlPayload,
      `${field} controlPayload`,
      1,
      MAX_CONTROL_PAYLOAD_BYTES,
    ),
    signature: copyControlRecordBytes(
      record.signature,
      `${field} signature`,
      1,
      MAX_CONTROL_SIGNATURE_BYTES,
    ),
  };
}

function exactOwnDataValues(
  value: unknown,
  fields: ReadonlyArray<string>,
  label: string,
  optionalFields: ReadonlyArray<string> = [],
  allowUnknown = false,
): Record<string, unknown> {
  if (value === null || typeof value !== 'object') {
    throw new Error(`${label} must be a plain object`);
  }
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    throw new Error(`${label} must be a plain object`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  let descriptors: PropertyDescriptorMap;
  if (allowUnknown) {
    descriptors = {};
    for (const field of [...fields, ...optionalFields]) {
      let descriptor: PropertyDescriptor | undefined;
      try {
        descriptor = Object.getOwnPropertyDescriptor(value, field);
      } catch {
        throw new Error(`${label} must contain only own data properties`);
      }
      if (descriptor !== undefined) descriptors[field] = descriptor;
    }
  } else {
    try {
      descriptors = Object.getOwnPropertyDescriptors(value);
    } catch {
      throw new Error(`${label} must contain only own data properties`);
    }
    const keys = Reflect.ownKeys(descriptors);
    const expected = new Set([...fields, ...optionalFields]);
    if (
      keys.length < fields.length ||
      keys.length > expected.size ||
      keys.some((key) => typeof key !== 'string' || !expected.has(key))
    ) {
      throw new Error(`${label} has unexpected properties`);
    }
  }
  const result: Record<string, unknown> = {};
  for (const field of [...fields, ...optionalFields]) {
    const descriptor = descriptors[field];
    if (descriptor === undefined) {
      if (optionalFields.includes(field)) continue;
      throw new Error(`${label} is missing ${field}`);
    }
    if (!descriptor.enumerable || !('value' in descriptor)) {
      throw new Error(`${label} must contain only own data properties`);
    }
    result[field] = descriptor.value;
  }
  return result;
}

function copyControlRecordBytes(
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
    length = Reflect.apply(typedArrayByteLengthGetter, value, []) as number;
    byteOffset = Reflect.apply(
      typedArrayByteOffsetGetter,
      value,
      [],
    ) as number;
    buffer = Reflect.apply(
      typedArrayBufferGetter,
      value,
      [],
    ) as ArrayBufferLike;
    tag = Reflect.apply(typedArrayTagGetter, value, []);
  } catch {
    throw new Error(`${field} must be a Uint8Array`);
  }
  let isShared = false;
  if (sharedArrayBufferByteLengthGetter !== undefined) {
    try {
      Reflect.apply(sharedArrayBufferByteLengthGetter, buffer, []);
      isShared = true;
    } catch {
      isShared = false;
    }
  }
  if (
    tag !== 'Uint8Array' ||
    isShared ||
    !Number.isSafeInteger(length) ||
    length < minimum ||
    length > maximum
  ) {
    throw new Error(`${field} must be a bounded unshared Uint8Array`);
  }
  try {
    const stableView = new Uint8Array(buffer, byteOffset, length);
    const out = new Uint8Array(length);
    Reflect.apply(uint8ArraySet, out, [stableView]);
    return out;
  } catch {
    throw new Error(`${field} must be a readable Uint8Array`);
  }
}

function cloneCreateGroupInput(input: CreateGroupInput): CreateGroupInput {
  const snapshot = exactOwnDataValues(
    input,
    ['groupId', 'creatorMemberId', 'credential'],
    'create-group input',
    ['authenticatedData'],
    true,
  );
  const groupId = copyControlRecordBytes(
    snapshot.groupId,
    'create-group groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  const creatorMemberId = copyControlRecordBytes(
    snapshot.creatorMemberId,
    'create-group creatorMemberId',
    1,
    MAX_IDENTITY_BYTES,
  );
  const credential = copyControlRecordBytes(
    snapshot.credential,
    'create-group credential',
    1,
    MAX_PROTOCOL_PAYLOAD_BYTES,
  );
  const authenticatedData =
    snapshot.authenticatedData === undefined
      ? undefined
      : copyControlRecordBytes(
          snapshot.authenticatedData,
          'create-group authenticatedData',
          0,
          MAX_PROTOCOL_PAYLOAD_BYTES,
        );
  return {
    groupId,
    creatorMemberId,
    credential,
    authenticatedData,
  };
}

function cloneBootstrapControlInput(
  input: GroupSecurityBootstrapControlInput,
): GroupSecurityBootstrapControlInput {
  const snapshot = exactOwnDataValues(
    input,
    ['operationId', 'subjectId'],
    'bootstrap control',
    [],
    true,
  );
  return {
    operationId: copyControlRecordBytes(
      snapshot.operationId,
      'bootstrap control operationId',
      FIXED_ID_LENGTH,
      FIXED_ID_LENGTH,
    ),
    subjectId: copyControlRecordBytes(
      snapshot.subjectId,
      'bootstrap control subjectId',
      1,
      MAX_IDENTITY_BYTES,
    ),
  };
}

function cloneCreateGroupCommitInput(
  input: CreateGroupCommitInput,
  storeKey: GroupStateStoreKey,
): CreateGroupCommitInput {
  const inputSnapshot = exactOwnDataValues(
    input,
    ['changes'],
    'create-commit input',
    ['authenticatedData'],
    true,
  );
  let changes: unknown[];
  try {
    changes = snapshotExactArray(
      inputSnapshot.changes,
      'create-commit changes',
      1,
      1,
    );
  } catch (error) {
    fail(
      'control-mismatch',
      'create-commit input must contain exactly one change',
      error,
    );
  }
  const changeSnapshot = exactOwnDataValues(
    changes[0],
    ['kind', 'memberId'],
    'create-commit change',
    ['keyPackage'],
    true,
  );
  const kind = changeSnapshot.kind;
  if (kind !== 'add' && kind !== 'remove' && kind !== 'update') {
    fail('control-mismatch', 'create-commit change has an invalid kind');
  }
  const memberId = copyControlRecordBytes(
    changeSnapshot.memberId,
    'requested memberId',
    1,
    MAX_IDENTITY_BYTES,
  );
  const authenticatedData =
    inputSnapshot.authenticatedData === undefined
      ? undefined
      : copyControlRecordBytes(
          inputSnapshot.authenticatedData,
          'create-commit authenticatedData',
          0,
          MAX_PROTOCOL_PAYLOAD_BYTES,
        );
  let keyPackage: GroupKeyPackage | undefined;
  if (kind !== 'remove') {
    const keyPackageSnapshot = exactOwnDataValues(
      changeSnapshot.keyPackage,
      ['protocol', 'groupId', 'reference', 'payload'],
      'requested keyPackage',
      [],
      true,
    );
    const protocolSnapshot = exactOwnDataValues(
      keyPackageSnapshot.protocol,
      ['id', 'version'],
      'requested keyPackage protocol',
      [],
      true,
    );
    keyPackage = {
      protocol: {
        id: protocolSnapshot.id as string,
        version: protocolSnapshot.version as number,
      },
      groupId: copyControlRecordBytes(
        keyPackageSnapshot.groupId,
        'keyPackage.groupId',
        1,
        MAX_GROUP_ID_BYTES,
      ),
      reference: copyControlRecordBytes(
        keyPackageSnapshot.reference,
        'keyPackage.reference',
        1,
        MAX_IDENTITY_BYTES,
      ),
      payload: copyControlRecordBytes(
        keyPackageSnapshot.payload,
        'keyPackage.payload',
        1,
        MAX_PROTOCOL_PAYLOAD_BYTES,
      ),
    };
    validateKeyPackage(keyPackage, storeKey);
  }
  return {
    changes: [
      kind === 'remove'
        ? {
            kind: 'remove',
            memberId,
          }
        : {
            kind,
            memberId,
            keyPackage: keyPackage!,
          },
    ],
    authenticatedData,
  };
}

function validateProviderMembershipAgainstControl(
  delta: AppliedGroupMembershipDelta,
  control: MembershipControlRecord,
  welcomes: ReadonlyArray<GroupWelcome>,
): void {
  const applied = requireSingleAppliedMembershipChange(delta);
  if (
    control.action === 'create' ||
    applied.kind !== control.action ||
    !equalBytes(applied.memberId, control.subjectId)
  ) {
    fail(
      'control-mismatch',
      'provider-applied membership change differs from signed action/subject',
    );
  }
  validateWelcomeRecipients(applied, welcomes);
}

function requireSingleAppliedMembershipChange(
  delta: AppliedGroupMembershipDelta,
): AppliedGroupMembershipChange {
  try {
    canonicalAppliedGroupMembershipDelta(delta);
  } catch (error) {
    fail('control-mismatch', 'provider returned an invalid membership delta', error);
  }
  if (delta.changes.length !== 1) {
    fail(
      'control-mismatch',
      'provider must report exactly one applied membership change',
    );
  }
  return delta.changes[0];
}

function validateWelcomeRecipients(
  applied: AppliedGroupMembershipChange,
  welcomes: ReadonlyArray<GroupWelcome>,
): void {
  if (applied.kind === 'add') {
    if (
      welcomes.length !== 1 ||
      !equalBytes(
        welcomes[0].recipientKeyPackageRef,
        applied.keyPackageRef,
      )
    ) {
      fail(
        'control-mismatch',
        'an add must produce exactly one Welcome for its applied key package',
      );
    }
  } else if (welcomes.length !== 0) {
    fail(
      'control-mismatch',
      'remove/update transitions must not produce Welcomes',
    );
  }
}

function validateKeyPackage(
  keyPackage: GroupKeyPackage,
  storeKey: GroupStateStoreKey,
): void {
  if (
    keyPackage === null ||
    typeof keyPackage !== 'object' ||
    !sameProtocol(keyPackage.protocol, storeKey.protocol)
  ) {
    fail('protocol-mismatch', 'key package protocol does not match group');
  }
  validateBytes(
    keyPackage.groupId,
    'keyPackage.groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  if (!equalBytes(keyPackage.groupId, storeKey.groupId)) {
    fail('group-mismatch', 'key package is bound to a different group');
  }
  validateBytes(
    keyPackage.reference,
    'keyPackage.reference',
    1,
    MAX_IDENTITY_BYTES,
  );
  validateBytes(
    keyPackage.payload,
    'keyPackage.payload',
    1,
    MAX_PROTOCOL_PAYLOAD_BYTES,
  );
}

function cloneKeyPackage(keyPackage: GroupKeyPackage): GroupKeyPackage {
  const raw = exactOwnDataValues(
    keyPackage,
    ['protocol', 'groupId', 'reference', 'payload'],
    'KeyPackage',
    [],
    true,
  );
  const rawProtocol = exactOwnDataValues(
    raw.protocol,
    ['id', 'version'],
    'KeyPackage protocol',
    [],
    true,
  );
  const snapshot: GroupKeyPackage = {
    protocol: {
      id: rawProtocol.id as string,
      version: rawProtocol.version as number,
    },
    groupId: copyControlRecordBytes(
      raw.groupId,
      'KeyPackage groupId',
      1,
      MAX_GROUP_ID_BYTES,
    ),
    reference: copyControlRecordBytes(
      raw.reference,
      'KeyPackage reference',
      1,
      MAX_IDENTITY_BYTES,
    ),
    payload: copyControlRecordBytes(
      raw.payload,
      'KeyPackage payload',
      1,
      MAX_PROTOCOL_PAYLOAD_BYTES,
    ),
  };
  validateProtocol(snapshot.protocol);
  validateBytes(
    snapshot.groupId,
    'KeyPackage groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  validateBytes(
    snapshot.reference,
    'KeyPackage reference',
    1,
    MAX_IDENTITY_BYTES,
  );
  validateBytes(
    snapshot.payload,
    'KeyPackage payload',
    1,
    MAX_PROTOCOL_PAYLOAD_BYTES,
  );
  return snapshot;
}

function sameKeyPackage(
  left: GroupKeyPackage,
  right: GroupKeyPackage,
): boolean {
  return (
    sameProtocol(left.protocol, right.protocol) &&
    equalBytes(left.groupId, right.groupId) &&
    equalBytes(left.reference, right.reference) &&
    equalBytes(left.payload, right.payload)
  );
}

function snapshotEncryptedGroupState(
  state: EncryptedGroupState,
): EncryptedGroupState {
  if (!isEncryptedGroupState(state)) {
    fail('malformed-state', 'provider did not return encrypted group state');
  }
  try {
    return EncryptedGroupState.deserialize(state.serialize());
  } catch (error) {
    fail('malformed-state', 'encrypted provider state is malformed', error);
  }
}

function validateEncryptedKeyPackage(
  state: EncryptedKeyPackageState,
  expected: GroupKeyPackage | undefined,
  storeKey: GroupStateStoreKey,
): EncryptedKeyPackageState {
  if (!isEncryptedKeyPackageState(state)) {
    fail(
      'control-mismatch',
      'provider did not return encrypted KeyPackage state',
    );
  }
  let snapshot: EncryptedKeyPackageState;
  try {
    snapshot = EncryptedKeyPackageState.deserialize(state.serialize());
  } catch (error) {
    fail(
      'control-mismatch',
      'encrypted KeyPackage state is malformed',
      error,
    );
  }
  validateKeyPackage(snapshot.keyPackage, storeKey);
  if (
    expected !== undefined &&
    !sameKeyPackage(snapshot.keyPackage, expected)
  ) {
    fail(
      'control-mismatch',
      'encrypted KeyPackage state does not match its public package',
    );
  }
  return snapshot;
}

function validateCommit(commit: GroupSecurityCommit): void {
  if (commit === null || typeof commit !== 'object') {
    throw new Error('group commit must be an object');
  }
  validateProtocol(commit.protocol);
  validateBytes(commit.groupId, 'commit.groupId', 1, MAX_GROUP_ID_BYTES);
  validateU64(commit.priorEpoch, 'commit.priorEpoch');
  validateU64(commit.epoch, 'commit.epoch');
  validateBytes(
    commit.payload,
    'commit.payload',
    1,
    MAX_PROTOCOL_PAYLOAD_BYTES,
  );
}

function validatePublicState(state: GroupSecurityPublicState): void {
  if (state === null || typeof state !== 'object') {
    throw new Error('group public state must be an object');
  }
  validateProtocol(state.protocol);
  validateBytes(state.groupId, 'state.groupId', 1, MAX_GROUP_ID_BYTES);
  validateU64(state.epoch, 'state.epoch');
  validateBytes(state.confirmedTranscriptHash, 'transcript hash', 1, 128);
  validateBytes(state.treeHash, 'tree hash', 1, 128);
}

function validateWelcomes(
  welcomes: ReadonlyArray<GroupWelcome>,
  commit: GroupSecurityCommit,
): GroupWelcome[] {
  const values = snapshotExactArray(
    welcomes,
    'Welcome list',
    0,
    MAX_WELCOMES,
  );
  const snapshots: GroupWelcome[] = [];
  let canonicalLength = WELCOME_SET_DOMAIN.byteLength + 2;
  for (let index = 0; index < values.length; index++) {
    const welcome = snapshotWelcome(values[index], `Welcome ${index}`);
    if (
      !sameProtocol(welcome.protocol, commit.protocol) ||
      !equalBytes(welcome.groupId, commit.groupId) ||
      welcome.epoch !== commit.epoch
    ) {
      throw new Error('Welcome metadata does not match commit');
    }
    validateBytes(
      welcome.recipientKeyPackageRef,
      'recipientKeyPackageRef',
      1,
      MAX_IDENTITY_BYTES,
    );
    validateBytes(
      welcome.payload,
      'welcome payload',
      1,
      MAX_PROTOCOL_PAYLOAD_BYTES,
    );
    canonicalLength +=
      2 +
      new TextEncoder().encode(welcome.protocol.id).byteLength +
      2 +
      2 +
      welcome.groupId.byteLength +
      8 +
      2 +
      welcome.recipientKeyPackageRef.byteLength +
      4 +
      welcome.payload.byteLength;
    if (canonicalLength > MAX_CANONICAL_WELCOME_SET_BYTES) {
      throw new Error('canonical Welcome set exceeds its size limit');
    }
    snapshots.push(welcome);
  }
  return snapshots;
}

function snapshotWelcome(value: unknown, label: string): GroupWelcome {
  const raw = exactOwnDataValues(
    value,
    ['protocol', 'groupId', 'epoch', 'recipientKeyPackageRef', 'payload'],
    label,
  );
  const rawProtocol = exactOwnDataValues(
    raw.protocol,
    ['id', 'version'],
    `${label} protocol`,
  );
  const welcome: GroupWelcome = {
    protocol: {
      id: rawProtocol.id as string,
      version: rawProtocol.version as number,
    },
    groupId: copyControlRecordBytes(
      raw.groupId,
      `${label} groupId`,
      1,
      MAX_GROUP_ID_BYTES,
    ),
    epoch: raw.epoch as bigint,
    recipientKeyPackageRef: copyControlRecordBytes(
      raw.recipientKeyPackageRef,
      `${label} recipientKeyPackageRef`,
      1,
      MAX_IDENTITY_BYTES,
    ),
    payload: copyControlRecordBytes(
      raw.payload,
      `${label} payload`,
      1,
      MAX_PROTOCOL_PAYLOAD_BYTES,
    ),
  };
  validateProtocol(welcome.protocol);
  validateU64(welcome.epoch, `${label} epoch`);
  return welcome;
}

async function welcomeSetHash(
  welcomes: ReadonlyArray<GroupWelcome>,
  commit: GroupSecurityCommit,
): Promise<Uint8Array> {
  const snapshots = validateWelcomes(welcomes, commit);
  const parts: Uint8Array[] = [WELCOME_SET_DOMAIN, u16(snapshots.length)];
  for (const welcome of snapshots) {
    parts.push(
      bytes16(new TextEncoder().encode(welcome.protocol.id)),
      u16(welcome.protocol.version),
      bytes16(welcome.groupId),
      u64(welcome.epoch),
      bytes16(welcome.recipientKeyPackageRef),
      bytes32(welcome.payload),
    );
  }
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', concat(parts) as BufferSource),
  );
}

async function pendingKeyPackageRequestCommitment(
  input: CreatePendingKeyPackageInput,
  storeKey: GroupStateStoreKey,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [
    KEY_PACKAGE_REQUEST_DOMAIN,
    input.operationId,
    bytes16(new TextEncoder().encode(storeKey.protocol.id)),
    u16(storeKey.protocol.version),
    bytes16(input.groupId),
    bytes16(input.memberId),
    bytes32(input.credential),
  ];
  if (input.extensions === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    const extensions = [...input.extensions].sort(
      ([left], [right]) => left - right,
    );
    parts.push(new Uint8Array([1]), u16(extensions.length));
    for (const [type, value] of extensions) {
      parts.push(u16(type), bytes32(value));
    }
  }
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', concat(parts) as BufferSource),
  );
}

async function rollbackForkPoison(
  evidence: GroupStateForkEvidence,
): Promise<GroupSecurityRollbackForkPoison> {
  const branches = [
    {
      recordId: new Uint8Array(evidence.firstRecordId),
      controlRecord: new Uint8Array(evidence.firstControlRecord),
    },
    {
      recordId: new Uint8Array(evidence.secondRecordId),
      controlRecord: new Uint8Array(evidence.secondControlRecord),
    },
  ].sort((left, right) =>
    toHex(left.recordId).localeCompare(toHex(right.recordId)),
  );
  const evidenceHash = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      concat([
        FORK_POISON_DOMAIN,
        u64(evidence.epoch),
        new Uint8Array(evidence.parentRecordId),
        branches[0].recordId,
        bytes32(branches[0].controlRecord),
        branches[1].recordId,
        bytes32(branches[1].controlRecord),
      ]) as BufferSource,
    ),
  );
  return {
    epoch: evidence.epoch,
    parentRecordId: new Uint8Array(evidence.parentRecordId),
    firstRecordId: branches[0].recordId,
    secondRecordId: branches[1].recordId,
    evidenceHash,
  };
}

async function rollbackAmbiguityPoison(
  candidate: MembershipControlRecord,
  candidateRecordId: Uint8Array,
  base: GroupSecurityRollbackAnchorValue,
): Promise<GroupSecurityRollbackForkPoison> {
  if (
    candidate.parentRecordId === undefined ||
    !equalBytes(candidate.parentRecordId, base.controlHead)
  ) {
    throw new Error(
      'authenticated ambiguity candidate is not a child of the observed base anchor',
    );
  }
  const serialized = serializeMembershipControlRecord(candidate);
  const observationHash = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      concat([
        FORK_AMBIGUITY_DOMAIN,
        u64(candidate.epoch),
        u64(BigInt(base.revision)),
        base.controlHead,
        base.storeCommitment,
        candidate.parentRecordId,
        candidateRecordId,
        bytes32(serialized),
      ]) as BufferSource,
    ),
  );
  return {
    reason: 'unreconciled-authenticated-candidate',
    epoch: candidate.epoch,
    baseRevision: base.revision,
    baseControlHead: new Uint8Array(base.controlHead),
    baseStoreCommitment: new Uint8Array(base.storeCommitment),
    candidateParentRecordId: new Uint8Array(candidate.parentRecordId),
    candidateRecordId: new Uint8Array(candidateRecordId),
    observationHash,
  };
}

async function rollbackFirstAnchorAmbiguityPoison(
  candidate: MembershipControlRecord,
  candidateRecordId: Uint8Array,
  initial: GroupSecurityRollbackAnchorValue,
): Promise<GroupSecurityRollbackForkPoison> {
  if (
    initial.forkPoison !== undefined ||
    initial.epoch !== candidate.epoch ||
    !equalBytes(initial.controlHead, candidateRecordId)
  ) {
    throw new Error(
      'first-anchor ambiguity candidate does not match its initialization anchor',
    );
  }
  const serialized = serializeMembershipControlRecord(candidate);
  const observationHash = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      concat([
        FIRST_ANCHOR_AMBIGUITY_DOMAIN,
        u64(candidate.epoch),
        u64(BigInt(initial.revision)),
        initial.controlHead,
        initial.storeCommitment,
        candidateRecordId,
        bytes32(serialized),
      ]) as BufferSource,
    ),
  );
  return {
    reason: 'unreconciled-first-anchor-candidate',
    epoch: candidate.epoch,
    candidateRevision: initial.revision,
    candidateControlHead: new Uint8Array(initial.controlHead),
    candidateStoreCommitment: new Uint8Array(initial.storeCommitment),
    observationHash,
  };
}

function makeForkEvidence(
  acceptedRecord: MembershipControlRecord,
  acceptedRecordId: Uint8Array,
  conflictingRecord: MembershipControlRecord,
  conflictingRecordId: Uint8Array,
): GroupStateForkEvidence {
  const genesisFork =
    acceptedRecord.action === 'create' &&
    conflictingRecord.action === 'create' &&
    acceptedRecord.epoch === 0n &&
    conflictingRecord.epoch === 0n &&
    acceptedRecord.parentRecordId === undefined &&
    conflictingRecord.parentRecordId === undefined;
  const ordinaryFork =
    acceptedRecord.action !== 'create' &&
    conflictingRecord.action !== 'create' &&
    acceptedRecord.parentRecordId !== undefined &&
    conflictingRecord.parentRecordId !== undefined &&
    equalBytes(
      acceptedRecord.parentRecordId,
      conflictingRecord.parentRecordId,
    );
  if (
    (!genesisFork && !ordinaryFork) ||
    acceptedRecord.epoch !== conflictingRecord.epoch ||
    equalBytes(acceptedRecordId, conflictingRecordId)
  ) {
    fail('malformed-state', 'invalid same-parent fork evidence');
  }
  const parentRecordId = genesisFork
    ? GENESIS_FORK_PARENT_ID
    : conflictingRecord.parentRecordId!;
  return {
    epoch: conflictingRecord.epoch,
    parentRecordId: new Uint8Array(parentRecordId),
    firstRecordId: new Uint8Array(acceptedRecordId),
    firstControlRecord: serializeMembershipControlRecord(acceptedRecord),
    secondRecordId: new Uint8Array(conflictingRecordId),
    secondControlRecord: serializeMembershipControlRecord(conflictingRecord),
  };
}

function validateReplayEntry(entry: GroupStateReplayEntry): void {
  validateFixedId(entry.recordId, 'replay recordId');
  if (entry.operationId === undefined) {
    fail('malformed-state', 'replay operationId is required');
  }
  validateFixedId(entry.operationId, 'replay operationId');
  validateU64(entry.epoch, 'replay epoch');
  validateBytes(
    entry.controlRecord,
    'replay controlRecord',
    1,
    4 * 1024 * 1024,
  );
}

function validateOutboxEntry(entry: GroupStateOutboxEntry): void {
  if (entry === null || typeof entry !== 'object') {
    fail('malformed-state', 'outbox entry must be an object');
  }
  validateFixedId(entry.id, 'outbox id');
  validateU64(entry.epoch, 'outbox epoch');
  if (
    typeof entry.kind !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(entry.kind) ||
    !Number.isSafeInteger(entry.createdAt) ||
    entry.createdAt < 0
  ) {
    fail('malformed-state', 'outbox metadata is invalid');
  }
  validateBytes(
    entry.payload,
    'outbox payload',
    1,
    MAX_OUTBOX_PAYLOAD_BYTES,
  );
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

function validateIdentity(value: Uint8Array, field: string): void {
  validateBytes(value, field, 1, MAX_IDENTITY_BYTES);
}

function validateFixedId(value: Uint8Array, field: string): void {
  validateBytes(value, field, FIXED_ID_LENGTH, FIXED_ID_LENGTH);
}

function validateBytes(
  value: Uint8Array,
  field: string,
  minimum: number,
  maximum: number,
): void {
  let length: unknown;
  let buffer: unknown;
  let tag: unknown;
  try {
    length = Reflect.apply(typedArrayByteLengthGetter, value, []);
    buffer = Reflect.apply(typedArrayBufferGetter, value, []);
    tag = Reflect.apply(typedArrayTagGetter, value, []);
  } catch {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  let isShared = false;
  if (sharedArrayBufferByteLengthGetter !== undefined) {
    try {
      Reflect.apply(sharedArrayBufferByteLengthGetter, buffer, []);
      isShared = true;
    } catch {
      isShared = false;
    }
  }
  if (
    tag !== 'Uint8Array' ||
    typeof length !== 'number' ||
    !Number.isSafeInteger(length) ||
    length < minimum ||
    length > maximum ||
    isShared
  ) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
}

function validateU64(value: bigint, field: string): void {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
}

function assertPublicStateMatchesKey(
  state: GroupSecurityPublicState,
  key: GroupStateStoreKey,
): void {
  const snapshot = clonePublicState(state);
  if (!sameProtocol(snapshot.protocol, key.protocol)) {
    fail('protocol-mismatch', 'provider state protocol does not match group');
  }
  if (!equalBytes(snapshot.groupId, key.groupId)) {
    fail('group-mismatch', 'provider state group does not match');
  }
}

function assertSamePublicStateShape(
  state: GroupSecurityPublicState,
  protocol: GroupSecurityProtocol,
  groupId: Uint8Array,
): void {
  const snapshot = clonePublicState(state);
  if (!sameProtocol(snapshot.protocol, protocol)) {
    fail('protocol-mismatch', 'provider state protocol mismatch');
  }
  if (!equalBytes(snapshot.groupId, groupId)) {
    fail('group-mismatch', 'provider state group mismatch');
  }
}

function assertSamePublicState(
  actual: GroupSecurityPublicState,
  expected: GroupSecurityPublicState,
): void {
  const actualSnapshot = clonePublicState(actual);
  const expectedSnapshot = clonePublicState(expected);
  if (
    !sameProtocol(actualSnapshot.protocol, expectedSnapshot.protocol) ||
    !equalBytes(actualSnapshot.groupId, expectedSnapshot.groupId) ||
    actualSnapshot.epoch !== expectedSnapshot.epoch ||
    !equalBytes(
      actualSnapshot.confirmedTranscriptHash,
      expectedSnapshot.confirmedTranscriptHash,
    ) ||
    !equalBytes(actualSnapshot.treeHash, expectedSnapshot.treeHash)
  ) {
    fail('malformed-state', 'provider/encrypted public state mismatch');
  }
}

function assertEnvelopeMatchesKey(
  state: EncryptedGroupState,
  key: GroupStateStoreKey,
): void {
  assertPublicStateMatchesKey(state.state, key);
}

function incrementEpoch(epoch: bigint): bigint {
  validateU64(epoch, 'epoch');
  if (epoch === MAX_U64) fail('epoch-mismatch', 'group epoch is exhausted');
  return epoch + 1n;
}

function clonePublicState(
  state: GroupSecurityPublicState,
): GroupSecurityPublicState {
  const raw = exactOwnDataValues(
    state,
    [
      'protocol',
      'groupId',
      'epoch',
      'confirmedTranscriptHash',
      'treeHash',
    ],
    'group public state',
    [],
    true,
  );
  const rawProtocol = exactOwnDataValues(
    raw.protocol,
    ['id', 'version'],
    'group public state protocol',
    [],
    true,
  );
  const snapshot: GroupSecurityPublicState = {
    protocol: {
      id: rawProtocol.id as string,
      version: rawProtocol.version as number,
    },
    groupId: copyControlRecordBytes(
      raw.groupId,
      'group public state groupId',
      1,
      MAX_GROUP_ID_BYTES,
    ),
    epoch: raw.epoch as bigint,
    confirmedTranscriptHash: copyControlRecordBytes(
      raw.confirmedTranscriptHash,
      'group public state confirmedTranscriptHash',
      1,
      128,
    ),
    treeHash: copyControlRecordBytes(
      raw.treeHash,
      'group public state treeHash',
      1,
      128,
    ),
  };
  validatePublicState(snapshot);
  return snapshot;
}

function cloneControlRecord(
  record: MembershipControlRecord,
): MembershipControlRecord {
  return deserializeMembershipControlRecord(
    serializeMembershipControlRecord(record),
  );
}

function cloneCommit(commit: GroupSecurityCommit): GroupSecurityCommit {
  const raw = exactOwnDataValues(
    commit,
    ['protocol', 'groupId', 'priorEpoch', 'epoch', 'payload'],
    'group commit',
    [],
    true,
  );
  const rawProtocol = exactOwnDataValues(
    raw.protocol,
    ['id', 'version'],
    'group commit protocol',
    [],
    true,
  );
  const snapshot: GroupSecurityCommit = {
    protocol: {
      id: rawProtocol.id as string,
      version: rawProtocol.version as number,
    },
    groupId: copyControlRecordBytes(
      raw.groupId,
      'group commit groupId',
      1,
      MAX_GROUP_ID_BYTES,
    ),
    priorEpoch: raw.priorEpoch as bigint,
    epoch: raw.epoch as bigint,
    payload: copyControlRecordBytes(
      raw.payload,
      'group commit payload',
      1,
      MAX_PROTOCOL_PAYLOAD_BYTES,
    ),
  };
  validateCommit(snapshot);
  return snapshot;
}

function cloneGroupSecurityCommitResult(
  result: GroupSecurityCommitResult,
): GroupSecurityCommitResult {
  const raw = exactOwnDataValues(
    result,
    ['commit', 'welcomes', 'state', 'appliedMembership'],
    'provider commit result',
    [],
    true,
  );
  const commit = cloneCommit(raw.commit as GroupSecurityCommit);
  const state = clonePublicState(raw.state as GroupSecurityPublicState);
  const welcomes = validateWelcomes(
    raw.welcomes as ReadonlyArray<GroupWelcome>,
    commit,
  );
  const appliedMembership = cloneAppliedGroupMembershipDelta(
    raw.appliedMembership as AppliedGroupMembershipDelta,
  );
  return {
    commit,
    welcomes,
    state,
    appliedMembership,
  };
}

function cloneGroupSecurityApplyResult(
  result: GroupSecurityApplyResult,
): GroupSecurityApplyResult {
  const raw = exactOwnDataValues(
    result,
    ['status', 'state', 'appliedMembership'],
    'provider apply result',
    [],
    true,
  );
  if (raw.status !== 'applied' && raw.status !== 'duplicate') {
    throw new Error('provider apply result is invalid');
  }
  const state = clonePublicState(raw.state as GroupSecurityPublicState);
  const appliedMembership = cloneAppliedGroupMembershipDelta(
    raw.appliedMembership as AppliedGroupMembershipDelta,
  );
  return {
    status: raw.status,
    state,
    appliedMembership,
  };
}

function cloneAppliedGroupMembershipDelta(
  delta: AppliedGroupMembershipDelta,
): AppliedGroupMembershipDelta {
  const rawDelta = exactOwnDataValues(
    delta,
    ['changes'],
    'applied membership delta',
  );
  const rawChanges = snapshotExactArray(
    rawDelta.changes,
    'applied membership changes',
    1,
    MAX_MEMBERSHIP_CHANGES,
  );
  const changes: AppliedGroupMembershipChange[] = [];
  for (let index = 0; index < rawChanges.length; index++) {
    const label = `applied membership change ${index}`;
    const raw = exactOwnDataValues(
      rawChanges[index],
      ['kind', 'memberId'],
      label,
      ['keyPackageRef'],
    );
    const hasKeyPackageRef = Object.prototype.hasOwnProperty.call(
      raw,
      'keyPackageRef',
    );
    const memberId = copyControlRecordBytes(
      raw.memberId,
      `${label} memberId`,
      1,
      MAX_IDENTITY_BYTES,
    );
    if (raw.kind === 'remove') {
      if (hasKeyPackageRef) {
        throw new Error(`${label} has unexpected properties`);
      }
      changes.push({ kind: 'remove', memberId });
      continue;
    }
    if (
      (raw.kind !== 'add' && raw.kind !== 'update') ||
      !hasKeyPackageRef
    ) {
      throw new Error(`${label} has an invalid kind or shape`);
    }
    changes.push({
      kind: raw.kind,
      memberId,
      keyPackageRef: copyControlRecordBytes(
        raw.keyPackageRef,
        `${label} keyPackageRef`,
        1,
        MAX_IDENTITY_BYTES,
      ),
    });
  }
  const snapshot: AppliedGroupMembershipDelta = { changes };
  canonicalAppliedGroupMembershipDelta(snapshot);
  return snapshot;
}

function cloneWelcome(welcome: GroupWelcome): GroupWelcome {
  return snapshotWelcome(welcome, 'Welcome');
}

function cloneDelivery(delivery: GroupSecurityDelivery): GroupSecurityDelivery {
  const raw = exactOwnDataValues(
    delivery,
    ['controlRecord', 'welcomes'],
    'group-security delivery',
    ['commit'],
  );
  const welcomeValues = snapshotExactArray(
    raw.welcomes,
    'group-security delivery Welcomes',
    0,
    MAX_WELCOMES,
  );
  const welcomes: GroupWelcome[] = [];
  for (let index = 0; index < welcomeValues.length; index++) {
    welcomes.push(
      snapshotWelcome(
        welcomeValues[index],
        `group-security delivery Welcome ${index}`,
      ),
    );
  }
  return {
    controlRecord: snapshotControlRecord(
      raw.controlRecord,
      'group-security delivery control record',
    ),
    commit:
      raw.commit === undefined
        ? undefined
        : cloneCommit(raw.commit as GroupSecurityCommit),
    welcomes,
  };
}

function sameDelivery(
  a: GroupSecurityDelivery,
  b: GroupSecurityDelivery,
): boolean {
  const left = cloneDelivery(a);
  const right = cloneDelivery(b);
  if (
    !equalBytes(
      serializeMembershipControlRecord(left.controlRecord),
      serializeMembershipControlRecord(right.controlRecord),
    ) ||
    (left.commit === undefined) !== (right.commit === undefined) ||
    left.welcomes.length !== right.welcomes.length
  ) {
    return false;
  }
  if (left.commit !== undefined && right.commit !== undefined) {
    if (
      !sameProtocol(left.commit.protocol, right.commit.protocol) ||
      !equalBytes(left.commit.groupId, right.commit.groupId) ||
      left.commit.priorEpoch !== right.commit.priorEpoch ||
      left.commit.epoch !== right.commit.epoch ||
      !equalBytes(left.commit.payload, right.commit.payload)
    ) {
      return false;
    }
  }
  for (let index = 0; index < left.welcomes.length; index++) {
    const welcome = left.welcomes[index];
    const other = right.welcomes[index];
    if (
      !(
        sameProtocol(welcome.protocol, other.protocol) &&
        equalBytes(welcome.groupId, other.groupId) &&
        welcome.epoch === other.epoch &&
        equalBytes(
          welcome.recipientKeyPackageRef,
          other.recipientKeyPackageRef,
        ) &&
        equalBytes(welcome.payload, other.payload)
      )
    ) {
      return false;
    }
  }
  return true;
}

function cloneStoreKey(key: GroupStateStoreKey): GroupStateStoreKey {
  return {
    protocol: { ...key.protocol },
    groupId: new Uint8Array(key.groupId),
  };
}

function cloneReplayEntry(entry: GroupStateReplayEntry): GroupStateReplayEntry {
  return {
    recordId: new Uint8Array(entry.recordId),
    operationId:
      entry.operationId === undefined
        ? undefined
        : new Uint8Array(entry.operationId),
    epoch: entry.epoch,
    controlRecord: new Uint8Array(entry.controlRecord),
  };
}

function sameProtocol(
  a: GroupSecurityProtocol,
  b: GroupSecurityProtocol,
): boolean {
  return a.id === b.id && a.version === b.version;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let different = 0;
  for (let i = 0; i < a.byteLength; i++) different |= a[i] ^ b[i];
  return different === 0;
}

function optionalBytesEqual(
  first: Uint8Array | undefined,
  second: Uint8Array | undefined,
): boolean {
  return first === undefined || second === undefined
    ? first === second
    : equalBytes(first, second);
}

function compareReplayEntries(
  a: GroupStateReplayEntry,
  b: GroupStateReplayEntry,
): number {
  return a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0;
}

function compareOutboxEntries(
  a: GroupStateOutboxEntry,
  b: GroupStateOutboxEntry,
): number {
  if (a.epoch !== b.epoch) return a.epoch < b.epoch ? -1 : 1;
  if (a.createdAt !== b.createdAt) return a.createdAt - b.createdAt;
  return toHex(a.id).localeCompare(toHex(b.id));
}

function bytes16(value: Uint8Array): Uint8Array {
  return concat([u16(value.byteLength), value]);
}

function bytes32(value: Uint8Array): Uint8Array {
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
  validateU64(value, 'u64');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const out = new Uint8Array(
    parts.reduce((total, part) => total + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  let result = '';
  for (const value of bytes) result += value.toString(16).padStart(2, '0');
  return result;
}

function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('invalid fixed hex id');
  const out = new Uint8Array(FIXED_ID_LENGTH);
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

async function withProviderLifecycle<T>(
  provider: GroupSecurityProvider,
  claimOnSuccess: boolean,
  operation: () => Promise<T>,
): Promise<T> {
  const lifecycleIdentity = providerLifecycleIdentity(provider);
  const previous =
    providerLifecycleTails.get(lifecycleIdentity) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  providerLifecycleTails.set(
    lifecycleIdentity,
    previous.then(() => current),
  );
  await previous;
  try {
    if (permanentlyOwnedProviders.has(lifecycleIdentity)) {
      fail(
        'already-initialized',
        'group security provider is already owned or permanently retired',
      );
    }
    try {
      const result = await operation();
      if (claimOnSuccess) {
        permanentlyOwnedProviders.add(lifecycleIdentity);
      }
      return result;
    } catch (error) {
      if (
        error instanceof GroupSecurityCoordinatorError &&
        (error.code === 'rollback-unavailable' ||
          error.code === 'rollback-failed' ||
          error.code === 'poisoned')
      ) {
        permanentlyOwnedProviders.add(lifecycleIdentity);
      }
      throw error;
    }
  } finally {
    release();
  }
}

function providerLifecycleIdentity(provider: GroupSecurityProvider): object {
  let identity: unknown;
  try {
    identity = provider.lifecycleIdentity ?? provider;
  } catch (error) {
    fail(
      'malformed-state',
      'group security provider lifecycle identity is unavailable',
      error,
    );
  }
  if (
    (typeof identity !== 'object' || identity === null) &&
    typeof identity !== 'function'
  ) {
    fail(
      'malformed-state',
      'group security provider lifecycle identity must be an object',
    );
  }
  const stableIdentity = identity as object;
  const observed = observedProviderLifecycleIdentities.get(provider);
  if (observed !== undefined && observed !== stableIdentity) {
    fail(
      'malformed-state',
      'group security provider lifecycle identity changed',
    );
  }
  observedProviderLifecycleIdentities.set(provider, stableIdentity);
  return stableIdentity;
}

function fail(
  code: GroupSecurityCoordinatorFailure,
  message: string,
  cause?: unknown,
): never {
  throw new GroupSecurityCoordinatorError(code, message, { cause });
}

function normalizeFailure(value: unknown, fallback: string): Error {
  return value instanceof Error ? value : new Error(fallback);
}
