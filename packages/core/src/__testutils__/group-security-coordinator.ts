import {
GroupSecurityCoordinator,
GroupSecurityCoordinatorConfig,
GroupSecurityDelivery,
GroupSecurityJoinInvitation,
GroupSecurityOutboxCodec
} from '../group-security-coordinator.js';
import { createGroupSecurityDurableAcceptance } from '../group-security-durable-acceptance.js';
import {
AppliedGroupMembershipDelta,
CreateGroupCommitInput,
CreateGroupInput,
CreateKeyPackageInput,
EncryptedGroupState,
EncryptedKeyPackageState,
ExportGroupSecretInput,
GroupKeyPackage,
GroupSecurityApplyResult,
GroupSecurityCommit,
GroupSecurityCommitResult,
GroupSecurityCreateResult,
GroupSecurityProvider,
GroupSecurityPublicState,
GroupStateProtector,
GroupWelcome,
JoinGroupInput,
} from '../group-security-provider.js';
import {
DurableGroupSecurityRollbackAnchor,
GroupSecurityRollbackAnchorValue,
GroupSecurityRollbackForkPoison,
InMemoryGroupSecurityRollbackAnchor,
} from '../group-security-rollback-anchor.js';
import { groupSecurityStoreSnapshotCommitment } from '../group-security-store-commitment.js';
import {
DurableGroupStateStore,
GroupStateStoreKey,
GroupStateStoreSnapshot,
GroupStateStoreTransaction,
InMemoryGroupStateStore,
} from '../group-state-store.js';
import {
MembershipControlAuthorizationContext,
MembershipControlAuthorizer,
MembershipControlRecord,
MembershipControlSignatureVerifier,
MembershipControlSigner,
UnsignedMembershipControlRecord,
deserializeMembershipControlRecord,
membershipControlRecordId,
serializeMembershipControlRecord,
signMembershipControlRecord,
} from '../membership-control-record.js';
import { WebCryptoGroupStateProtector } from '../webcrypto-group-state-protector.js';

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export const protocol = { id: 'coordinator.contract.test', version: 1 };

export const groupId = new Uint8Array([0x10, 0x20, 0x30, 0x40]);

export const storeKey: GroupStateStoreKey = { protocol, groupId };

export const createGroupInput: CreateGroupInput = {
  groupId,
  creatorMemberId: id(0xa1),
  credential: id(0xa1),
};

export function id(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

export function publicState(
  epoch: bigint,
  selectedGroupId: Uint8Array = groupId,
): GroupSecurityPublicState {
  return {
    protocol,
    groupId: new Uint8Array(selectedGroupId),
    epoch,
    confirmedTranscriptHash: new Uint8Array(32).fill(
      Number((epoch + 0x31n) & 0xffn),
    ),
    treeHash: new Uint8Array(32).fill(Number((epoch + 0x71n) & 0xffn)),
  };
}

export function cloneState(
  state: GroupSecurityPublicState,
): GroupSecurityPublicState {
  return {
    protocol: { ...state.protocol },
    groupId: new Uint8Array(state.groupId),
    epoch: state.epoch,
    confirmedTranscriptHash: new Uint8Array(state.confirmedTranscriptHash),
    treeHash: new Uint8Array(state.treeHash),
  };
}

export function commitPayload(
  prior: bigint,
  epoch: bigint,
  appliedMembership: AppliedGroupMembershipDelta,
): Uint8Array {
  const [change] = appliedMembership.changes;
  return encoder.encode(
    JSON.stringify({
      prior: prior.toString(),
      epoch: epoch.toString(),
      kind: change.kind,
      memberId: toHex(change.memberId),
      keyPackageRef:
        change.kind === 'remove' ? undefined : toHex(change.keyPackageRef),
    }),
  );
}

export function deltaFromCommitPayload(
  payload: Uint8Array,
): AppliedGroupMembershipDelta {
  const decoded = JSON.parse(decoder.decode(payload)) as {
    kind: 'add' | 'remove' | 'update';
    memberId: string;
    keyPackageRef?: string;
  };
  const memberId = fromHex(decoded.memberId);
  if (decoded.kind === 'remove') {
    return { changes: [{ kind: 'remove', memberId }] };
  }
  if (decoded.keyPackageRef === undefined) {
    throw new Error('test commit lacks key-package reference');
  }
  return {
    changes: [
      {
        kind: decoded.kind,
        memberId,
        keyPackageRef: fromHex(decoded.keyPackageRef),
      },
    ],
  };
}

export function deltaFromInput(
  input: CreateGroupCommitInput,
): AppliedGroupMembershipDelta {
  const [change] = input.changes;
  if (change === undefined) throw new Error('test provider needs one change');
  if (change.kind === 'remove') {
    return {
      changes: [{ kind: 'remove', memberId: new Uint8Array(change.memberId) }],
    };
  }
  return {
    changes: [
      {
        kind: change.kind,
        memberId: new Uint8Array(change.memberId),
        keyPackageRef: new Uint8Array(change.keyPackage.reference),
      },
    ],
  };
}

export function cloneDelta(
  delta: AppliedGroupMembershipDelta,
): AppliedGroupMembershipDelta {
  return {
    changes: delta.changes.map((change) =>
      change.kind === 'remove'
        ? { kind: 'remove', memberId: new Uint8Array(change.memberId) }
        : {
            kind: change.kind,
            memberId: new Uint8Array(change.memberId),
            keyPackageRef: new Uint8Array(change.keyPackageRef),
          },
    ),
  };
}

export class ContractTestProvider implements GroupSecurityProvider {
  readonly protocol = protocol;
  createKeyPackageCalls = 0;
  hasActiveGroupCalls = 0;
  authenticateKeyPackageCalls = 0;
  authenticateKeyPackageRequestCalls = 0;
  exportKeyPackageCalls = 0;
  importKeyPackageCalls = 0;
  clearKeyPackageCalls = 0;
  joinGroupCalls = 0;
  createGroupCalls = 0;
  createCommitCalls = 0;
  applyCommitCalls = 0;
  importCalls = 0;
  exportStateCalls = 0;
  clearCalls = 0;
  failNextImportAfterMutation = false;
  failNextCreateCommitAfterRetainedCheckpointMutation = false;
  failStateExports = false;
  createGroupBarrier?: () => Promise<void>;
  createCommitBarrier?: () => Promise<void>;
  applyCommitBarrier?: () => Promise<void>;
  joinGroupBarrier?: () => Promise<void>;
  importEncryptedStateBarrier?: () => Promise<void>;
  authenticateKeyPackageRequestBarrier?: () => Promise<void>;
  getPublicStateOverrideOnce?: GroupSecurityPublicState;
  activeTransitions = 0;
  maxActiveTransitions = 0;
  createDeltaOverride?: AppliedGroupMembershipDelta;
  applyDeltaOverride?: AppliedGroupMembershipDelta;
  welcomeRecipientOverride?: Uint8Array;
  authenticatedMemberIdOverride?: Uint8Array;
  authenticatedRequestCommitmentOverride?: Uint8Array;
  authenticatedCreatorMemberIdOverride?: Uint8Array;
  importedStateOverrideAfterOpen?: GroupSecurityPublicState;
  lastExportedKeyPackageState?: EncryptedKeyPackageState;
  lastExportedGroupState?: EncryptedGroupState;
  private current?: GroupSecurityPublicState;
  private readonly keyPackages = new Map<string, GroupKeyPackage>();
  private readonly encryptedKeyPackages = new Map<
    string,
    Promise<EncryptedKeyPackageState>
  >();

  async hasActiveGroup(): Promise<boolean> {
    this.hasActiveGroupCalls += 1;
    return this.current !== undefined;
  }

  async createKeyPackage(
    input: CreateKeyPackageInput,
  ): Promise<GroupKeyPackage> {
    this.createKeyPackageCalls += 1;
    if (!equalBytes(input.credential, input.memberId)) {
      throw new Error(
        'test credential does not authenticate the requested member',
      );
    }
    if (input.requestCommitment.byteLength !== 32) {
      throw new Error('test request commitment is malformed');
    }
    let reference: Uint8Array;
    do {
      reference = crypto.getRandomValues(new Uint8Array(32));
    } while (this.keyPackages.has(toHex(reference)));
    const keyPackage = {
      protocol,
      groupId: new Uint8Array(input.groupId),
      reference,
      payload: (() => {
        const payload = new Uint8Array(64);
        payload.set(input.credential, 0);
        payload.set(input.requestCommitment, 32);
        return payload;
      })(),
    };
    this.keyPackages.set(
      toHex(keyPackage.reference),
      cloneKeyPackage(keyPackage),
    );
    return cloneKeyPackage(keyPackage);
  }

  async authenticateKeyPackageMember(
    keyPackage: GroupKeyPackage,
  ): Promise<Uint8Array> {
    this.authenticateKeyPackageCalls += 1;
    if (
      keyPackage.payload.byteLength !== 32 &&
      keyPackage.payload.byteLength !== 64
    ) {
      throw new Error('test KeyPackage credential is malformed');
    }
    return new Uint8Array(
      this.authenticatedMemberIdOverride ?? keyPackage.payload.subarray(0, 32),
    );
  }

  async authenticateKeyPackageRequestCommitment(
    keyPackage: GroupKeyPackage,
  ): Promise<Uint8Array> {
    this.authenticateKeyPackageRequestCalls += 1;
    await this.authenticateKeyPackageRequestBarrier?.();
    if (keyPackage.payload.byteLength !== 64) {
      throw new Error('test KeyPackage request binding is malformed');
    }
    return new Uint8Array(
      this.authenticatedRequestCommitmentOverride ??
        keyPackage.payload.subarray(32),
    );
  }

  async exportEncryptedKeyPackage(
    reference: Uint8Array,
    protector: GroupStateProtector,
  ): Promise<EncryptedKeyPackageState> {
    this.exportKeyPackageCalls += 1;
    const keyPackage = this.keyPackages.get(toHex(reference));
    if (keyPackage === undefined) throw new Error('unknown test KeyPackage');
    const encodedReference = toHex(reference);
    let pending = this.encryptedKeyPackages.get(encodedReference);
    if (pending === undefined) {
      pending = EncryptedKeyPackageState.seal(
        keyPackage,
        privateKeyPackageBytes(keyPackage),
        protector,
      );
      this.encryptedKeyPackages.set(encodedReference, pending);
    }
    const exported = EncryptedKeyPackageState.deserialize(
      (await pending).serialize(),
    );
    this.lastExportedKeyPackageState = exported;
    return exported;
  }

  async importEncryptedKeyPackage(
    envelope: EncryptedKeyPackageState,
    protector: GroupStateProtector,
  ): Promise<GroupKeyPackage> {
    this.importKeyPackageCalls += 1;
    const keyPackage = envelope.keyPackage;
    if (
      !equalBytes(
        await envelope.open(protector),
        privateKeyPackageBytes(keyPackage),
      )
    ) {
      throw new Error('private KeyPackage state does not match public package');
    }
    this.keyPackages.set(
      toHex(keyPackage.reference),
      cloneKeyPackage(keyPackage),
    );
    this.encryptedKeyPackages.set(
      toHex(keyPackage.reference),
      Promise.resolve(
        EncryptedKeyPackageState.deserialize(envelope.serialize()),
      ),
    );
    return cloneKeyPackage(keyPackage);
  }

  async clearKeyPackageState(reference: Uint8Array): Promise<void> {
    this.clearKeyPackageCalls += 1;
    const encodedReference = toHex(reference);
    this.keyPackages.delete(encodedReference);
    this.encryptedKeyPackages.delete(encodedReference);
  }

  async createGroup(
    input: CreateGroupInput,
  ): Promise<GroupSecurityCreateResult> {
    this.createGroupCalls += 1;
    await this.createGroupBarrier?.();
    if (!equalBytes(input.credential, input.creatorMemberId)) {
      throw new Error(
        'test creator credential does not authenticate the member',
      );
    }
    this.current = publicState(0n, input.groupId);
    return {
      state: cloneState(this.current),
      authenticatedCreatorMemberId: new Uint8Array(
        this.authenticatedCreatorMemberIdOverride ?? input.credential,
      ),
    };
  }

  async joinGroup(input: JoinGroupInput): Promise<GroupSecurityPublicState> {
    this.joinGroupCalls += 1;
    await this.joinGroupBarrier?.();
    const reference = toHex(input.keyPackageRef);
    const pending = this.keyPackages.get(reference);
    if (pending === undefined) {
      throw new Error('test KeyPackage is not pending');
    }
    if (
      !equalBytes(input.welcome.recipientKeyPackageRef, input.keyPackageRef)
    ) {
      throw new Error('test Welcome does not address the pending KeyPackage');
    }
    if (!equalBytes(input.welcome.groupId, pending.groupId)) {
      throw new Error(
        'test Welcome does not match the KeyPackage group binding',
      );
    }
    this.keyPackages.delete(reference);
    this.encryptedKeyPackages.delete(reference);
    this.current = publicState(input.welcome.epoch, input.welcome.groupId);
    return cloneState(this.current);
  }

  hasPendingKeyPackage(reference: Uint8Array): boolean {
    return this.keyPackages.has(toHex(reference));
  }

  async createCommit(
    input: CreateGroupCommitInput,
  ): Promise<GroupSecurityCommitResult> {
    const prior = this.requireState();
    this.createCommitCalls += 1;
    await this.createCommitBarrier?.();
    if (this.failNextCreateCommitAfterRetainedCheckpointMutation) {
      this.failNextCreateCommitAfterRetainedCheckpointMutation = false;
      overrideEnvelopeAlgorithm(this.lastExportedGroupState!);
      throw new Error(
        'injected commit failure after retained checkpoint mutation',
      );
    }
    this.activeTransitions += 1;
    this.maxActiveTransitions = Math.max(
      this.maxActiveTransitions,
      this.activeTransitions,
    );
    try {
      await Promise.resolve();
      const epoch = prior.epoch + 1n;
      const appliedMembership = deltaFromInput(input);
      const commit: GroupSecurityCommit = {
        protocol,
        groupId: new Uint8Array(prior.groupId),
        priorEpoch: prior.epoch,
        epoch,
        payload: commitPayload(prior.epoch, epoch, appliedMembership),
      };
      this.current = publicState(epoch, prior.groupId);
      const [change] = appliedMembership.changes;
      const welcomes: GroupWelcome[] =
        change.kind === 'add'
          ? [
              {
                protocol,
                groupId: new Uint8Array(prior.groupId),
                epoch,
                recipientKeyPackageRef: new Uint8Array(
                  this.welcomeRecipientOverride ?? change.keyPackageRef,
                ),
                payload: new Uint8Array([0x55, Number(epoch)]),
              },
            ]
          : [];
      return {
        commit,
        welcomes,
        state: cloneState(this.current),
        appliedMembership: cloneDelta(
          this.createDeltaOverride ?? appliedMembership,
        ),
      };
    } finally {
      this.activeTransitions -= 1;
    }
  }

  async applyCommit(
    commit: GroupSecurityCommit,
  ): Promise<GroupSecurityApplyResult> {
    const prior = this.requireState();
    this.applyCommitCalls += 1;
    const appliedMembership = deltaFromCommitPayload(commit.payload);
    if (commit.epoch === prior.epoch) {
      return {
        status: 'duplicate',
        state: cloneState(prior),
        appliedMembership: cloneDelta(
          this.applyDeltaOverride ?? appliedMembership,
        ),
      };
    }
    if (
      commit.priorEpoch !== prior.epoch ||
      commit.epoch !== prior.epoch + 1n ||
      appliedMembership.changes.length !== 1
    ) {
      throw new Error('contract provider rejected commit');
    }
    await this.applyCommitBarrier?.();
    this.current = publicState(commit.epoch, prior.groupId);
    return {
      status: 'applied',
      state: cloneState(this.current),
      appliedMembership: cloneDelta(
        this.applyDeltaOverride ?? appliedMembership,
      ),
    };
  }

  async exportSecret(input: ExportGroupSecretInput): Promise<Uint8Array> {
    this.requireState();
    return new Uint8Array(input.length).fill(input.context[0] ?? 0);
  }

  async getPublicState(): Promise<GroupSecurityPublicState> {
    if (this.getPublicStateOverrideOnce !== undefined) {
      const override = this.getPublicStateOverrideOnce;
      this.getPublicStateOverrideOnce = undefined;
      return cloneState(override);
    }
    return cloneState(this.requireState());
  }

  async exportEncryptedState(
    protector: GroupStateProtector,
  ): Promise<EncryptedGroupState> {
    this.exportStateCalls += 1;
    if (this.failStateExports) {
      throw new Error('injected encrypted-state export failure');
    }
    const state = this.requireState();
    const exported = await EncryptedGroupState.seal(
      state,
      privateBytes(state.epoch),
      protector,
    );
    this.lastExportedGroupState = exported;
    return exported;
  }

  async importEncryptedState(
    envelope: EncryptedGroupState,
    protector: GroupStateProtector,
  ): Promise<GroupSecurityPublicState> {
    this.importCalls += 1;
    if (
      !equalBytes(
        await envelope.open(protector),
        privateBytes(envelope.state.epoch),
      )
    ) {
      throw new Error('private state does not match public epoch');
    }
    if (this.importedStateOverrideAfterOpen !== undefined) {
      Object.defineProperty(envelope, 'state', {
        value: cloneState(this.importedStateOverrideAfterOpen),
        configurable: true,
      });
      this.importedStateOverrideAfterOpen = undefined;
    }
    this.current = cloneState(envelope.state);
    await this.importEncryptedStateBarrier?.();
    if (this.failNextImportAfterMutation) {
      this.failNextImportAfterMutation = false;
      throw new Error('injected import failure after mutation');
    }
    return cloneState(this.current);
  }

  async clearGroupState(): Promise<void> {
    this.clearCalls += 1;
    this.current = undefined;
  }

  private requireState(): GroupSecurityPublicState {
    if (this.current === undefined)
      throw new Error('provider is not initialized');
    return this.current;
  }
}

export function privateBytes(epoch: bigint): Uint8Array {
  return encoder.encode(`private-contract-state:${epoch}`);
}

export function privateKeyPackageBytes(
  keyPackage: GroupKeyPackage,
): Uint8Array {
  return encoder.encode(
    `private-key-package:${toHex(keyPackage.groupId)}:${toHex(keyPackage.reference)}:${toHex(keyPackage.payload)}`,
  );
}

export function cloneKeyPackage(keyPackage: GroupKeyPackage): GroupKeyPackage {
  return {
    protocol: { ...keyPackage.protocol },
    groupId: new Uint8Array(keyPackage.groupId),
    reference: new Uint8Array(keyPackage.reference),
    payload: new Uint8Array(keyPackage.payload),
  };
}

export function overrideEnvelopeAlgorithm(envelope: object): void {
  Object.defineProperty(envelope, 'algorithm', {
    value: 'retained-provider-mutation',
    enumerable: true,
    configurable: true,
  });
}

export class TestIdentities {
  readonly actorId = id(0xa1);
  readonly attackerId = id(0xb2);
  failNextSign = false;
  verifyCalls = 0;
  private readonly keys = new Map<string, CryptoKey>();

  static async create(): Promise<TestIdentities> {
    const value = new TestIdentities();
    value.keys.set(toHex(value.actorId), await generateHmacKey());
    value.keys.set(toHex(value.attackerId), await generateHmacKey());
    return value;
  }

  readonly sign: MembershipControlSigner = async (payload, actorId) => {
    if (this.failNextSign) {
      this.failNextSign = false;
      throw new Error('injected signer failure');
    }
    return this.signAs(actorId, payload);
  };

  readonly verify: MembershipControlSignatureVerifier = async (
    payload,
    signature,
    actorId,
  ) => {
    this.verifyCalls += 1;
    const key = this.keys.get(toHex(actorId));
    return (
      key !== undefined &&
      crypto.subtle.verify(
        'HMAC',
        key,
        signature as BufferSource,
        payload as BufferSource,
      )
    );
  };

  async signAs(actorId: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
    const key = this.keys.get(toHex(actorId));
    if (key === undefined) throw new Error('unknown test actor');
    return new Uint8Array(
      await crypto.subtle.sign('HMAC', key, payload as BufferSource),
    );
  }
}

export async function generateHmacKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export class AuthorizationPolicy {
  allowed = true;
  requirePrevious = false;
  calls: MembershipControlAuthorizationContext[] = [];

  constructor(private readonly allowedActor: Uint8Array) {}

  readonly authorize: MembershipControlAuthorizer = async (context) => {
    this.calls.push(context);
    if (
      !this.allowed ||
      !equalBytes(context.record.actorId, this.allowedActor)
    ) {
      return false;
    }
    if (context.record.action === 'create') {
      return context.previousRecord === undefined;
    }
    if (!this.requirePrevious) return true;
    return (
      context.previousRecord !== undefined &&
      context.previousRecordId !== undefined &&
      context.record.parentRecordId !== undefined &&
      equalBytes(context.previousRecordId, context.record.parentRecordId) &&
      context.previousRecord.epoch + 1n === context.record.epoch
    );
  };
}

export interface EncodedDelivery {
  controlRecord: number[];
  commit?: {
    protocol: { id: string; version: number };
    groupId: number[];
    priorEpoch: string;
    epoch: string;
    payload: number[];
  };
  welcomes: Array<{
    protocol: { id: string; version: number };
    groupId: number[];
    epoch: string;
    recipientKeyPackageRef: number[];
    payload: number[];
  }>;
}

export class JsonTestCodec implements GroupSecurityOutboxCodec {
  failDecode = false;

  encode(delivery: GroupSecurityDelivery): Uint8Array {
    const encoded: EncodedDelivery = {
      controlRecord: Array.from(
        serializeMembershipControlRecord(delivery.controlRecord),
      ),
      commit:
        delivery.commit === undefined
          ? undefined
          : {
              protocol: { ...delivery.commit.protocol },
              groupId: Array.from(delivery.commit.groupId),
              priorEpoch: delivery.commit.priorEpoch.toString(),
              epoch: delivery.commit.epoch.toString(),
              payload: Array.from(delivery.commit.payload),
            },
      welcomes: delivery.welcomes.map((welcome) => ({
        protocol: { ...welcome.protocol },
        groupId: Array.from(welcome.groupId),
        epoch: welcome.epoch.toString(),
        recipientKeyPackageRef: Array.from(welcome.recipientKeyPackageRef),
        payload: Array.from(welcome.payload),
      })),
    };
    return encoder.encode(JSON.stringify(encoded));
  }

  decode(payload: Uint8Array): GroupSecurityDelivery {
    if (this.failDecode) throw new Error('injected codec decode failure');
    const encoded = JSON.parse(decoder.decode(payload)) as EncodedDelivery;
    return {
      controlRecord: deserializeMembershipControlRecord(
        new Uint8Array(encoded.controlRecord),
      ),
      commit:
        encoded.commit === undefined
          ? undefined
          : {
              protocol: { ...encoded.commit.protocol },
              groupId: new Uint8Array(encoded.commit.groupId),
              priorEpoch: BigInt(encoded.commit.priorEpoch),
              epoch: BigInt(encoded.commit.epoch),
              payload: new Uint8Array(encoded.commit.payload),
            },
      welcomes: encoded.welcomes.map((welcome) => ({
        protocol: { ...welcome.protocol },
        groupId: new Uint8Array(welcome.groupId),
        epoch: BigInt(welcome.epoch),
        recipientKeyPackageRef: new Uint8Array(welcome.recipientKeyPackageRef),
        payload: new Uint8Array(welcome.payload),
      })),
    };
  }
}

export class FailOnceStore implements DurableGroupStateStore {
  failNextTransaction = false;

  constructor(readonly delegate: InMemoryGroupStateStore) {}

  load(key: GroupStateStoreKey): Promise<GroupStateStoreSnapshot | undefined> {
    return this.delegate.load(key);
  }

  transaction<T>(
    key: GroupStateStoreKey,
    operation: (transaction: GroupStateStoreTransaction) => T | Promise<T>,
  ): Promise<T> {
    if (!this.failNextTransaction)
      return this.delegate.transaction(key, operation);
    this.failNextTransaction = false;
    return this.delegate.transaction(key, async (transaction) => {
      await operation(transaction);
      throw new Error('injected durable commit failure');
    });
  }
}

export class AdversarialStore implements DurableGroupStateStore {
  mutateLoads?: (snapshot: GroupStateStoreSnapshot) => GroupStateStoreSnapshot;
  mutateNextTransaction?: (transaction: GroupStateStoreTransaction) => void;
  mutateNextLoadAfterTransaction?: (
    snapshot: GroupStateStoreSnapshot,
  ) => GroupStateStoreSnapshot;
  mutateNextTransactionResult?: (result: unknown) => unknown;
  skipNextTransactionCallback = false;
  beforeNextTransaction?: () => Promise<void>;
  throwAfterNextTransaction = false;
  private mutateNextLoad?: (
    snapshot: GroupStateStoreSnapshot,
  ) => GroupStateStoreSnapshot;

  constructor(readonly delegate: InMemoryGroupStateStore) {}

  async load(
    key: GroupStateStoreKey,
  ): Promise<GroupStateStoreSnapshot | undefined> {
    const snapshot = await this.delegate.load(key);
    if (snapshot === undefined) return undefined;
    const mutate = this.mutateNextLoad ?? this.mutateLoads;
    this.mutateNextLoad = undefined;
    return mutate === undefined ? snapshot : mutate(snapshot);
  }

  async transaction<T>(
    key: GroupStateStoreKey,
    operation: (transaction: GroupStateStoreTransaction) => T | Promise<T>,
  ): Promise<T> {
    if (this.skipNextTransactionCallback) {
      this.skipNextTransactionCallback = false;
      return undefined as T;
    }
    const mutateTransaction = this.mutateNextTransaction;
    this.mutateNextTransaction = undefined;
    const beforeTransaction = this.beforeNextTransaction;
    this.beforeNextTransaction = undefined;
    await beforeTransaction?.();
    const result = await this.delegate.transaction(key, async (transaction) => {
      mutateTransaction?.(transaction);
      return operation(transaction);
    });
    if (this.throwAfterNextTransaction) {
      this.throwAfterNextTransaction = false;
      throw new Error('injected timeout after durable commit');
    }
    this.mutateNextLoad = this.mutateNextLoadAfterTransaction;
    this.mutateNextLoadAfterTransaction = undefined;
    const mutateResult = this.mutateNextTransactionResult;
    this.mutateNextTransactionResult = undefined;
    return (mutateResult === undefined ? result : mutateResult(result)) as T;
  }
}

export class StaticSnapshotStore implements DurableGroupStateStore {
  constructor(private readonly snapshot: GroupStateStoreSnapshot) {}

  async load(): Promise<GroupStateStoreSnapshot> {
    return this.snapshot;
  }

  async transaction<T>(): Promise<T> {
    throw new Error('unexpected transaction against static snapshot');
  }
}

export class StaticRollbackAnchor
  implements DurableGroupSecurityRollbackAnchor
{
  constructor(private readonly value: GroupSecurityRollbackAnchorValue) {}

  async load(): Promise<GroupSecurityRollbackAnchorValue> {
    return this.value;
  }

  async advance(): Promise<boolean> {
    throw new Error('unexpected advance against static rollback anchor');
  }

  async poison(): Promise<GroupSecurityRollbackAnchorValue> {
    throw new Error('unexpected poison against static rollback anchor');
  }
}

export class ReconciliationLoadFailureStore implements DurableGroupStateStore {
  private remainingFailedLoads = 0;
  private releaseTransaction!: () => void;
  readonly transactionEntered: Promise<void>;
  private readonly transactionRelease: Promise<void>;

  constructor(readonly delegate: InMemoryGroupStateStore) {
    let entered!: () => void;
    this.transactionEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    this.transactionRelease = new Promise<void>((resolve) => {
      this.releaseTransaction = resolve;
    });
    this.entered = entered;
  }

  private readonly entered: () => void;

  release(): void {
    this.releaseTransaction();
  }

  async load(
    key: GroupStateStoreKey,
  ): Promise<GroupStateStoreSnapshot | undefined> {
    if (this.remainingFailedLoads > 0) {
      this.remainingFailedLoads -= 1;
      throw new Error('injected reconciliation load failure');
    }
    return this.delegate.load(key);
  }

  async transaction<T>(
    key: GroupStateStoreKey,
    operation: (transaction: GroupStateStoreTransaction) => T | Promise<T>,
  ): Promise<T> {
    this.entered();
    await this.transactionRelease;
    try {
      return await this.delegate.transaction(key, operation);
    } catch (error) {
      this.remainingFailedLoads = 2;
      throw error;
    }
  }
}

export class ControlledRollbackAnchor
  implements DurableGroupSecurityRollbackAnchor
{
  failNextAdvance = false;
  rejectNextAdvance = false;
  noOpNextPoison = false;
  malformedNextAdvance?: unknown;
  private readonly delegate = new InMemoryGroupSecurityRollbackAnchor();

  load(
    key: GroupStateStoreKey,
  ): Promise<GroupSecurityRollbackAnchorValue | undefined> {
    return this.delegate.load(key);
  }

  advance(
    key: GroupStateStoreKey,
    expected: GroupSecurityRollbackAnchorValue | undefined,
    next: GroupSecurityRollbackAnchorValue,
  ): Promise<boolean> {
    if (this.malformedNextAdvance !== undefined) {
      const result = this.malformedNextAdvance;
      this.malformedNextAdvance = undefined;
      return Promise.resolve(result as boolean);
    }
    if (this.failNextAdvance) {
      this.failNextAdvance = false;
      return Promise.reject(new Error('injected rollback anchor failure'));
    }
    if (this.rejectNextAdvance) {
      this.rejectNextAdvance = false;
      return Promise.resolve(false);
    }
    return this.delegate.advance(key, expected, next);
  }

  async poison(
    key: GroupStateStoreKey,
    forkPoison: GroupSecurityRollbackForkPoison,
    initial?: GroupSecurityRollbackAnchorValue,
  ): Promise<GroupSecurityRollbackAnchorValue> {
    if (this.noOpNextPoison) {
      this.noOpNextPoison = false;
      const current = await this.delegate.load(key);
      if (current !== undefined) return current;
      if (initial !== undefined) return initial;
      throw new Error('test no-op poison has no active anchor');
    }
    return this.delegate.poison(key, forkPoison, initial);
  }
}

export interface TestContext {
  provider: ContractTestProvider;
  store: DurableGroupStateStore;
  rollbackAnchor: DurableGroupSecurityRollbackAnchor;
  protector: GroupStateProtector;
  identities: TestIdentities;
  authorization: AuthorizationPolicy;
  codec: JsonTestCodec;
}

export async function context(
  store: DurableGroupStateStore = new InMemoryGroupStateStore(),
): Promise<TestContext> {
  const identities = await TestIdentities.create();
  return {
    provider: new ContractTestProvider(),
    store,
    rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
    protector: await WebCryptoGroupStateProtector.generate('coordinator-key'),
    identities,
    authorization: new AuthorizationPolicy(identities.actorId),
    codec: new JsonTestCodec(),
  };
}

export type RetentionOptions = Pick<
  GroupSecurityCoordinatorConfig,
  | 'maxOutboxEntries'
  | 'maxReplayEntries'
  | 'replayWindowEpochs'
  | 'outboxDeliveryTimeoutMs'
>;

export function config(
  value: TestContext,
  options: Partial<RetentionOptions> = {},
): GroupSecurityCoordinatorConfig {
  return {
    provider: value.provider,
    store: value.store,
    storeKey,
    rollbackAnchor: value.rollbackAnchor,
    protector: value.protector,
    actorId: value.identities.actorId,
    signControlRecord: value.identities.sign,
    verifyControlSignature: value.identities.verify,
    authorizeControl: value.authorization.authorize,
    outboxCodec: value.codec,
    maxOutboxEntries: options.maxOutboxEntries ?? 8,
    maxReplayEntries: options.maxReplayEntries ?? 8,
    replayWindowEpochs: options.replayWindowEpochs ?? 4n,
    outboxDeliveryTimeoutMs: options.outboxDeliveryTimeoutMs,
    now: () => 1_700_000_000_000,
  };
}

export async function bootstrap(
  value: TestContext,
  options?: Partial<RetentionOptions>,
): Promise<GroupSecurityCoordinator> {
  return GroupSecurityCoordinator.bootstrap(
    config(value, options),
    createGroupInput,
    { operationId: id(1), subjectId: value.identities.actorId },
  );
}

export function control(
  operation: number,
  action: 'add' | 'remove' | 'update' = 'update',
  subjectId: Uint8Array = id(0xc1),
  digest: Uint8Array = id(operation + 0x20),
): {
  operationId: Uint8Array;
  requestDigest: Uint8Array;
  action: 'add' | 'remove' | 'update';
  subjectId: Uint8Array;
} {
  return {
    operationId: id(operation),
    requestDigest: digest,
    action,
    subjectId,
  };
}

export function transitionInput(
  value: ReturnType<typeof control>,
): CreateGroupCommitInput {
  if (value.action === 'remove') {
    return {
      changes: [{ kind: 'remove', memberId: new Uint8Array(value.subjectId) }],
    };
  }
  return {
    changes: [
      {
        kind: value.action,
        memberId: new Uint8Array(value.subjectId),
        keyPackage: {
          protocol,
          groupId: new Uint8Array(groupId),
          reference: id(value.operationId[0] ^ 0x5a),
          payload: new Uint8Array(value.subjectId),
        },
      },
    ],
  };
}

export function createTransition(
  coordinator: GroupSecurityCoordinator,
  value: ReturnType<typeof control>,
) {
  return coordinator.createCommit(transitionInput(value), value);
}

export async function flushAndCollect(
  coordinator: GroupSecurityCoordinator,
): Promise<GroupSecurityDelivery[]> {
  const values: GroupSecurityDelivery[] = [];
  await coordinator.flushOutbox(async (delivery) => {
    values.push(delivery);
    return createGroupSecurityDurableAcceptance(delivery);
  });
  return values;
}

export function cloneContextWithProvider(
  value: TestContext,
  provider = new ContractTestProvider(),
): TestContext {
  return { ...value, provider };
}

export async function createInvitation(
  recipient: TestContext,
  keyPackage: GroupKeyPackage,
  subjectId: Uint8Array = recipient.identities.actorId,
  sourceProvider = new ContractTestProvider(),
  addOperation = 0x22,
): Promise<GroupSecurityJoinInvitation> {
  const source: TestContext = {
    provider: sourceProvider,
    store: new InMemoryGroupStateStore(),
    rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
    protector: recipient.protector,
    identities: recipient.identities,
    authorization: new AuthorizationPolicy(recipient.identities.actorId),
    codec: recipient.codec,
  };
  const sourceCoordinator = await bootstrap(source);
  const [genesis] = await flushAndCollect(sourceCoordinator);
  const addControl = control(
    addOperation,
    'add',
    subjectId,
    id(addOperation + 0x40),
  );
  await sourceCoordinator.createCommit(
    {
      changes: [
        {
          kind: 'add',
          memberId: new Uint8Array(subjectId),
          keyPackage: cloneKeyPackage(keyPackage),
        },
      ],
    },
    addControl,
  );
  const [delivery] = await flushAndCollect(sourceCoordinator);
  return {
    subjectId: new Uint8Array(subjectId),
    keyPackageRef: new Uint8Array(keyPackage.reference),
    controlPrefix: [genesis.controlRecord, delivery.controlRecord],
    commit: delivery.commit!,
    welcome: delivery.welcomes[0],
    authenticatedData: new Uint8Array([0x71, 0x72]),
  };
}

export function cloneInvitation(
  invitation: GroupSecurityJoinInvitation,
): GroupSecurityJoinInvitation {
  return {
    subjectId: new Uint8Array(invitation.subjectId),
    keyPackageRef: new Uint8Array(invitation.keyPackageRef),
    controlPrefix: invitation.controlPrefix.map((record) =>
      deserializeMembershipControlRecord(
        serializeMembershipControlRecord(record),
      ),
    ),
    commit: {
      protocol: { ...invitation.commit.protocol },
      groupId: new Uint8Array(invitation.commit.groupId),
      priorEpoch: invitation.commit.priorEpoch,
      epoch: invitation.commit.epoch,
      payload: new Uint8Array(invitation.commit.payload),
    },
    welcome: {
      protocol: { ...invitation.welcome.protocol },
      groupId: new Uint8Array(invitation.welcome.groupId),
      epoch: invitation.welcome.epoch,
      recipientKeyPackageRef: new Uint8Array(
        invitation.welcome.recipientKeyPackageRef,
      ),
      payload: new Uint8Array(invitation.welcome.payload),
    },
    authenticatedData:
      invitation.authenticatedData === undefined
        ? undefined
        : new Uint8Array(invitation.authenticatedData),
  };
}

export async function mutateOnlyOutbox(
  value: TestContext,
  mutate: (delivery: GroupSecurityDelivery) => GroupSecurityDelivery,
): Promise<void> {
  await value.store.transaction(storeKey, (transaction) => {
    const [entry] = transaction.outbox;
    const delivery = value.codec.decode(entry.payload);
    transaction.removeOutbox(entry.id);
    transaction.enqueueOutbox({
      ...entry,
      payload: value.codec.encode(mutate(delivery)),
    });
  });
  await advanceAnchorForUnchangedSecurityHead(value);
}

export async function advanceAnchorForUnchangedSecurityHead(
  value: TestContext,
): Promise<void> {
  const snapshot = await value.store.load(storeKey);
  const current = await value.rollbackAnchor.load(storeKey);
  if (
    snapshot?.encryptedState === undefined ||
    current === undefined ||
    snapshot.revision !== current.revision + 1 ||
    snapshot.encryptedState.state.epoch !== current.epoch
  ) {
    throw new Error(
      'test fixture cannot advance the unchanged rollback anchor',
    );
  }
  if (
    !(await value.rollbackAnchor.advance(storeKey, current, {
      revision: snapshot.revision,
      epoch: current.epoch,
      controlHead: current.controlHead,
      storeCommitment: await groupSecurityStoreSnapshotCommitment(
        snapshot,
        storeKey,
      ),
      forkPoison: undefined,
    }))
  ) {
    throw new Error('test fixture rollback anchor CAS failed');
  }
}

export async function replaceReplayHead(
  value: TestContext,
  mutate: (record: MembershipControlRecord) => Promise<MembershipControlRecord>,
): Promise<void> {
  await value.store.transaction(storeKey, async (transaction) => {
    const head = [...transaction.replay]
      .sort((a, b) => (a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0))
      .at(-1)!;
    const changed = await mutate(
      deserializeMembershipControlRecord(head.controlRecord),
    );
    const changedId = await membershipControlRecordId(changed);
    transaction.removeReplay(head.recordId);
    transaction.markReplay({
      recordId: changedId,
      operationId: changed.operationId,
      epoch: changed.epoch,
      controlRecord: serializeMembershipControlRecord(changed),
    });
  });
}

export interface RewrittenSignedSnapshot {
  readonly snapshot: GroupStateStoreSnapshot;
  readonly headRecordId: Uint8Array;
}

export async function rewriteSignedReplayChain(
  snapshot: GroupStateStoreSnapshot,
  identities: TestIdentities,
  mutate: (
    record: UnsignedMembershipControlRecord,
  ) => UnsignedMembershipControlRecord,
): Promise<RewrittenSignedSnapshot> {
  const ordered = [...snapshot.replay].sort((left, right) =>
    left.epoch < right.epoch ? -1 : left.epoch > right.epoch ? 1 : 0,
  );
  const replay: GroupStateStoreSnapshot['replay'][number][] = [];
  let parentRecordId: Uint8Array | undefined;
  for (const entry of ordered) {
    const persisted = deserializeMembershipControlRecord(entry.controlRecord);
    const { signature: _signature, ...unsigned } = persisted;
    const relinked = mutate({
      ...unsigned,
      parentRecordId:
        persisted.action === 'create'
          ? undefined
          : new Uint8Array(parentRecordId!),
    });
    const record = await signMembershipControlRecord(relinked, identities.sign);
    const recordId = await membershipControlRecordId(record);
    replay.push({
      recordId,
      operationId: new Uint8Array(record.operationId),
      epoch: record.epoch,
      controlRecord: serializeMembershipControlRecord(record),
    });
    parentRecordId = recordId;
  }
  if (parentRecordId === undefined) {
    throw new Error('test replay rewrite requires at least one record');
  }
  return {
    snapshot: { ...snapshot, replay },
    headRecordId: new Uint8Array(parentRecordId),
  };
}

export async function restoreFromSignedSnapshot(
  value: TestContext,
  provider: ContractTestProvider,
  rewritten: RewrittenSignedSnapshot,
): Promise<GroupSecurityCoordinator> {
  const encryptedState = rewritten.snapshot.encryptedState;
  if (encryptedState === undefined) {
    throw new Error('test restore snapshot requires encrypted state');
  }
  const rollbackAnchor = new StaticRollbackAnchor({
    revision: rewritten.snapshot.revision,
    epoch: encryptedState.state.epoch,
    controlHead: rewritten.headRecordId,
    storeCommitment: await groupSecurityStoreSnapshotCommitment(
      rewritten.snapshot,
      storeKey,
    ),
    forkPoison: undefined,
  });
  return GroupSecurityCoordinator.restore(
    config({
      ...value,
      provider,
      store: new StaticSnapshotStore(rewritten.snapshot),
      rollbackAnchor,
    }),
  );
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let index = 0; index < a.byteLength; index++) {
    if (a[index] !== b[index]) return false;
  }
  return true;
}

export function toHex(bytes: Uint8Array): string {
  let value = '';
  for (let index = 0; index < bytes.byteLength; index++) {
    value += bytes[index].toString(16).padStart(2, '0');
  }
  return value;
}

export function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) {
    throw new Error('invalid test hex');
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
