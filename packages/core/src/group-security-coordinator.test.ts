import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  AppliedGroupMembershipDelta,
  CreateGroupCommitInput,
  CreateGroupInput,
  CreateKeyPackageInput,
  EncryptedKeyPackageState,
  EncryptedGroupState,
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
} from './group-security-provider.js';
import {
  GroupSecurityCoordinator,
  GroupSecurityCoordinatorConfig,
  GroupSecurityDelivery,
  GroupSecurityJoinInvitation,
  GroupSecurityOutboxCodec,
  CreatePendingKeyPackageInput,
  GROUP_SECURITY_OUTBOX_KIND,
  canonicalGroupSecurityState,
} from './group-security-coordinator.js';
import {
  DurableGroupStateStore,
  GroupStateStoreKey,
  GroupStateStoreSnapshot,
  GroupStateStoreTransaction,
  InMemoryGroupStateStore,
} from './group-state-store.js';
import {
  DurableGroupSecurityRollbackAnchor,
  GroupSecurityRollbackForkPoison,
  GroupSecurityRollbackAnchorValue,
  InMemoryGroupSecurityRollbackAnchor,
} from './group-security-rollback-anchor.js';
import { createGroupSecurityDurableAcceptance } from './group-security-durable-acceptance.js';
import { groupSecurityStoreSnapshotCommitment } from './group-security-store-commitment.js';
import {
  MembershipControlAuthorizationContext,
  MembershipControlAuthorizer,
  MembershipControlRecord,
  MembershipControlSignatureVerifier,
  MembershipControlSigner,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
  signMembershipControlRecord,
} from './membership-control-record.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';

const protocol = { id: 'coordinator.contract.test', version: 1 };
const groupId = new Uint8Array([0x10, 0x20, 0x30, 0x40]);
const storeKey: GroupStateStoreKey = { protocol, groupId };
const createGroupInput: CreateGroupInput = {
  groupId,
  creatorMemberId: id(0xa1),
  credential: id(0xa1),
};

function id(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

function publicState(
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

function cloneState(state: GroupSecurityPublicState): GroupSecurityPublicState {
  return {
    protocol: { ...state.protocol },
    groupId: new Uint8Array(state.groupId),
    epoch: state.epoch,
    confirmedTranscriptHash: new Uint8Array(state.confirmedTranscriptHash),
    treeHash: new Uint8Array(state.treeHash),
  };
}

function commitPayload(
  prior: bigint,
  epoch: bigint,
  appliedMembership: AppliedGroupMembershipDelta,
): Uint8Array {
  const [change] = appliedMembership.changes;
  return new TextEncoder().encode(
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

function deltaFromCommitPayload(payload: Uint8Array): AppliedGroupMembershipDelta {
  const decoded = JSON.parse(new TextDecoder().decode(payload)) as {
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

function deltaFromInput(
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

function cloneDelta(
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

class ContractTestProvider implements GroupSecurityProvider {
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
      throw new Error('test credential does not authenticate the requested member');
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
    this.keyPackages.set(toHex(keyPackage.reference), cloneKeyPackage(keyPackage));
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
    this.keyPackages.set(toHex(keyPackage.reference), cloneKeyPackage(keyPackage));
    this.encryptedKeyPackages.set(
      toHex(keyPackage.reference),
      Promise.resolve(EncryptedKeyPackageState.deserialize(envelope.serialize())),
    );
    return cloneKeyPackage(keyPackage);
  }

  async clearKeyPackageState(reference: Uint8Array): Promise<void> {
    this.clearKeyPackageCalls += 1;
    const encodedReference = toHex(reference);
    this.keyPackages.delete(encodedReference);
    this.encryptedKeyPackages.delete(encodedReference);
  }

  async createGroup(input: CreateGroupInput): Promise<GroupSecurityCreateResult> {
    this.createGroupCalls += 1;
    await this.createGroupBarrier?.();
    if (!equalBytes(input.credential, input.creatorMemberId)) {
      throw new Error('test creator credential does not authenticate the member');
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
    if (!equalBytes(input.welcome.recipientKeyPackageRef, input.keyPackageRef)) {
      throw new Error('test Welcome does not address the pending KeyPackage');
    }
    if (!equalBytes(input.welcome.groupId, pending.groupId)) {
      throw new Error('test Welcome does not match the KeyPackage group binding');
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
      throw new Error('injected commit failure after retained checkpoint mutation');
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
      const welcomes: GroupWelcome[] = change.kind === 'add'
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
    if (!equalBytes(await envelope.open(protector), privateBytes(envelope.state.epoch))) {
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
    if (this.current === undefined) throw new Error('provider is not initialized');
    return this.current;
  }
}

function privateBytes(epoch: bigint): Uint8Array {
  return new TextEncoder().encode(`private-contract-state:${epoch}`);
}

function privateKeyPackageBytes(
  keyPackage: GroupKeyPackage,
): Uint8Array {
  return new TextEncoder().encode(
    `private-key-package:${toHex(keyPackage.groupId)}:${toHex(keyPackage.reference)}:${toHex(keyPackage.payload)}`,
  );
}

function cloneKeyPackage(keyPackage: GroupKeyPackage): GroupKeyPackage {
  return {
    protocol: { ...keyPackage.protocol },
    groupId: new Uint8Array(keyPackage.groupId),
    reference: new Uint8Array(keyPackage.reference),
    payload: new Uint8Array(keyPackage.payload),
  };
}

function overrideEnvelopeAlgorithm(envelope: object): void {
  Object.defineProperty(envelope, 'algorithm', {
    value: 'retained-provider-mutation',
    enumerable: true,
    configurable: true,
  });
}

class TestIdentities {
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

async function generateHmacKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

class AuthorizationPolicy {
  allowed = true;
  requirePrevious = false;
  calls: MembershipControlAuthorizationContext[] = [];

  constructor(private readonly allowedActor: Uint8Array) {}

  readonly authorize: MembershipControlAuthorizer = async (context) => {
    this.calls.push(context);
    if (!this.allowed || !equalBytes(context.record.actorId, this.allowedActor)) {
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

interface EncodedDelivery {
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

class JsonTestCodec implements GroupSecurityOutboxCodec {
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
    return new TextEncoder().encode(JSON.stringify(encoded));
  }

  decode(payload: Uint8Array): GroupSecurityDelivery {
    if (this.failDecode) throw new Error('injected codec decode failure');
    const encoded = JSON.parse(new TextDecoder().decode(payload)) as EncodedDelivery;
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
        recipientKeyPackageRef: new Uint8Array(
          welcome.recipientKeyPackageRef,
        ),
        payload: new Uint8Array(welcome.payload),
      })),
    };
  }
}

class FailOnceStore implements DurableGroupStateStore {
  failNextTransaction = false;

  constructor(readonly delegate: InMemoryGroupStateStore) {}

  load(key: GroupStateStoreKey): Promise<GroupStateStoreSnapshot | undefined> {
    return this.delegate.load(key);
  }

  transaction<T>(
    key: GroupStateStoreKey,
    operation: (
      transaction: GroupStateStoreTransaction,
    ) => T | Promise<T>,
  ): Promise<T> {
    if (!this.failNextTransaction) return this.delegate.transaction(key, operation);
    this.failNextTransaction = false;
    return this.delegate.transaction(key, async (transaction) => {
      await operation(transaction);
      throw new Error('injected durable commit failure');
    });
  }
}

class AdversarialStore implements DurableGroupStateStore {
  mutateLoads?: (
    snapshot: GroupStateStoreSnapshot,
  ) => GroupStateStoreSnapshot;
  mutateNextTransaction?: (
    transaction: GroupStateStoreTransaction,
  ) => void;
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
    operation: (
      transaction: GroupStateStoreTransaction,
    ) => T | Promise<T>,
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
    const result = await this.delegate.transaction(
      key,
      async (transaction) => {
        mutateTransaction?.(transaction);
        return operation(transaction);
      },
    );
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

class StaticSnapshotStore implements DurableGroupStateStore {
  constructor(private readonly snapshot: GroupStateStoreSnapshot) {}

  async load(): Promise<GroupStateStoreSnapshot> {
    return this.snapshot;
  }

  async transaction<T>(): Promise<T> {
    throw new Error('unexpected transaction against static snapshot');
  }
}

class ReconciliationLoadFailureStore implements DurableGroupStateStore {
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
    operation: (
      transaction: GroupStateStoreTransaction,
    ) => T | Promise<T>,
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

class ControlledRollbackAnchor
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

interface TestContext {
  provider: ContractTestProvider;
  store: DurableGroupStateStore;
  rollbackAnchor: DurableGroupSecurityRollbackAnchor;
  protector: GroupStateProtector;
  identities: TestIdentities;
  authorization: AuthorizationPolicy;
  codec: JsonTestCodec;
}

async function context(
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

type RetentionOptions = Pick<
  GroupSecurityCoordinatorConfig,
  | 'maxOutboxEntries'
  | 'maxReplayEntries'
  | 'replayWindowEpochs'
  | 'outboxDeliveryTimeoutMs'
>;

function config(
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

async function bootstrap(
  value: TestContext,
  options?: Partial<RetentionOptions>,
): Promise<GroupSecurityCoordinator> {
  return GroupSecurityCoordinator.bootstrap(
    config(value, options),
    createGroupInput,
    { operationId: id(1), subjectId: value.identities.actorId },
  );
}

function control(
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
  return { operationId: id(operation), requestDigest: digest, action, subjectId };
}

function transitionInput(
  value: ReturnType<typeof control>,
): CreateGroupCommitInput {
  if (value.action === 'remove') {
    return {
      changes: [
        { kind: 'remove', memberId: new Uint8Array(value.subjectId) },
      ],
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

function createTransition(
  coordinator: GroupSecurityCoordinator,
  value: ReturnType<typeof control>,
) {
  return coordinator.createCommit(transitionInput(value), value);
}

async function flushAndCollect(
  coordinator: GroupSecurityCoordinator,
): Promise<GroupSecurityDelivery[]> {
  const values: GroupSecurityDelivery[] = [];
  await coordinator.flushOutbox(async (delivery) => {
    values.push(delivery);
    return createGroupSecurityDurableAcceptance(delivery);
  });
  return values;
}

function cloneContextWithProvider(
  value: TestContext,
  provider = new ContractTestProvider(),
): TestContext {
  return { ...value, provider };
}

async function createInvitation(
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

function cloneInvitation(
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

describe('GroupSecurityCoordinator', () => {
  test('accepts genuine cross-realm Uint8Array configuration bytes', async () => {
    const value = await context();
    const crossRealmGroupId = runInNewContext(
      'new Uint8Array(bytes)',
      { bytes: Array.from(groupId) },
    ) as Uint8Array;
    const crossRealmActorId = runInNewContext(
      'new Uint8Array(bytes)',
      { bytes: Array.from(value.identities.actorId) },
    ) as Uint8Array;
    expect(crossRealmGroupId instanceof Uint8Array).toBe(false);
    expect(crossRealmActorId instanceof Uint8Array).toBe(false);
    Object.defineProperties(crossRealmGroupId, {
      byteLength: {
        get: () => {
          throw new Error('shadowed byteLength getter must not run');
        },
      },
      buffer: {
        get: () => {
          throw new Error('shadowed buffer getter must not run');
        },
      },
      [Symbol.toStringTag]: { value: 'Uint16Array' },
    });

    const coordinator = await GroupSecurityCoordinator.bootstrap(
      {
        ...config(value),
        storeKey: { protocol, groupId: crossRealmGroupId },
        actorId: crossRealmActorId,
      },
      createGroupInput,
      { operationId: id(1), subjectId: value.identities.actorId },
    );
    expect(coordinator.publicState.groupId).toEqual(groupId);
  });

  test('rejects non-Uint8 views and spoofed Uint8Array configuration bytes', async () => {
    const otherViewValue = await context();
    const otherView = runInNewContext(
      'new Uint16Array([0x2010, 0x4030])',
    ) as unknown as Uint8Array;
    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(otherViewValue),
          storeKey: { protocol, groupId: otherView },
        },
        createGroupInput,
        { operationId: id(1), subjectId: otherViewValue.identities.actorId },
      ),
    ).rejects.toThrow(/invalid length or backing buffer/);
    expect(otherViewValue.provider.createGroupCalls).toBe(0);

    const spoofedValue = await context();
    const spoofed = Object.create(Uint8Array.prototype) as Uint8Array;
    Object.defineProperties(spoofed, {
      byteLength: { value: groupId.byteLength },
      buffer: { value: new ArrayBuffer(groupId.byteLength) },
      [Symbol.toStringTag]: { value: 'Uint8Array' },
    });
    expect(spoofed instanceof Uint8Array).toBe(true);
    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(spoofedValue),
          storeKey: { protocol, groupId: spoofed },
        },
        createGroupInput,
        { operationId: id(1), subjectId: spoofedValue.identities.actorId },
      ),
    ).rejects.toThrow(/invalid length or backing buffer/);
    expect(spoofedValue.provider.createGroupCalls).toBe(0);
  });

  test('rejects cross-realm SharedArrayBuffer-backed configuration bytes', async () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const value = await context();
    const crossRealmShared = runInNewContext(`(() => {
      const bytes = new Uint8Array(new SharedArrayBuffer(4));
      Object.defineProperty(bytes, 'buffer', { value: new ArrayBuffer(4) });
      return bytes;
    })()`) as Uint8Array;
    expect(crossRealmShared instanceof Uint8Array).toBe(false);

    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(value),
          storeKey: { protocol, groupId: crossRealmShared },
        },
        createGroupInput,
        { operationId: id(1), subjectId: value.identities.actorId },
      ),
    ).rejects.toThrow(/invalid length or backing buffer/);
    expect(value.provider.createGroupCalls).toBe(0);
  });

  test('requires a durable rollback anchor before provider initialization', async () => {
    const value = await context();
    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(value),
          rollbackAnchor: undefined,
        } as unknown as GroupSecurityCoordinatorConfig,
        createGroupInput,
        { operationId: id(1), subjectId: value.identities.actorId },
      ),
    ).rejects.toThrow(/rollbackAnchor/);
    await expect(value.provider.getPublicState()).rejects.toThrow(
      /not initialized/,
    );
  });

  test('requires atomic anchor poison before provider initialization', async () => {
    const value = await context();
    const anchor = value.rollbackAnchor;
    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(value),
          rollbackAnchor: {
            load: anchor.load.bind(anchor),
            advance: anchor.advance.bind(anchor),
          } as DurableGroupSecurityRollbackAnchor,
        },
        createGroupInput,
        { operationId: id(1), subjectId: value.identities.actorId },
      ),
    ).rejects.toThrow(/atomic poison/);
    expect(value.provider.createGroupCalls).toBe(0);
    expect(await value.store.load(storeKey)).toBeUndefined();
  });

  test('rejects a poisoned anchor before loading the group store', async () => {
    let loadCalls = 0;
    const store: DurableGroupStateStore = {
      async load() {
        loadCalls += 1;
        throw new Error('store must not be loaded after terminal poison');
      },
      async transaction<T>(): Promise<T> {
        throw new Error('store must not be mutated after terminal poison');
      },
    };
    const value = await context(store);
    await value.rollbackAnchor.poison(
      storeKey,
      {
        epoch: 0n,
        parentRecordId: id(0x31),
        firstRecordId: id(0x32),
        secondRecordId: id(0x33),
        evidenceHash: id(0x34),
      },
      {
        revision: 1,
        epoch: 0n,
        controlHead: id(0x35),
        storeCommitment: id(0x36),
        forkPoison: undefined,
      },
    );

    await expect(
      GroupSecurityCoordinator.restore(config(value)),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(loadCalls).toBe(0);
    expect(value.provider.importCalls).toBe(0);
  });

  test('rejects truthy non-boolean signature and authorization results', async () => {
    const signatureValue = await context();
    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(signatureValue),
          verifyControlSignature: (async () =>
            'false') as unknown as MembershipControlSignatureVerifier,
        },
        createGroupInput,
        { operationId: id(1), subjectId: signatureValue.identities.actorId },
      ),
    ).rejects.toMatchObject({ code: 'bad-signature' });
    expect(await signatureValue.store.load(storeKey)).toBeUndefined();

    const authorizationValue = await context();
    await expect(
      GroupSecurityCoordinator.bootstrap(
        {
          ...config(authorizationValue),
          authorizeControl: (async () =>
            ({})) as unknown as MembershipControlAuthorizer,
        },
        createGroupInput,
        {
          operationId: id(1),
          subjectId: authorizationValue.identities.actorId,
        },
      ),
    ).rejects.toMatchObject({ code: 'unauthorized-control' });
    expect(await authorizationValue.store.load(storeKey)).toBeUndefined();
  });

  test('rejects bootstrap with an active provider without replacing its group', async () => {
    const value = await context();
    const activeGroupId = new Uint8Array([0x91, 0x92, 0x93]);
    await value.provider.createGroup({
      ...createGroupInput,
      groupId: activeGroupId,
    });
    value.provider.failStateExports = true;

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'already-initialized',
    });
    expect((await value.provider.getPublicState()).groupId).toEqual(
      activeGroupId,
    );
    expect(value.provider.clearCalls).toBe(0);
    expect(value.provider.exportStateCalls).toBe(0);
    expect(await value.store.load(storeKey)).toBeUndefined();
  });

  test('serializes bootstrap and permanently claims a successful provider', async () => {
    const value = await context();
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release!: () => void;
    const releasePromise = new Promise<void>((resolve) => {
      release = resolve;
    });
    value.provider.createGroupBarrier = async () => {
      entered();
      await releasePromise;
    };

    const first = bootstrap(value);
    await enteredPromise;
    const second = bootstrap(value);
    await Promise.resolve();
    expect(value.provider.createGroupCalls).toBe(1);
    release();
    await expect(first).resolves.toBeInstanceOf(GroupSecurityCoordinator);
    await expect(second).rejects.toMatchObject({ code: 'already-initialized' });
    expect(value.provider.createGroupCalls).toBe(1);
    expect(value.provider.clearCalls).toBe(0);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
  });

  test('shares lifecycle ownership across forwarding provider wrappers', async () => {
    const value = await context();
    const lifecycleIdentity = {};
    const wrap = (): ContractTestProvider =>
      new Proxy(value.provider, {
        get(target, property) {
          if (property === 'lifecycleIdentity') return lifecycleIdentity;
          const member = Reflect.get(target, property, target) as unknown;
          return typeof member === 'function' ? member.bind(target) : member;
        },
      });
    const first = await GroupSecurityCoordinator.bootstrap(
      config({ ...value, provider: wrap() }),
      createGroupInput,
      { operationId: id(1), subjectId: value.identities.actorId },
    );
    expect(first.publicState.epoch).toBe(0n);
    await expect(
      GroupSecurityCoordinator.bootstrap(
        config({ ...value, provider: wrap() }),
        createGroupInput,
        { operationId: id(2), subjectId: value.identities.actorId },
      ),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(value.provider.createGroupCalls).toBe(1);
    expect(value.provider.clearCalls).toBe(0);

    const directValue = await context();
    await bootstrap(directValue);
    const directWrapper = new Proxy(directValue.provider, {
      get(target, property) {
        if (property === 'lifecycleIdentity') return target;
        const member = Reflect.get(target, property, target) as unknown;
        return typeof member === 'function' ? member.bind(target) : member;
      },
    });
    await expect(
      GroupSecurityCoordinator.bootstrap(
        config({ ...directValue, provider: directWrapper }),
        createGroupInput,
        { operationId: id(2), subjectId: directValue.identities.actorId },
      ),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(directValue.provider.createGroupCalls).toBe(1);
    expect(directValue.provider.clearCalls).toBe(0);
  });

  test('poisons concurrent authorized genesis records before first-anchor publication', async () => {
    const firstValue = await context();
    const secondValue: TestContext = {
      ...firstValue,
      provider: new ContractTestProvider(),
      authorization: new AuthorizationPolicy(firstValue.identities.actorId),
    };
    let arrivals = 0;
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await released;
    };
    firstValue.provider.createGroupBarrier = barrier;
    secondValue.provider.createGroupBarrier = barrier;

    const results = await Promise.allSettled([
      bootstrap(firstValue),
      GroupSecurityCoordinator.bootstrap(
        config(secondValue),
        createGroupInput,
        { operationId: id(2), subjectId: secondValue.identities.actorId },
      ),
    ]);
    expect(results.some((result) => result.status === 'rejected')).toBe(true);
    expect(
      (await firstValue.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(firstValue, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('rejects bootstrap when the provider retains a different public state', async () => {
    const value = await context();
    value.provider.getPublicStateOverrideOnce = publicState(1n);

    await expect(bootstrap(value)).rejects.toThrow(/public state/);
    expect(value.provider.clearCalls).toBe(1);
    expect(await value.store.load(storeKey)).toBeUndefined();
  });

  test('rejects accessor-backed and proxied bootstrap provider outputs without invoking them', async () => {
    const accessorValue = await context();
    const createGroup = accessorValue.provider.createGroup.bind(
      accessorValue.provider,
    );
    let stateReads = 0;
    accessorValue.provider.createGroup = async (input) => {
      const created = await createGroup(input);
      const result = {
        authenticatedCreatorMemberId:
          created.authenticatedCreatorMemberId,
      } as Partial<GroupSecurityCreateResult>;
      Object.defineProperty(result, 'state', {
        enumerable: true,
        get() {
          stateReads += 1;
          return created.state;
        },
      });
      return result as GroupSecurityCreateResult;
    };
    await expect(bootstrap(accessorValue)).rejects.toThrow(
      /own data properties/,
    );
    expect(stateReads).toBe(0);
    expect(accessorValue.provider.clearCalls).toBe(1);

    const creatorValue = await context();
    const createCreatorGroup = creatorValue.provider.createGroup.bind(
      creatorValue.provider,
    );
    let iteratorReads = 0;
    creatorValue.provider.createGroup = async (input) => {
      const created = await createCreatorGroup(input);
      const authenticatedCreatorMemberId = new Proxy(
        created.authenticatedCreatorMemberId,
        {
          get(target, property) {
            if (property === Symbol.iterator) {
              iteratorReads += 1;
              return function* () {
                throw new Error('hostile byte iterator must not be consumed');
              };
            }
            return Reflect.get(target, property, target) as unknown;
          },
        },
      );
      return { ...created, authenticatedCreatorMemberId };
    };
    await expect(bootstrap(creatorValue)).rejects.toThrow(/Uint8Array/);
    expect(iteratorReads).toBe(0);
    expect(creatorValue.provider.clearCalls).toBe(1);

    const publicStateValue = await context();
    const getPublicState = publicStateValue.provider.getPublicState.bind(
      publicStateValue.provider,
    );
    let epochReads = 0;
    publicStateValue.provider.getPublicState = async () => {
      const result = await getPublicState();
      Object.defineProperty(result, 'epoch', {
        configurable: true,
        enumerable: true,
        get() {
          epochReads += 1;
          return 0n;
        },
      });
      return result;
    };
    await expect(bootstrap(publicStateValue)).rejects.toThrow(
      /own data properties/,
    );
    expect(epochReads).toBe(0);
    expect(publicStateValue.provider.clearCalls).toBe(1);
  });

  test('rejects active metadata in a pre-group store before provider mutation', async () => {
    const value = await context(
      new StaticSnapshotStore({
        revision: 1,
        encryptedState: undefined,
        pendingKeyPackages: [],
        pendingKeyPackageRequests: [],
        consumedKeyPackageRefs: [],
        replay: [],
        forkEvidence: undefined,
        outbox: [{
        id: id(0x91),
        epoch: 0n,
        kind: GROUP_SECURITY_OUTBOX_KIND,
        payload: new Uint8Array([1]),
        createdAt: 1,
        }],
      }),
    );

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'malformed-state',
    });
    expect(value.provider.createGroupCalls).toBe(0);
    expect(await value.rollbackAnchor.load(storeKey)).toBeUndefined();
  });

  test('rejects pending-package creation with an active provider even when state export would fail', async () => {
    const value = await context();
    await value.provider.createGroup(createGroupInput);
    value.provider.failStateExports = true;

    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
        operationId: id(0xcf),
        groupId,
        memberId: value.identities.actorId,
        credential: value.identities.actorId,
      }),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(value.provider.createKeyPackageCalls).toBe(0);
    expect(value.provider.exportStateCalls).toBe(0);
  });

  test('rejects an Alice creator input relabeled as Bob before provider mutation', async () => {
    const value = await context();

    await expect(
      GroupSecurityCoordinator.bootstrap(
        config(value),
        createGroupInput,
        {
          operationId: id(1),
          subjectId: value.identities.attackerId,
        },
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(value.provider.createGroupCalls).toBe(0);
    expect(await value.store.load(storeKey)).toBeUndefined();
  });

  test('rejects a provider-authenticated Bob creator for an Alice genesis subject', async () => {
    const value = await context();
    value.provider.authenticatedCreatorMemberIdOverride =
      value.identities.attackerId;

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'control-mismatch',
    });
    expect(value.provider.createGroupCalls).toBe(1);
    expect(value.provider.clearCalls).toBe(1);
    await expect(value.provider.getPublicState()).rejects.toThrow(
      /not initialized/,
    );
    expect(await value.store.load(storeKey)).toBeUndefined();
  });

  test('creates the first anchor at the existing revision after pending KeyPackage transactions', async () => {
    const value = await context();
    for (const credential of [0x41, 0x42]) {
      const keyPackage = await value.provider.createKeyPackage({
        groupId,
        memberId: id(credential),
        credential: id(credential),
        requestCommitment: id(credential + 1),
      });
      const encrypted = await value.provider.exportEncryptedKeyPackage(
        keyPackage.reference,
        value.protector,
      );
      await value.store.transaction(storeKey, (transaction) => {
        expect(transaction.putPendingKeyPackage(encrypted)).toBe(true);
        expect(
          transaction.bindPendingKeyPackageRequest({
            operationId: id(credential + 2),
            requestCommitment: id(credential + 1),
            keyPackageReference: keyPackage.reference,
          }),
        ).toBe(true);
      });
    }
    expect((await value.store.load(storeKey))?.revision).toBe(2);
    expect(await value.rollbackAnchor.load(storeKey)).toBeUndefined();

    const coordinator = await bootstrap(value);
    const snapshot = (await value.store.load(storeKey))!;
    expect(coordinator.publicState.epoch).toBe(0n);
    expect(snapshot.revision).toBe(3);
    expect(snapshot.pendingKeyPackages).toHaveLength(2);
    expect(await value.rollbackAnchor.load(storeKey)).toEqual({
      revision: 3,
      epoch: 0n,
      controlHead: snapshot.replay[0].recordId,
      storeCommitment:
        await groupSecurityStoreSnapshotCommitment(snapshot),
      forkPoison: undefined,
    });
  });

  test('snapshots and durably persists a group-bound KeyPackage with byte-stable exports', async () => {
    const value = await context();
    const extension = new Uint8Array([0x61, 0x62]);
    const input: CreatePendingKeyPackageInput = {
      operationId: id(0xd1),
      groupId: new Uint8Array(groupId),
      memberId: id(0x51),
      credential: id(0x51),
      extensions: new Map([[7, extension]]),
    };
    const pending = GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      input,
    );
    input.operationId.fill(0xee);
    input.groupId.fill(0xee);
    input.memberId.fill(0xee);
    input.credential.fill(0xee);
    extension.fill(0xee);

    const keyPackage = await pending;
    expect(keyPackage).toMatchObject({
      protocol,
      groupId,
    });
    expect(keyPackage.payload.subarray(0, 32)).toEqual(id(0x51));
    expect(keyPackage.payload).toHaveLength(64);
    expect(keyPackage.reference).toHaveLength(32);
    const first = await value.provider.exportEncryptedKeyPackage(
      keyPackage.reference,
      value.protector,
    );
    const second = await value.provider.exportEncryptedKeyPackage(
      keyPackage.reference,
      value.protector,
    );
    expect(second.serialize()).toEqual(first.serialize());
    const snapshot = (await value.store.load(storeKey))!;
    expect(snapshot.pendingKeyPackages).toHaveLength(1);
    expect(snapshot.pendingKeyPackages[0].serialize()).toEqual(first.serialize());
    expect(snapshot.encryptedState).toBeUndefined();
    expect(await value.rollbackAnchor.load(storeKey)).toBeUndefined();
  });

  test('rejects proxied and shared authenticated KeyPackage outputs before persistence', async () => {
    const memberValue = await context();
    let memberIteratorReads = 0;
    memberValue.provider.authenticateKeyPackageMember = async () =>
      new Proxy(id(0x51), {
        get(target, property) {
          if (property === Symbol.iterator) {
            memberIteratorReads += 1;
            return function* () {
              throw new Error('hostile byte iterator must not be consumed');
            };
          }
          return Reflect.get(target, property, target) as unknown;
        },
      });
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(
        config(memberValue),
        {
          operationId: id(0xd6),
          groupId,
          memberId: id(0x51),
          credential: id(0x51),
        },
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(memberIteratorReads).toBe(0);
    expect(memberValue.provider.clearKeyPackageCalls).toBe(1);
    expect(await memberValue.store.load(storeKey)).toBeUndefined();

    const requestValue = await context();
    let requestIteratorReads = 0;
    requestValue.provider.authenticateKeyPackageRequestCommitment =
      async () =>
        new Proxy(id(0xd7), {
          get(target, property) {
            if (property === Symbol.iterator) {
              requestIteratorReads += 1;
              return function* () {
                throw new Error('hostile byte iterator must not be consumed');
              };
            }
            return Reflect.get(target, property, target) as unknown;
          },
        });
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(
        config(requestValue),
        {
          operationId: id(0xd7),
          groupId,
          memberId: id(0x52),
          credential: id(0x52),
        },
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(requestIteratorReads).toBe(0);
    expect(requestValue.provider.clearKeyPackageCalls).toBe(1);
    expect(await requestValue.store.load(storeKey)).toBeUndefined();

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedValue = await context();
      sharedValue.provider.authenticateKeyPackageRequestCommitment =
        async () => new Uint8Array(new SharedArrayBuffer(32));
      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(
          config(sharedValue),
          {
            operationId: id(0xd8),
            groupId,
            memberId: id(0x53),
            credential: id(0x53),
          },
        ),
      ).rejects.toMatchObject({ code: 'control-mismatch' });
      expect(sharedValue.provider.clearKeyPackageCalls).toBe(1);
      expect(await sharedValue.store.load(storeKey)).toBeUndefined();
    }
  });

  test.each(['accessor', 'typed-array Proxy'] as const)(
    'retires a provider whose retained KeyPackage has an unusable %s output',
    async (variant) => {
      const value = await context();
      const createKeyPackage = value.provider.createKeyPackage.bind(
        value.provider,
      );
      let retainedReference: Uint8Array | undefined;
      let hostileReads = 0;
      value.provider.createKeyPackage = async (input) => {
        const created = await createKeyPackage(input);
        retainedReference = new Uint8Array(created.reference);
        if (variant === 'accessor') {
          const output = {
            protocol: created.protocol,
            groupId: created.groupId,
            reference: created.reference,
          } as Partial<GroupKeyPackage>;
          Object.defineProperty(output, 'payload', {
            enumerable: true,
            get() {
              hostileReads += 1;
              return created.payload;
            },
          });
          return output as GroupKeyPackage;
        }
        return {
          ...created,
          payload: new Proxy(created.payload, {
            get(target, property) {
              if (property === Symbol.iterator) {
                hostileReads += 1;
                return function* () {
                  throw new Error(
                    'hostile byte iterator must not be consumed',
                  );
                };
              }
              return Reflect.get(target, property, target) as unknown;
            },
          }),
        };
      };
      const input: CreatePendingKeyPackageInput = {
        operationId: id(0xd9),
        groupId,
        memberId: id(0x54),
        credential: id(0x54),
      };

      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(
          config(value),
          input,
        ),
      ).rejects.toMatchObject({ code: 'rollback-unavailable' });
      expect(hostileReads).toBe(0);
      expect(retainedReference).toBeDefined();
      expect(value.provider.hasPendingKeyPackage(retainedReference!)).toBe(
        true,
      );
      expect(value.provider.clearKeyPackageCalls).toBe(0);
      expect(await value.store.load(storeKey)).toBeUndefined();

      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(
          config(value),
          input,
        ),
      ).rejects.toMatchObject({ code: 'already-initialized' });
      expect(value.provider.createKeyPackageCalls).toBe(1);
    },
  );

  test('requires exact post-commit pending state from an invoked transaction callback', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    store.skipNextTransactionCallback = true;
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
        operationId: id(0xcf),
        groupId,
        memberId: id(0x51),
        credential: id(0x51),
      }),
    ).rejects.toMatchObject({ code: 'store-conflict' });
    expect(await delegate.load(storeKey)).toBeUndefined();
    expect(value.provider.clearKeyPackageCalls).toBe(1);

    const retryProvider = new ContractTestProvider();
    const retry = cloneContextWithProvider(value, retryProvider);
    store.mutateNextLoadAfterTransaction = (snapshot) => ({
      ...snapshot,
      pendingKeyPackageRequests: [],
    });
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(retry), {
        operationId: id(0xd0),
        groupId,
        memberId: id(0x52),
        credential: id(0x52),
      }),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect((await delegate.load(storeKey))?.pendingKeyPackages).toHaveLength(1);
    expect(retryProvider.clearKeyPackageCalls).toBe(1);
  });

  test('clones KeyPackage extensions through captured Map intrinsics', async () => {
    class HostileExtensions extends Map<number, Uint8Array> {
      override get size(): number {
        return 0;
      }

      override *[Symbol.iterator](): MapIterator<[number, Uint8Array]> {
        throw new Error('hostile map iterator must not be consumed');
      }
    }
    const value = await context();
    const extensions = new HostileExtensions([
      [7, new Uint8Array([0x61])],
    ]);
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
        operationId: id(0xd0),
        groupId,
        memberId: id(0x51),
        credential: id(0x51),
        extensions,
      }),
    ).resolves.toMatchObject({ groupId });
    expect(value.provider.createKeyPackageCalls).toBe(1);
  });

  test('bounds pending KeyPackage bytes intrinsically before copying and rejects shared extensions', async () => {
    const value = await context();
    const oversizedExtension = new Uint8Array(1024 * 1024 + 1);
    Object.defineProperty(oversizedExtension, 'byteLength', { value: 1 });
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
        operationId: id(0xd4),
        groupId,
        memberId: id(0x51),
        credential: id(0x51),
        extensions: new Map([[7, oversizedExtension]]),
      }),
    ).rejects.toThrow(/bounded unshared Uint8Array/);

    const oversizedOperationId = new Uint8Array(33);
    Object.defineProperty(oversizedOperationId, 'byteLength', { value: 32 });
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
        operationId: oversizedOperationId,
        groupId,
        memberId: id(0x51),
        credential: id(0x51),
      }),
    ).rejects.toThrow(/bounded unshared Uint8Array/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedExtension = new Uint8Array(new SharedArrayBuffer(1));
      sharedExtension[0] = 0x61;
      Object.defineProperty(sharedExtension, 'buffer', {
        value: new ArrayBuffer(1),
      });
      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
          operationId: id(0xd5),
          groupId,
          memberId: id(0x51),
          credential: id(0x51),
          extensions: new Map([[7, sharedExtension]]),
        }),
      ).rejects.toThrow(/bounded unshared Uint8Array/);
    }
    expect(value.provider.createKeyPackageCalls).toBe(0);
    expect(await value.store.load(storeKey)).toBeUndefined();
  });

  test('resumes a committed pending request after timeout and rejects changed retries', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const request: CreatePendingKeyPackageInput = {
      operationId: id(0xd2),
      groupId: new Uint8Array(groupId),
      memberId: id(0x52),
      credential: id(0x52),
      extensions: new Map([[8, new Uint8Array([0x63])]]),
    };
    store.throwAfterNextTransaction = true;

    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(
        config(value),
        request,
      ),
    ).rejects.toThrow(/timeout after durable commit/);
    const committed = (await delegate.load(storeKey))!;
    expect(committed.pendingKeyPackages).toHaveLength(1);
    expect(committed.pendingKeyPackageRequests).toHaveLength(1);
    const committedPackage = committed.pendingKeyPackages[0].keyPackage;
    expect(value.provider.hasPendingKeyPackage(committedPackage.reference))
      .toBe(false);

    const retryProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(value, retryProvider);
    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(
        config(restarted),
        request,
      ),
    ).resolves.toEqual(committedPackage);
    expect(retryProvider.createKeyPackageCalls).toBe(0);

    const changedRequests: CreatePendingKeyPackageInput[] = [
      {
        ...request,
        credential: id(0x53),
      },
      {
        ...request,
        memberId: id(0x54),
        credential: id(0x54),
      },
      {
        ...request,
        extensions: new Map([[8, new Uint8Array([0x64])]]),
      },
    ];
    for (const changed of changedRequests) {
      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(
          config(restarted),
          changed,
        ),
      ).rejects.toMatchObject({ code: 'operation-conflict' });
    }
    expect(retryProvider.createKeyPackageCalls).toBe(0);

    const second = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(restarted),
      { ...request, operationId: id(0xd3) },
    );
    expect(second.reference).not.toEqual(committedPackage.reference);
    expect(retryProvider.createKeyPackageCalls).toBe(1);
  });

  test('rechecks a durable pending retry after authentication before returning it', async () => {
    const value = await context();
    const request: CreatePendingKeyPackageInput = {
      operationId: id(0xd4),
      groupId,
      memberId: value.identities.actorId,
      credential: value.identities.actorId,
    };
    await GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      request,
    );
    const retryProvider = new ContractTestProvider();
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    retryProvider.authenticateKeyPackageRequestBarrier = async () => {
      entered();
      await released;
    };
    const retry = GroupSecurityCoordinator.createPendingKeyPackage(
      config(cloneContextWithProvider(value, retryProvider)),
      request,
    );
    await enteredPromise;
    await bootstrap(value);
    release();

    await expect(retry).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(retryProvider.createKeyPackageCalls).toBe(0);
  });

  test('rejects a provider credential binding that differs from the requested pending member', async () => {
    const value = await context();
    value.provider.authenticatedMemberIdOverride = value.identities.attackerId;

    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), {
        operationId: id(0xd2),
        groupId,
        memberId: value.identities.actorId,
        credential: value.identities.actorId,
      }),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(value.provider.clearKeyPackageCalls).toBe(1);
    expect((await value.store.load(storeKey))?.pendingKeyPackages ?? []).toEqual(
      [],
    );
  });

  test('rejects remapping one pending operation to another same-member package', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const firstRequest: CreatePendingKeyPackageInput = {
      operationId: id(0xe1),
      groupId,
      memberId: id(0x51),
      credential: id(0x51),
    };
    const secondRequest = {
      ...firstRequest,
      operationId: id(0xe2),
    };
    const firstPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      firstRequest,
    );
    await GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      secondRequest,
    );
    const invitation = await createInvitation(value, firstPackage, id(0x51));
    store.mutateLoads = (snapshot) => {
      const requests = snapshot.pendingKeyPackageRequests.map((request) => ({
        ...request,
        operationId: new Uint8Array(request.operationId),
        requestCommitment: new Uint8Array(request.requestCommitment),
        keyPackageReference: new Uint8Array(request.keyPackageReference),
      }));
      const firstReference = requests[0].keyPackageReference;
      requests[0].keyPackageReference = requests[1].keyPackageReference;
      requests[1].keyPackageReference = firstReference;
      return { ...snapshot, pendingKeyPackageRequests: requests };
    };

    await expect(
      GroupSecurityCoordinator.createPendingKeyPackage(
        config(value),
        firstRequest,
      ),
    ).rejects.toMatchObject({ code: 'operation-conflict' });
    expect(value.provider.createKeyPackageCalls).toBe(2);

    const joiningProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(value, joiningProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'operation-conflict' });
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
  });

  test('persists independent KeyPackage and group-state envelope snapshots', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    store.mutateNextTransaction = () => {
      overrideEnvelopeAlgorithm(value.provider.lastExportedKeyPackageState!);
    };
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      {
        operationId: id(0xd3),
        groupId,
        memberId: value.identities.actorId,
        credential: value.identities.actorId,
      },
    );
    const pending = (await delegate.load(storeKey))!.pendingKeyPackages[0];
    expect(pending.algorithm).toBe(value.protector.algorithm);
    await expect(pending.open(value.protector)).resolves.toEqual(
      privateKeyPackageBytes(keyPackage),
    );

    store.mutateNextTransaction = () => {
      overrideEnvelopeAlgorithm(value.provider.lastExportedGroupState!);
    };
    await bootstrap(value);
    const encryptedState = (await delegate.load(storeKey))!.encryptedState!;
    expect(encryptedState.algorithm).toBe(value.protector.algorithm);
    await expect(encryptedState.open(value.protector)).resolves.toEqual(
      privateBytes(0n),
    );
  });

  test('rejects an Alice KeyPackage relabeled as Bob before creating an Add', async () => {
    const recipient = await context();
    const alicePackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd4),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const sourceProvider = new ContractTestProvider();

    await expect(
      createInvitation(
        recipient,
        alicePackage,
        recipient.identities.attackerId,
        sourceProvider,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(sourceProvider.authenticateKeyPackageCalls).toBe(1);
    expect(sourceProvider.createCommitCalls).toBe(0);
  });

  test('rejects a signed Bob invitation addressed to Alice pending state before join mutation', async () => {
    const recipient = await context();
    const alicePackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd5),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const sourceProvider = new ContractTestProvider();
    sourceProvider.authenticatedMemberIdOverride =
      recipient.identities.attackerId;
    const invitation = await createInvitation(
      recipient,
      alicePackage,
      recipient.identities.attackerId,
      sourceProvider,
    );
    const joiningProvider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, joiningProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(joiningProvider.authenticateKeyPackageCalls).toBe(1);
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
    expect(joiningProvider.joinGroupCalls).toBe(0);
  });

  test('joins across provider restarts and atomically consumes the pending KeyPackage', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd6),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const joiningProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(recipient, joiningProvider);
    restarted.authorization.requirePrevious = true;

    const coordinator = await GroupSecurityCoordinator.joinFromInvitation(
      config(restarted),
      invitation,
    );
    expect(coordinator.publicState.epoch).toBe(1n);
    expect(joiningProvider.importKeyPackageCalls).toBe(1);
    expect(joiningProvider.joinGroupCalls).toBe(1);
    expect(joiningProvider.hasPendingKeyPackage(keyPackage.reference)).toBe(false);
    const snapshot = (await recipient.store.load(storeKey))!;
    expect(snapshot.encryptedState?.state.epoch).toBe(1n);
    expect(snapshot.pendingKeyPackages).toHaveLength(0);
    expect(snapshot.consumedKeyPackageRefs).toEqual([keyPackage.reference]);
    expect(snapshot.replay.map((entry) => entry.epoch)).toEqual([0n, 1n]);
    expect(await recipient.rollbackAnchor.load(storeKey)).toEqual({
      revision: snapshot.revision,
      epoch: 1n,
      controlHead: snapshot.replay.at(-1)!.recordId,
      storeCommitment:
        await groupSecurityStoreSnapshotCommitment(snapshot),
      forkPoison: undefined,
    });

    const restoredProvider = new ContractTestProvider();
    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(recipient, restoredProvider)),
    );
    expect(restored.publicState.epoch).toBe(1n);
    expect(restoredProvider.importCalls).toBe(1);

    const replayProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, replayProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'stale-replay' });
    expect(replayProvider.importKeyPackageCalls).toBe(0);
    expect(replayProvider.joinGroupCalls).toBe(0);
  });

  test('poisons concurrent forked joins before the first active anchor', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd6),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const firstInvitation = await createInvitation(
      recipient,
      keyPackage,
      recipient.identities.actorId,
      new ContractTestProvider(),
      0x22,
    );
    const secondInvitation = await createInvitation(
      recipient,
      keyPackage,
      recipient.identities.actorId,
      new ContractTestProvider(),
      0x23,
    );
    const firstProvider = new ContractTestProvider();
    const secondProvider = new ContractTestProvider();
    let arrivals = 0;
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await released;
    };
    firstProvider.joinGroupBarrier = barrier;
    secondProvider.joinGroupBarrier = barrier;

    const results = await Promise.allSettled([
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, firstProvider)),
        firstInvitation,
      ),
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, secondProvider)),
        secondInvitation,
      ),
    ]);
    expect(results.some((result) => result.status === 'rejected')).toBe(true);
    expect(
      (await recipient.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(recipient, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('rolls a consumed provider back to fresh state when the join store transaction fails', async () => {
    const delegate = new InMemoryGroupStateStore();
    const failingStore = new FailOnceStore(delegate);
    const recipient = await context(failingStore);
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd7),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const failedProvider = new ContractTestProvider();
    failingStore.failNextTransaction = true;

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, failedProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(failedProvider.joinGroupCalls).toBe(1);
    expect(failedProvider.clearCalls).toBe(1);
    expect(failedProvider.clearKeyPackageCalls).toBe(1);
    expect(failedProvider.hasPendingKeyPackage(keyPackage.reference)).toBe(false);
    await expect(failedProvider.getPublicState()).rejects.toThrow(
      /not initialized/,
    );
    const afterFailure = (await delegate.load(storeKey))!;
    expect(afterFailure.encryptedState).toBeUndefined();
    expect(afterFailure.pendingKeyPackages).toHaveLength(1);
    expect(afterFailure.consumedKeyPackageRefs).toHaveLength(0);
    expect(await recipient.rollbackAnchor.load(storeKey)).toBeUndefined();

    const retryProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, retryProvider)),
        invitation,
      ),
    ).resolves.toBeInstanceOf(GroupSecurityCoordinator);
    expect(retryProvider.joinGroupCalls).toBe(1);
  });

  test('rejects malformed, substituted, and changed-group invitations before provider mutation', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd8),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const substitutePackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd9),
        groupId,
        memberId: recipient.identities.attackerId,
        credential: recipient.identities.attackerId,
      },
    );

    const malformed = cloneInvitation(invitation);
    malformed.controlPrefix.at(-1)!.signature.fill(0);
    const malformedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, malformedProvider)),
        malformed,
      ),
    ).rejects.toMatchObject({ code: 'bad-signature' });
    expect(malformedProvider.importKeyPackageCalls).toBe(0);
    expect(malformedProvider.joinGroupCalls).toBe(0);

    const substituted = cloneInvitation(invitation);
    substituted.keyPackageRef.set(substitutePackage.reference);
    substituted.welcome.recipientKeyPackageRef.set(
      substitutePackage.reference,
    );
    const substitutedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, substitutedProvider)),
        substituted,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(substitutedProvider.importKeyPackageCalls).toBe(0);

    const changedGroup = cloneInvitation(invitation);
    changedGroup.commit.groupId[0] ^= 0xff;
    changedGroup.welcome.groupId[0] ^= 0xff;
    const changedGroupProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, changedGroupProvider)),
        changedGroup,
      ),
    ).rejects.toThrow();
    expect(changedGroupProvider.importKeyPackageCalls).toBe(0);
  });

  test('never restores a reusable KeyPackage after post-store anchor failure', async () => {
    const recipient = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    recipient.rollbackAnchor = rollbackAnchor;
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xda),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const provider = new ContractTestProvider();
    rollbackAnchor.rejectNextAdvance = true;

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, provider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    const snapshot = (await recipient.store.load(storeKey))!;
    expect(snapshot.encryptedState?.state.epoch).toBe(1n);
    expect(snapshot.pendingKeyPackages).toHaveLength(0);
    expect(snapshot.consumedKeyPackageRefs).toEqual([keyPackage.reference]);
    expect(provider.hasPendingKeyPackage(keyPackage.reference)).toBe(false);
    expect(provider.clearCalls).toBe(0);
    expect(provider.clearKeyPackageCalls).toBe(0);
    expect(await rollbackAnchor.load(storeKey)).toBeUndefined();

    const replayProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, replayProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'stale-replay' });
    expect(replayProvider.importKeyPackageCalls).toBe(0);
  });

  test('snapshots a mutable invitation before asynchronous verification', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xdb),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const provider = new ContractTestProvider();
    const pending = GroupSecurityCoordinator.joinFromInvitation(
      config(cloneContextWithProvider(recipient, provider)),
      invitation,
    );

    invitation.subjectId.fill(0xee);
    invitation.keyPackageRef.fill(0xee);
    invitation.controlPrefix[0].controlPayload.fill(0xee);
    invitation.controlPrefix.at(-1)!.signature.fill(0xee);
    invitation.commit.payload.fill(0xee);
    invitation.welcome.recipientKeyPackageRef.fill(0xee);
    invitation.welcome.payload.fill(0xee);
    invitation.authenticatedData?.fill(0xee);

    await expect(pending).resolves.toBeInstanceOf(GroupSecurityCoordinator);
    expect(provider.joinGroupCalls).toBe(1);
  });

  test('rejects a truthy non-boolean invitation-chain authorization result', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xda),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const provider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        {
          ...config(cloneContextWithProvider(recipient, provider)),
          authorizeControl: (async () =>
            ({})) as unknown as MembershipControlAuthorizer,
        },
        invitation,
      ),
    ).rejects.toThrow(/unauthorized/);
    expect(provider.importKeyPackageCalls).toBe(0);
    expect(await recipient.rollbackAnchor.load(storeKey)).toBeUndefined();
  });

  test('rejects an aggregate oversized invitation prefix before verification', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xdc),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const oversizedRecord = {
      ...invitation.controlPrefix[1],
      controlPayload: new Uint8Array(2 * 1024 * 1024),
    };
    const verifyCalls = recipient.identities.verifyCalls;
    const joiningProvider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, joiningProvider), {
          maxReplayEntries: 128,
        }),
        {
          ...invitation,
          controlPrefix: new Array(65).fill(oversizedRecord),
        },
      ),
    ).rejects.toThrow(/prefix exceeds its byte bound/);
    expect(recipient.identities.verifyCalls).toBe(verifyCalls);
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
  });

  test('rejects invitation iterator overrides and accessor-backed records before reading them', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xde),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const verifyCalls = recipient.identities.verifyCalls;
    let ownKeysCalls = 0;
    const oversizedPrefix = new Proxy(new Array(9), {
      ownKeys() {
        ownKeysCalls += 1;
        throw new Error('oversized prefix keys must not be enumerated');
      },
    });
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient)),
        { ...invitation, controlPrefix: oversizedPrefix },
      ),
    ).rejects.toThrow(/outside configured bounds/);
    expect(ownKeysCalls).toBe(0);
    const overriddenPrefix = [...invitation.controlPrefix];
    Object.defineProperty(overriddenPrefix, Symbol.iterator, {
      configurable: true,
      value: function* () {
        throw new Error('hostile array iterator must not be consumed');
      },
    });
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient)),
        { ...invitation, controlPrefix: overriddenPrefix },
      ),
    ).rejects.toThrow(/extra properties/);

    let payloadReads = 0;
    const accessorRecord = { ...invitation.controlPrefix[0] };
    Object.defineProperty(accessorRecord, 'controlPayload', {
      configurable: true,
      enumerable: true,
      get() {
        payloadReads += 1;
        return payloadReads === 1
          ? new Uint8Array([1])
          : new Uint8Array(4 * 1024 * 1024);
      },
    });
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient)),
        {
          ...invitation,
          controlPrefix: [accessorRecord, invitation.controlPrefix[1]],
        },
      ),
    ).rejects.toThrow(/own data properties/);
    expect(payloadReads).toBe(0);
    expect(recipient.identities.verifyCalls).toBe(verifyCalls);
  });

  test('snapshots outer invitation descriptors and rejects shared bytes before provider or store mutation', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xdf),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const before = await recipient.store.load(storeKey);
    const joiningProvider = new ContractTestProvider();
    let subjectReads = 0;
    const accessorInvitation = { ...invitation };
    Object.defineProperty(accessorInvitation, 'subjectId', {
      configurable: true,
      enumerable: true,
      get() {
        subjectReads += 1;
        return subjectReads === 1
          ? recipient.identities.actorId
          : new Uint8Array(4 * 1024 * 1024);
      },
    });
    const proxiedInvitation = new Proxy(accessorInvitation, {});

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, joiningProvider)),
        proxiedInvitation,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(subjectReads).toBe(0);
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
    expect(joiningProvider.joinGroupCalls).toBe(0);
    expect(await recipient.store.load(storeKey)).toEqual(before);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedAuthenticatedData = new Uint8Array(
        new SharedArrayBuffer(32),
      );
      await expect(
        GroupSecurityCoordinator.joinFromInvitation(
          config(cloneContextWithProvider(recipient, joiningProvider)),
          {
            ...invitation,
            authenticatedData: sharedAuthenticatedData,
          },
        ),
      ).rejects.toThrow(/bounded unshared Uint8Array/);
      expect(joiningProvider.importKeyPackageCalls).toBe(0);
      expect(joiningProvider.joinGroupCalls).toBe(0);
      expect(await recipient.store.load(storeKey)).toEqual(before);
    }
  });

  test('rejects an existing rollback anchor or active provider before recipient mutation', async () => {
    const anchored = await context();
    const anchoredPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(anchored),
      {
        operationId: id(0xdc),
        groupId,
        memberId: anchored.identities.actorId,
        credential: anchored.identities.actorId,
      },
    );
    const anchoredInvitation = await createInvitation(
      anchored,
      anchoredPackage,
    );
    const anchoredSnapshot = (await anchored.store.load(storeKey))!;
    await anchored.rollbackAnchor.advance(storeKey, undefined, {
      revision: 1,
      epoch: 0n,
      controlHead: id(0x88),
      storeCommitment:
        await groupSecurityStoreSnapshotCommitment(anchoredSnapshot),
      forkPoison: undefined,
    });
    const anchoredProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(anchored, anchoredProvider)),
        anchoredInvitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(anchoredProvider.importKeyPackageCalls).toBe(0);

    const active = await context();
    const activePackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(active),
      {
        operationId: id(0xdd),
        groupId,
        memberId: active.identities.actorId,
        credential: active.identities.actorId,
      },
    );
    const activeInvitation = await createInvitation(active, activePackage);
    const activeProvider = new ContractTestProvider();
    await activeProvider.createGroup(createGroupInput);
    activeProvider.failStateExports = true;
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(active, activeProvider)),
        activeInvitation,
      ),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(activeProvider.importKeyPackageCalls).toBe(0);
    expect(activeProvider.joinGroupCalls).toBe(0);
    expect(activeProvider.exportStateCalls).toBe(0);
  });

  test('restores the signed chain before provider import and supplies previousRecord authorization context', async () => {
    const first = await context();
    first.authorization.requirePrevious = true;
    const coordinator = await bootstrap(first);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);

    const restartedProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(first, restartedProvider);
    const restored = await GroupSecurityCoordinator.restore(config(restarted));
    expect(restored.publicState.epoch).toBe(1n);
    expect(restartedProvider.importCalls).toBe(1);

    await expect(
      createTransition(restored, control(3)),
    ).resolves.toMatchObject({ status: 'committed' });
    const latest = first.authorization.calls.at(-1)!;
    expect(latest.previousRecord?.epoch).toBe(1n);
    expect(latest.previousRecordId).toEqual(latest.record.parentRecordId);
  });

  test('retires a restoring provider when state advances or poisons during import', async () => {
    const advanced = await context();
    const active = await bootstrap(advanced);
    await flushAndCollect(active);
    const restoringProvider = new ContractTestProvider();
    let importEntered!: () => void;
    const importStarted = new Promise<void>((resolve) => {
      importEntered = resolve;
    });
    let releaseImport!: () => void;
    const importRelease = new Promise<void>((resolve) => {
      releaseImport = resolve;
    });
    restoringProvider.importEncryptedStateBarrier = async () => {
      importEntered();
      await importRelease;
    };
    const restoring = GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(advanced, restoringProvider)),
    );
    await importStarted;
    await createTransition(active, control(2));
    releaseImport();
    await expect(restoring).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(restoringProvider.clearCalls).toBe(1);
    const latest = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(advanced)),
    );
    expect(latest.publicState.epoch).toBe(1n);

    const poisoned = await context();
    const poisonedActive = await bootstrap(poisoned);
    await flushAndCollect(poisonedActive);
    const poisonedProvider = new ContractTestProvider();
    let poisonImportEntered!: () => void;
    const poisonImportStarted = new Promise<void>((resolve) => {
      poisonImportEntered = resolve;
    });
    let releasePoisonImport!: () => void;
    const poisonImportRelease = new Promise<void>((resolve) => {
      releasePoisonImport = resolve;
    });
    poisonedProvider.importEncryptedStateBarrier = async () => {
      poisonImportEntered();
      await poisonImportRelease;
    };
    const restoringPoisoned = GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(poisoned, poisonedProvider)),
    );
    await poisonImportStarted;
    await poisoned.rollbackAnchor.poison(storeKey, {
      epoch: 0n,
      parentRecordId: id(0x61),
      firstRecordId: id(0x62),
      secondRecordId: id(0x63),
      evidenceHash: id(0x64),
    });
    releasePoisonImport();
    await expect(restoringPoisoned).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect(poisonedProvider.clearCalls).toBe(1);
    const finalProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(poisoned, finalProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(finalProvider.importCalls).toBe(0);
  });

  test('serializes concurrent transitions for one group', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    const results = await Promise.all([
      createTransition(coordinator, control(2)),
      createTransition(coordinator, control(3)),
    ]);

    expect(results.map((result) => result.status)).toEqual([
      'committed',
      'committed',
    ]);
    expect(value.provider.maxActiveTransitions).toBe(1);
    expect(coordinator.publicState.epoch).toBe(2n);
  });

  test('rolls back from an independent checkpoint after provider-retained export mutation', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    value.provider.failNextCreateCommitAfterRetainedCheckpointMutation = true;

    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toThrow(/retained checkpoint mutation/);
    expect(value.provider.importCalls).toBe(1);
    expect(coordinator.publicState.epoch).toBe(0n);
    await expect(
      createTransition(coordinator, control(3)),
    ).resolves.toMatchObject({ status: 'committed' });
  });

  test('snapshots bootstrap and queued transition inputs at invocation', async () => {
    const value = await context();
    const groupInput: CreateGroupInput = {
      groupId: new Uint8Array(groupId),
      creatorMemberId: new Uint8Array(value.identities.actorId),
      credential: new Uint8Array(value.identities.actorId),
      authenticatedData: new Uint8Array([0x31]),
    };
    const bootstrapControl = {
      operationId: id(1),
      subjectId: new Uint8Array(value.identities.actorId),
    };
    const pendingBootstrap = GroupSecurityCoordinator.bootstrap(
      config(value),
      groupInput,
      bootstrapControl,
    );
    groupInput.groupId.fill(0xee);
    groupInput.creatorMemberId.fill(0xee);
    groupInput.credential.fill(0xee);
    groupInput.authenticatedData!.fill(0xee);
    bootstrapControl.operationId.fill(0xee);
    bootstrapControl.subjectId.fill(0xee);
    const coordinator = await pendingBootstrap;
    expect(coordinator.publicState.groupId).toEqual(groupId);
    await flushAndCollect(coordinator);

    const requested = control(2, 'update', id(0xd1), id(0xe1));
    const requestedInput = transitionInput(requested);
    const expectedSubject = new Uint8Array(requested.subjectId);
    const expectedOperation = new Uint8Array(requested.operationId);
    const expectedDigest = new Uint8Array(requested.requestDigest);
    const expectedReference = new Uint8Array(
      requestedInput.changes[0].kind === 'remove'
        ? new Uint8Array()
        : requestedInput.changes[0].keyPackage.reference,
    );
    const pending = coordinator.createCommit(requestedInput, requested);
    requested.operationId.fill(0xdd);
    requested.requestDigest.fill(0xdd);
    requested.subjectId.fill(0xdd);
    requestedInput.changes[0].memberId.fill(0xdd);
    if (requestedInput.changes[0].kind !== 'remove') {
      requestedInput.changes[0].keyPackage.reference.fill(0xdd);
      requestedInput.changes[0].keyPackage.payload.fill(0xdd);
    }

    const result = await pending;
    expect(result).toMatchObject({ status: 'committed' });
    if (result.status !== 'committed') throw new Error('transition was not committed');
    expect(result.controlRecord.operationId).toEqual(expectedOperation);
    expect(result.controlRecord.subjectId).toEqual(expectedSubject);
    expect(toHex(result.controlRecord.controlPayload)).toContain(
      toHex(expectedDigest),
    );
    const [delivery] = await flushAndCollect(coordinator);
    expect(deltaFromCommitPayload(delivery.commit!.payload)).toEqual({
      changes: [
        {
          kind: 'update',
          memberId: expectedSubject,
          keyPackageRef: expectedReference,
        },
      ],
    });
  });

  test('snapshots received deliveries before queued application', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);
    await createTransition(sourceCoordinator, control(2));
    const [delivery] = await flushAndCollect(sourceCoordinator);
    const expectedRecord = serializeMembershipControlRecord(
      delivery.controlRecord,
    );

    const pending = targetCoordinator.applyCommit(
      delivery.commit!,
      delivery.controlRecord,
      delivery.welcomes,
    );
    delivery.commit!.groupId.fill(0xee);
    delivery.commit!.payload.fill(0xee);
    delivery.controlRecord.groupId.fill(0xee);
    delivery.controlRecord.operationId.fill(0xee);
    delivery.controlRecord.controlPayload.fill(0xee);
    delivery.controlRecord.signature.fill(0xee);

    const result = await pending;
    expect(result).toMatchObject({ status: 'committed' });
    if (result.status !== 'committed') throw new Error('transition was not committed');
    expect(serializeMembershipControlRecord(result.controlRecord)).toEqual(
      expectedRecord,
    );
  });

  test('does not invoke Welcome iterators and accepts canonical null-prototype controls', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);
    await createTransition(sourceCoordinator, control(2));
    const [delivery] = await flushAndCollect(sourceCoordinator);
    const hostileWelcomes = [...delivery.welcomes];
    let iteratorCalls = 0;
    Object.defineProperty(hostileWelcomes, Symbol.iterator, {
      enumerable: false,
      value: function* () {
        iteratorCalls += 1;
        throw new Error('hostile array iterator must not be consumed');
      },
    });

    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        hostileWelcomes,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(iteratorCalls).toBe(0);
    expect(target.provider.applyCommitCalls).toBe(0);

    const nullProtocol = Object.assign(
      Object.create(null) as Record<string, unknown>,
      delivery.controlRecord.protocol,
      { ignoredProtocolField: true },
    );
    const nullRecord = Object.assign(
      Object.create(null) as Record<string, unknown>,
      delivery.controlRecord,
      { protocol: nullProtocol, ignoredRecordField: true },
    ) as unknown as MembershipControlRecord;
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        nullRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'committed' });
  });

  test('rejects accessor-backed incoming control records before reading them', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    const [delivery] = await flushAndCollect(coordinator);
    const accessorRecord = { ...delivery.controlRecord };
    let payloadReads = 0;
    Object.defineProperty(accessorRecord, 'controlPayload', {
      configurable: true,
      enumerable: true,
      get() {
        payloadReads += 1;
        return payloadReads === 1
          ? new Uint8Array([1])
          : new Uint8Array(4 * 1024 * 1024);
      },
    });
    const verifyCalls = value.identities.verifyCalls;

    await expect(
      coordinator.applyCommit(
        delivery.commit!,
        accessorRecord,
        delivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(payloadReads).toBe(0);
    expect(value.identities.verifyCalls).toBe(verifyCalls);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedGroupId = new Uint8Array(
        new SharedArrayBuffer(delivery.controlRecord.groupId.byteLength),
      );
      sharedGroupId.set(delivery.controlRecord.groupId);
      await expect(
        coordinator.applyCommit(
          delivery.commit!,
          { ...delivery.controlRecord, groupId: sharedGroupId },
          delivery.welcomes,
        ),
      ).rejects.toMatchObject({ code: 'control-mismatch' });
      expect(value.identities.verifyCalls).toBe(verifyCalls);
    }
  });

  test('clears a fresh provider after bootstrap failure and explicitly flags an unavailable reset', async () => {
    const clearable = await context();
    clearable.identities.failNextSign = true;
    await expect(bootstrap(clearable)).rejects.toThrow(/signer failure/);
    expect(clearable.provider.clearCalls).toBe(1);
    await expect(clearable.provider.getPublicState()).rejects.toThrow(
      /not initialized/,
    );

    const undisposable = await context();
    Object.defineProperty(undisposable.provider, 'clearGroupState', {
      value: undefined,
    });
    undisposable.identities.failNextSign = true;
    await expect(bootstrap(undisposable)).rejects.toMatchObject({
      code: 'rollback-unavailable',
    });
    expect((await undisposable.provider.getPublicState()).epoch).toBe(0n);
  });

  test('retires a provider when bootstrap cleanup reports success but leaves its group active', async () => {
    const value = await context();
    value.identities.failNextSign = true;
    value.provider.clearGroupState = async () => {
      value.provider.clearCalls += 1;
    };

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect(value.provider.clearCalls).toBe(1);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'already-initialized',
    });
    expect(value.provider.createGroupCalls).toBe(1);
  });

  test('retires a joining provider when cleanup reports success but leaves the joined group active', async () => {
    const value = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      {
        operationId: id(0xe7),
        groupId,
        memberId: value.identities.actorId,
        credential: value.identities.actorId,
      },
    );
    const invitation = await createInvitation(value, keyPackage);
    const provider = new ContractTestProvider();
    provider.getPublicStateOverrideOnce = publicState(7n);
    provider.clearGroupState = async () => {
      provider.clearCalls += 1;
    };
    const joining = cloneContextWithProvider(value, provider);

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(joining),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(provider.clearCalls).toBe(1);
    expect((await provider.getPublicState()).epoch).toBe(1n);
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(joining),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(provider.joinGroupCalls).toBe(1);
  });

  test('restores a preexisting provider checkpoint when restore import mutates then fails', async () => {
    const stored = await context();
    const coordinator = await bootstrap(stored);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);

    const provider = new ContractTestProvider();
    await provider.createGroup(createGroupInput);
    provider.failNextImportAfterMutation = true;
    const restarted = cloneContextWithProvider(stored, provider);
    await expect(
      GroupSecurityCoordinator.restore(config(restarted)),
    ).rejects.toThrow(/import failure after mutation/);
    expect((await provider.getPublicState()).epoch).toBe(0n);
    expect(provider.importCalls).toBe(2);
  });

  test('does not replace an active provider when its restore checkpoint export fails', async () => {
    const stored = await context();
    await bootstrap(stored);

    const provider = new ContractTestProvider();
    const activeGroupId = new Uint8Array([0x81, 0x82]);
    await provider.createGroup({
      ...createGroupInput,
      groupId: activeGroupId,
    });
    provider.failStateExports = true;

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toThrow(/export failure/);
    expect(provider.importCalls).toBe(0);
    expect((await provider.getPublicState()).groupId).toEqual(activeGroupId);
  });

  test('does not replace an active provider from a stale exported restore checkpoint', async () => {
    const stored = await context();
    await bootstrap(stored);

    const provider = new ContractTestProvider();
    const activeGroupId = new Uint8Array([0x84, 0x85]);
    await provider.createGroup({
      ...createGroupInput,
      groupId: activeGroupId,
    });
    const staleState = publicState(7n, activeGroupId);
    const staleCheckpoint = await EncryptedGroupState.seal(
      staleState,
      privateBytes(staleState.epoch),
      stored.protector,
    );
    provider.exportEncryptedState = async () => staleCheckpoint;

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toThrow(/public state/);
    expect(provider.importCalls).toBe(0);
    expect(await provider.getPublicState()).toEqual(
      publicState(0n, activeGroupId),
    );
  });

  test('compares restore import against state independent of the provider argument', async () => {
    const stored = await context();
    await bootstrap(stored);
    const provider = new ContractTestProvider();
    provider.importedStateOverrideAfterOpen = publicState(7n);

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(provider.importCalls).toBe(1);
    expect(provider.clearCalls).toBe(1);
    await expect(provider.getPublicState()).rejects.toThrow(/not initialized/);
  });

  test('rejects a restore whose provider reports the import but retains another state', async () => {
    const stored = await context();
    await bootstrap(stored);
    const provider = new ContractTestProvider();
    provider.getPublicStateOverrideOnce = publicState(7n);

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(provider.importCalls).toBe(1);
    expect(provider.clearCalls).toBe(1);
  });

  test('detects rollback to a complete independently populated snapshot before provider import', async () => {
    const advanced = await context();
    const older: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: advanced.protector,
      identities: advanced.identities,
      authorization: new AuthorizationPolicy(advanced.identities.actorId),
      codec: advanced.codec,
    };
    const advancedCoordinator = await bootstrap(advanced);
    const olderCoordinator = await bootstrap(older);
    await flushAndCollect(advancedCoordinator);
    await flushAndCollect(olderCoordinator);
    await createTransition(advancedCoordinator, control(2));
    await flushAndCollect(advancedCoordinator);

    const olderSnapshot = (await older.store.load(storeKey))!;
    const advancedAnchor = (await advanced.rollbackAnchor.load(storeKey))!;
    expect(olderSnapshot.encryptedState?.state.epoch).toBe(0n);
    expect(advancedAnchor.epoch).toBe(1n);
    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config({
          ...older,
          provider,
          rollbackAnchor: advanced.rollbackAnchor,
        }),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects aggregate replay amplification before verification, authorization, or provider import', async () => {
    const value = await context();
    await bootstrap(value);
    const snapshot = (await value.store.load(storeKey))!;
    const aliasedControlRecord = new Uint8Array(4 * 1024 * 1024);
    const replay = Array.from({ length: 2048 }, (_, index) => {
      const recordId = id(0x81);
      const operationId = id(0x82);
      new DataView(recordId.buffer).setUint32(28, index, false);
      new DataView(operationId.buffer).setUint32(28, index, false);
      return {
        recordId,
        operationId,
        epoch: BigInt(index),
        controlRecord: aliasedControlRecord,
      };
    });
    value.identities.verifyCalls = 0;
    value.authorization.calls = [];
    const provider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.restore(
        config(
          {
            ...value,
            provider,
            store: new StaticSnapshotStore({ ...snapshot, replay }),
          },
          { maxReplayEntries: 2048 },
        ),
      ),
    ).rejects.toThrow(/exceeds its bound/);
    expect(value.identities.verifyCalls).toBe(0);
    expect(value.authorization.calls).toHaveLength(0);
    expect(provider.importCalls).toBe(0);
  });

  test('rejects same-revision pending and consumed metadata substitution before provider import', async () => {
    const value = await context();
    await bootstrap(value);
    const snapshot = (await value.store.load(storeKey))!;
    const pending = await EncryptedKeyPackageState.seal(
      {
        protocol,
        groupId,
        reference: new Uint8Array([0xa1]),
        payload: new Uint8Array([0xa2]),
      },
      new Uint8Array([0xa3]),
      value.protector,
    );
    const variants: GroupStateStoreSnapshot[] = [
      {
        ...snapshot,
        pendingKeyPackages: [pending],
        pendingKeyPackageRequests: [
          {
            operationId: id(0xa4),
            requestCommitment: id(0xa5),
            keyPackageReference: new Uint8Array([0xa1]),
          },
        ],
      },
      {
        ...snapshot,
        consumedKeyPackageRefs: [new Uint8Array([0xb1])],
      },
    ];
    value.identities.verifyCalls = 0;
    value.authorization.calls = [];

    for (const substituted of variants) {
      const provider = new ContractTestProvider();
      await expect(
        GroupSecurityCoordinator.restore(
          config({
            ...value,
            provider,
            store: new StaticSnapshotStore(substituted),
          }),
        ),
      ).rejects.toMatchObject({ code: 'rollback-detected' });
      expect(provider.importCalls).toBe(0);
      expect(value.identities.verifyCalls).toBe(0);
      expect(value.authorization.calls).toHaveLength(0);
    }
  });

  test('rejects same-revision outbox deletion before count or delivery', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    store.mutateLoads = (snapshot) => ({
      ...snapshot,
      outbox: [],
    });

    await expect(coordinator.pendingOutboxCount()).rejects.toMatchObject({
      code: 'rollback-detected',
    });
    let sends = 0;
    await expect(
      coordinator.flushOutbox(async (delivery) => {
        sends += 1;
        return createGroupSecurityDurableAcceptance(delivery);
      }),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(sends).toBe(0);
    expect((await delegate.load(storeKey))?.outbox).toHaveLength(1);
  });

  test('rejects same-revision pending and consumed substitution during runtime reads', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    const pending = await EncryptedKeyPackageState.seal(
      {
        protocol,
        groupId,
        reference: new Uint8Array([0xc1]),
        payload: new Uint8Array([0xc2]),
      },
      new Uint8Array([0xc3]),
      value.protector,
    );
    const mutations = [
      (snapshot: GroupStateStoreSnapshot): GroupStateStoreSnapshot => ({
        ...snapshot,
        pendingKeyPackages: [pending],
        pendingKeyPackageRequests: [
          {
            operationId: id(0xc4),
            requestCommitment: id(0xc5),
            keyPackageReference: new Uint8Array([0xc1]),
          },
        ],
      }),
      (snapshot: GroupStateStoreSnapshot): GroupStateStoreSnapshot => ({
        ...snapshot,
        consumedKeyPackageRefs: [new Uint8Array([0xd1])],
      }),
    ];

    for (const mutate of mutations) {
      store.mutateLoads = mutate;
      await expect(coordinator.pendingOutboxCount()).rejects.toMatchObject({
        code: 'rollback-detected',
      });
    }
  });

  test('rejects transaction-base deletion before a transition can launder it', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    const before = (await delegate.load(storeKey))!;
    store.mutateNextTransaction = (transaction) => {
      for (const entry of transaction.outbox) {
        transaction.removeOutbox(entry.id);
      }
    };

    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await delegate.load(storeKey)).toEqual(before);
  });

  test('rejects truthy non-boolean durable transaction method results', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await delegate.load(storeKey);
    store.mutateNextTransaction = (transaction) => {
      const markReplay = transaction.markReplay.bind(transaction);
      Object.defineProperty(transaction, 'markReplay', {
        configurable: true,
        value: (entry: Parameters<GroupStateStoreTransaction['markReplay']>[0]) => {
          markReplay(entry);
          return {};
        },
      });
    };

    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'store-conflict' });
    expect(await delegate.load(storeKey)).toEqual(before);
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
  });

  test('verifies the committed snapshot before advancing its anchor', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    store.mutateNextLoadAfterTransaction = (snapshot) => ({
      ...snapshot,
      outbox: [],
    });
    const value = await context(store);

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await delegate.load(storeKey))?.outbox).toHaveLength(1);
    expect(await value.rollbackAnchor.load(storeKey)).toBeUndefined();
  });

  test('ignores an untrusted transaction result and adopts only the reloaded authorized view', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    value.authorization.requirePrevious = true;
    const coordinator = await bootstrap(value);
    const [genesis] = await flushAndCollect(coordinator);
    const forgedRecord = {
      ...genesis.controlRecord,
      epoch: 99n,
      operationId: id(0xee),
    };
    store.mutateNextTransactionResult = (result) => {
      if (result !== null && typeof result === 'object' && 'view' in result) {
        const returned = result as {
          view: {
            headRecordId: Uint8Array;
            lastControlRecord: MembershipControlRecord;
            recordsById: Map<string, MembershipControlRecord>;
          };
        };
        returned.view.headRecordId = id(0xee);
        returned.view.lastControlRecord = forgedRecord;
        returned.view.recordsById = new Map([
          [toHex(id(0xee)), forgedRecord],
        ]);
        return returned;
      }
      return { view: { lastControlRecord: forgedRecord } };
    };

    const first = await createTransition(coordinator, control(2));
    expect(first.status).toBe('committed');
    expect(coordinator.publicState.epoch).toBe(1n);
    await createTransition(coordinator, control(3));

    const epochTwoAuthorization = value.authorization.calls.findLast(
      (call) => call.record.epoch === 2n,
    );
    expect(epochTwoAuthorization?.previousRecord?.epoch).toBe(1n);
    expect(epochTwoAuthorization?.previousRecordId).toEqual(
      first.recordId,
    );
  });

  test('advances the anchor when restore prunes replay metadata', async () => {
    const value = await context();
    const coordinator = await bootstrap(value, {
      maxReplayEntries: 8,
      replayWindowEpochs: 4n,
    });
    await flushAndCollect(coordinator);
    for (let operation = 2; operation <= 4; operation++) {
      await createTransition(coordinator, control(operation));
      await flushAndCollect(coordinator);
    }
    const before = (await value.store.load(storeKey))!;
    expect(before.replay.map((entry) => entry.epoch)).toEqual([
      0n,
      1n,
      2n,
      3n,
    ]);

    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value), {
        maxReplayEntries: 8,
        replayWindowEpochs: 1n,
      }),
    );
    const after = (await value.store.load(storeKey))!;
    const anchor = (await value.rollbackAnchor.load(storeKey))!;
    expect(restored.publicState.epoch).toBe(3n);
    expect(after.revision).toBe(before.revision + 1);
    expect(after.replay.map((entry) => entry.epoch)).toEqual([2n, 3n]);
    expect(anchor).toEqual({
      revision: after.revision,
      epoch: 3n,
      controlHead: after.replay.at(-1)!.recordId,
      storeCommitment:
        await groupSecurityStoreSnapshotCommitment(after),
    });
  });

  test('poisons the coordinator when rollback-anchor CAS is rejected after commit', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    value.rollbackAnchor = rollbackAnchor;
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const beforeAnchor = (await rollbackAnchor.load(storeKey))!;

    rollbackAnchor.rejectNextAdvance = true;
    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    const snapshot = (await value.store.load(storeKey))!;
    expect(snapshot.revision).toBe(beforeAnchor.revision + 1);
    expect(snapshot.encryptedState?.state.epoch).toBe(1n);
    expect(await rollbackAnchor.load(storeKey)).toEqual(beforeAnchor);
    expect(() => coordinator.publicState).toThrow(/poisoned/);
    expect((await value.provider.getPublicState()).epoch).toBe(1n);

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects a truthy non-boolean rollback-anchor CAS result', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    rollbackAnchor.malformedNextAdvance = {};
    value.rollbackAnchor = rollbackAnchor;

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await value.store.load(storeKey))?.encryptedState).toBeDefined();
    expect(await rollbackAnchor.load(storeKey)).toBeUndefined();
    expect(value.provider.clearCalls).toBe(0);
  });

  test('fails closed when initial rollback-anchor persistence throws', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    rollbackAnchor.failNextAdvance = true;
    value.rollbackAnchor = rollbackAnchor;

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await value.store.load(storeKey))?.encryptedState).toBeDefined();
    expect(await rollbackAnchor.load(storeKey)).toBeUndefined();
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(value.provider.clearCalls).toBe(0);

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rolls provider and chain state back after store, signer, authorizer, or codec failure', async () => {
    const delegate = new InMemoryGroupStateStore();
    const failingStore = new FailOnceStore(delegate);
    const value = await context(failingStore);
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await delegate.load(storeKey);

    failingStore.failNextTransaction = true;
    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toThrow(/durable commit failure/);
    expect(coordinator.publicState.epoch).toBe(0n);
    expect(await delegate.load(storeKey)).toEqual(before);

    value.identities.failNextSign = true;
    await expect(
      createTransition(coordinator, control(3)),
    ).rejects.toThrow(/signer failure/);
    expect(coordinator.publicState.epoch).toBe(0n);

    value.authorization.allowed = false;
    await expect(
      createTransition(coordinator, control(4)),
    ).rejects.toMatchObject({ code: 'unauthorized-control' });
    value.authorization.allowed = true;
    expect(coordinator.publicState.epoch).toBe(0n);

    value.codec.failDecode = true;
    await expect(
      createTransition(coordinator, control(5)),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    value.codec.failDecode = false;
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await delegate.load(storeKey)).toEqual(before);
  });

  test('descriptor-snapshots provider transition results before reading fields', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await value.store.load(storeKey);
    const createCommit = value.provider.createCommit.bind(value.provider);
    let stateReads = 0;
    value.provider.createCommit = async (input) => {
      const result = await createCommit(input);
      const output = {
        commit: result.commit,
        welcomes: result.welcomes,
        appliedMembership: result.appliedMembership,
      } as Partial<GroupSecurityCommitResult>;
      Object.defineProperty(output, 'state', {
        enumerable: true,
        get() {
          stateReads += 1;
          return result.state;
        },
      });
      return output as GroupSecurityCommitResult;
    };

    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toThrow(/own data properties/);
    expect(stateReads).toBe(0);
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await value.store.load(storeKey)).toEqual(before);
  });

  test('snapshots create-commit input/change descriptors and rejects shared key-package bytes before mutation', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await value.store.load(storeKey);
    const providerCalls = value.provider.createCommitCalls;
    const localControl = control(2, 'update', id(0xd1));
    const validInput = transitionInput(localControl);

    let changesReads = 0;
    const accessorInput: Record<string, unknown> = {};
    Object.defineProperty(accessorInput, 'changes', {
      configurable: true,
      enumerable: true,
      get() {
        changesReads += 1;
        return changesReads === 1 ? validInput.changes : [];
      },
    });
    await expect(
      coordinator.createCommit(
        new Proxy(accessorInput, {}) as unknown as CreateGroupCommitInput,
        localControl,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(changesReads).toBe(0);

    const validChange = validInput.changes[0];
    if (validChange.kind === 'remove') {
      throw new Error('test setup requires a KeyPackage-bearing change');
    }
    let keyPackageReads = 0;
    const accessorChange = { ...validChange };
    Object.defineProperty(accessorChange, 'keyPackage', {
      configurable: true,
      enumerable: true,
      get() {
        keyPackageReads += 1;
        return keyPackageReads === 1 ? validChange.keyPackage : undefined;
      },
    });
    await expect(
      coordinator.createCommit(
        {
          changes: [new Proxy(accessorChange, {})],
        } as CreateGroupCommitInput,
        localControl,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(keyPackageReads).toBe(0);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedPayload = new Uint8Array(new SharedArrayBuffer(32));
      await expect(
        coordinator.createCommit(
          {
            changes: [
              {
                ...validChange,
                keyPackage: {
                  ...validChange.keyPackage,
                  payload: sharedPayload,
                },
              },
            ],
          },
          localControl,
        ),
      ).rejects.toThrow(/bounded unshared Uint8Array/);
    }

    expect(value.provider.createCommitCalls).toBe(providerCalls);
    expect(await value.store.load(storeKey)).toEqual(before);
    expect(coordinator.publicState.epoch).toBe(0n);
  });

  test('makes exact local and incoming retries idempotent but rejects operation reuse with changed intent', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);

    const localControl = control(2, 'add', id(0xd1), id(0xe1));
    await createTransition(sourceCoordinator, localControl);
    const calls = source.provider.createCommitCalls;
    await expect(
      createTransition(sourceCoordinator, localControl),
    ).resolves.toMatchObject({ status: 'duplicate' });
    expect(source.provider.createCommitCalls).toBe(calls);
    await expect(
      sourceCoordinator.createCommit(transitionInput(localControl), {
        ...localControl,
        action: 'remove',
      }),
    ).rejects.toMatchObject({ code: 'operation-conflict' });
    await expect(
      sourceCoordinator.createCommit(transitionInput(localControl), {
        ...localControl,
        requestDigest: id(0xe2),
      }),
    ).rejects.toMatchObject({ code: 'operation-conflict' });

    const [delivery] = await flushAndCollect(sourceCoordinator);
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'committed' });
    const applyCalls = target.provider.applyCommitCalls;
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'duplicate' });
    expect(target.provider.applyCommitCalls).toBe(applyCalls);
  });

  test('durably fails closed when partitioned coordinators rejoin with same-parent siblings', async () => {
    const left = await context();
    const right: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: left.protector,
      identities: left.identities,
      authorization: new AuthorizationPolicy(left.identities.actorId),
      codec: left.codec,
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);

    await createTransition(leftCoordinator, control(2, 'update', id(0xd1)));
    await createTransition(rightCoordinator, control(3, 'update', id(0xd2)));
    const [leftDelivery] = await flushAndCollect(leftCoordinator);
    const [rightDelivery] = await flushAndCollect(rightCoordinator);

    await expect(
      leftCoordinator.applyCommit(
        rightDelivery.commit!,
        rightDelivery.controlRecord,
        rightDelivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    await expect(
      rightCoordinator.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(left.provider.applyCommitCalls).toBe(0);
    expect(right.provider.applyCommitCalls).toBe(0);
    expect(() => leftCoordinator.publicState).toThrow(/same-parent/);
    await expect(leftCoordinator.pendingOutboxCount()).rejects.toMatchObject({
      code: 'fork-detected',
    });

    const leftFork = (await left.store.load(storeKey))!.forkEvidence;
    const rightFork = (await right.store.load(storeKey))!.forkEvidence;
    expect((await left.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();
    expect((await right.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();
    expect(leftFork).toBeDefined();
    expect(rightFork).toBeDefined();
    expect(leftFork?.firstRecordId).toEqual(rightFork?.firstRecordId);
    expect(leftFork?.secondRecordId).toEqual(rightFork?.secondRecordId);

    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(left, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
    expect((await left.store.load(storeKey))?.forkEvidence).toEqual(leftFork);
  });

  test('reconciles concurrent incoming siblings but does not poison an exact incoming race', async () => {
    const target = await context();
    const sourceLeft: TestContext = {
      ...target,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(target.identities.actorId),
    };
    const sourceRight: TestContext = {
      ...sourceLeft,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(target.identities.actorId),
    };
    const targetBase = await bootstrap(target);
    const leftSource = await bootstrap(sourceLeft);
    const rightSource = await bootstrap(sourceRight);
    await flushAndCollect(targetBase);
    await flushAndCollect(leftSource);
    await flushAndCollect(rightSource);
    await createTransition(leftSource, control(0x41, 'update', id(0xd1)));
    await createTransition(rightSource, control(0x42, 'update', id(0xd2)));
    const [leftDelivery] = await flushAndCollect(leftSource);
    const [rightDelivery] = await flushAndCollect(rightSource);

    const firstProvider = new ContractTestProvider();
    const secondProvider = new ContractTestProvider();
    const first = await GroupSecurityCoordinator.restore(
      config({
        ...target,
        provider: firstProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    const second = await GroupSecurityCoordinator.restore(
      config({
        ...target,
        provider: secondProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    let arrivals = 0;
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await released;
    };
    firstProvider.applyCommitBarrier = barrier;
    secondProvider.applyCommitBarrier = barrier;
    const forkResults = await Promise.allSettled([
      first.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
      second.applyCommit(
        rightDelivery.commit!,
        rightDelivery.controlRecord,
        rightDelivery.welcomes,
      ),
    ]);
    expect(forkResults.some((result) => result.status === 'rejected')).toBe(
      true,
    );
    expect((await target.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();
    const poisonedRestartProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config({ ...target, provider: poisonedRestartProvider }),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(poisonedRestartProvider.importCalls).toBe(0);

    const exactTarget: TestContext = {
      ...target,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(target.identities.actorId),
    };
    const exactBase = await bootstrap(exactTarget);
    await flushAndCollect(exactBase);
    const exactFirstProvider = new ContractTestProvider();
    const exactSecondProvider = new ContractTestProvider();
    const exactFirst = await GroupSecurityCoordinator.restore(
      config({
        ...exactTarget,
        provider: exactFirstProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    const exactSecond = await GroupSecurityCoordinator.restore(
      config({
        ...exactTarget,
        provider: exactSecondProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    arrivals = 0;
    let releaseExact!: () => void;
    const exactReleased = new Promise<void>((resolve) => {
      releaseExact = resolve;
    });
    const exactBarrier = async () => {
      arrivals += 1;
      if (arrivals === 2) releaseExact();
      await exactReleased;
    };
    exactFirstProvider.applyCommitBarrier = exactBarrier;
    exactSecondProvider.applyCommitBarrier = exactBarrier;
    const exactResults = await Promise.allSettled([
      exactFirst.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
      exactSecond.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
    ]);
    expect(exactResults.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect((await exactTarget.rollbackAnchor.load(storeKey))?.forkPoison).toBeUndefined();
    const exactRestart = await GroupSecurityCoordinator.restore(
      config({ ...exactTarget, provider: new ContractTestProvider() }),
    );
    expect(exactRestart.publicState.epoch).toBe(1n);
  });

  test('durably poisons an authenticated ambiguity when conflict reconciliation cannot load', async () => {
    const delegate = new InMemoryGroupStateStore();
    const winner = await context(delegate);
    const winnerCoordinator = await bootstrap(winner);
    await flushAndCollect(winnerCoordinator);
    const failingStore = new ReconciliationLoadFailureStore(delegate);
    const loserProvider = new ContractTestProvider();
    const loserContext: TestContext = {
      ...winner,
      provider: loserProvider,
      store: failingStore,
      authorization: new AuthorizationPolicy(winner.identities.actorId),
    };
    const loser = await GroupSecurityCoordinator.restore(config(loserContext));
    const losingTransition = createTransition(
      loser,
      control(0x51, 'update', id(0xd2)),
    );
    await failingStore.transactionEntered;
    await createTransition(
      winnerCoordinator,
      control(0x52, 'update', id(0xd1)),
    );
    failingStore.release();

    await expect(losingTransition).rejects.toMatchObject({
      code: 'fork-detected',
    });
    const poison = (await winner.rollbackAnchor.load(storeKey))?.forkPoison;
    expect(poison).toMatchObject({
      reason: 'unreconciled-authenticated-candidate',
      epoch: 1n,
    });
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(winner, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('durably poisons an unreconciled first-anchor candidate', async () => {
    const delegate = new InMemoryGroupStateStore();
    const winner = await context(delegate);
    const failingStore = new ReconciliationLoadFailureStore(delegate);
    const loserContext: TestContext = {
      ...winner,
      provider: new ContractTestProvider(),
      store: failingStore,
      authorization: new AuthorizationPolicy(winner.identities.actorId),
    };
    const losingBootstrap = GroupSecurityCoordinator.bootstrap(
      config(loserContext),
      createGroupInput,
      { operationId: id(2), subjectId: winner.identities.actorId },
    );
    await failingStore.transactionEntered;
    await bootstrap(winner);
    failingStore.release();

    await expect(losingBootstrap).rejects.toMatchObject({
      code: 'fork-detected',
    });
    expect((await winner.rollbackAnchor.load(storeKey))?.forkPoison).toMatchObject({
      reason: 'unreconciled-first-anchor-candidate',
      epoch: 0n,
      candidateRevision: 1,
    });
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(winner, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('recovers exact commits when a durable transaction rejects after commit', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);

    store.throwAfterNextTransaction = true;
    const coordinator = await bootstrap(value);
    expect(coordinator.publicState.epoch).toBe(0n);

    store.throwAfterNextTransaction = true;
    await expect(flushAndCollect(coordinator)).resolves.toHaveLength(1);
    expect(await coordinator.pendingOutboxCount()).toBe(0);

    store.throwAfterNextTransaction = true;
    await expect(
      createTransition(coordinator, control(3)),
    ).resolves.toMatchObject({ status: 'committed' });
    expect(value.provider.importCalls).toBe(0);

    const snapshot = (await delegate.load(storeKey))!;
    const anchor = (await value.rollbackAnchor.load(storeKey))!;
    expect(anchor.revision).toBe(snapshot.revision);
    expect(anchor.storeCommitment).toEqual(
      await groupSecurityStoreSnapshotCommitment(snapshot),
    );
    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value)),
    );
    expect(restored.publicState.epoch).toBe(1n);
  });

  test('rejects a no-op anchor response instead of claiming an ambiguity was durably poisoned', async () => {
    const delegate = new InMemoryGroupStateStore();
    const anchor = new ControlledRollbackAnchor();
    const winner = await context(delegate);
    winner.rollbackAnchor = anchor;
    const winnerCoordinator = await bootstrap(winner);
    await flushAndCollect(winnerCoordinator);
    const failingStore = new ReconciliationLoadFailureStore(delegate);
    const loserContext: TestContext = {
      ...winner,
      provider: new ContractTestProvider(),
      store: failingStore,
      authorization: new AuthorizationPolicy(winner.identities.actorId),
    };
    const loser = await GroupSecurityCoordinator.restore(config(loserContext));
    const losingTransition = createTransition(
      loser,
      control(0x53, 'update', id(0xd4)),
    );
    await failingStore.transactionEntered;
    await createTransition(
      winnerCoordinator,
      control(0x54, 'update', id(0xd5)),
    );
    anchor.noOpNextPoison = true;
    failingStore.release();

    await expect(losingTransition).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await anchor.load(storeKey))?.forkPoison).toBeUndefined();
    expect(() => loser.publicState).toThrow(/poisoned/);
  });

  test('retains terminal fork poison when the store audit transaction fails', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new FailOnceStore(delegate);
    const left = await context(store);
    const right: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: left.protector,
      identities: left.identities,
      authorization: new AuthorizationPolicy(left.identities.actorId),
      codec: left.codec,
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);
    await createTransition(leftCoordinator, control(2, 'update', id(0xd1)));
    await createTransition(rightCoordinator, control(3, 'update', id(0xd2)));
    await flushAndCollect(leftCoordinator);
    const [conflict] = await flushAndCollect(rightCoordinator);
    store.failNextTransaction = true;

    await expect(
      leftCoordinator.applyCommit(
        conflict.commit!,
        conflict.controlRecord,
        conflict.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect((await delegate.load(storeKey))?.forkEvidence).toBeUndefined();
    expect((await left.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();

    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(left, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('stops synchronous access as soon as anchor poison wins before audit persistence', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const left = await context(store);
    const right: TestContext = {
      ...left,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(left.identities.actorId),
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);
    await createTransition(leftCoordinator, control(0x55, 'update', id(0xd1)));
    await createTransition(rightCoordinator, control(0x56, 'update', id(0xd2)));
    await flushAndCollect(leftCoordinator);
    const [conflict] = await flushAndCollect(rightCoordinator);
    let auditEntered!: () => void;
    const auditStarted = new Promise<void>((resolve) => {
      auditEntered = resolve;
    });
    let releaseAudit!: () => void;
    const auditRelease = new Promise<void>((resolve) => {
      releaseAudit = resolve;
    });
    store.beforeNextTransaction = async () => {
      auditEntered();
      await auditRelease;
    };
    const applying = leftCoordinator.applyCommit(
      conflict.commit!,
      conflict.controlRecord,
      conflict.welcomes,
    );
    await auditStarted;
    expect(() => leftCoordinator.publicState).toThrow(/same-parent/);
    releaseAudit();
    await expect(applying).rejects.toMatchObject({ code: 'fork-detected' });
  });

  test('poisons an authenticated Add sibling before checking its missing Welcome', async () => {
    const left = await context();
    const right: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: left.protector,
      identities: left.identities,
      authorization: new AuthorizationPolicy(left.identities.actorId),
      codec: left.codec,
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);
    await createTransition(leftCoordinator, control(2, 'add', id(0xd1)));
    await createTransition(rightCoordinator, control(3, 'add', id(0xd2)));
    await flushAndCollect(leftCoordinator);
    const [conflict] = await flushAndCollect(rightCoordinator);
    expect(conflict.welcomes).toHaveLength(1);

    await expect(
      leftCoordinator.applyCommit(
        conflict.commit!,
        conflict.controlRecord,
        [],
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(left.provider.applyCommitCalls).toBe(0);
    expect((await left.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();
  });

  test('durably poisons a second authenticated genesis and rejects restart', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    const [genesis] = await flushAndCollect(coordinator);
    const alternateState = {
      ...publicState(0n),
      treeHash: id(0x99),
    };
    const original = genesis.controlRecord;
    const alternate = await signMembershipControlRecord(
      {
        version: original.version,
        protocol: { ...original.protocol },
        groupId: new Uint8Array(original.groupId),
        epoch: 0n,
        operationId: id(0x92),
        action: 'create',
        actorId: new Uint8Array(original.actorId),
        subjectId: new Uint8Array(original.subjectId),
        controlPayload: canonicalGroupSecurityState(alternateState),
      },
      value.identities.sign,
    );

    await expect(
      coordinator.applyCommit(undefined as never, alternate, []),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect((await value.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('poisons concurrent same-parent commits without requiring loser redelivery', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const firstProvider = new ContractTestProvider();
    const secondProvider = new ContractTestProvider();
    const first = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value, firstProvider)),
    );
    const second = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value, secondProvider)),
    );
    let arrivals = 0;
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await released;
    };
    firstProvider.createCommitBarrier = barrier;
    secondProvider.createCommitBarrier = barrier;
    const results = await Promise.allSettled([
      createTransition(first, control(2, 'update', id(0xd1))),
      createTransition(second, control(3, 'update', id(0xd2))),
    ]);

    expect(results.some((result) => result.status === 'rejected')).toBe(true);
    expect((await value.rollbackAnchor.load(storeKey))?.forkPoison).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('rejects a local provider delta or Welcome recipient that diverges from the requested signed control', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await value.store.load(storeKey);
    const localControl = control(2, 'update', id(0xd1));

    await expect(
      coordinator.createCommit({ changes: [] }, localControl),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(value.provider.createCommitCalls).toBe(0);

    value.provider.createDeltaOverride = {
      changes: [
        {
          kind: 'update',
          memberId: localControl.subjectId,
          keyPackageRef: id(0xfe),
        },
      ],
    };
    await expect(
      createTransition(coordinator, localControl),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await value.store.load(storeKey)).toEqual(before);

    value.provider.createDeltaOverride = undefined;
    const originalCreateCommit = value.provider.createCommit.bind(
      value.provider,
    );
    let deltaIteratorCalls = 0;
    value.provider.createCommit = async (input) => {
      const result = await originalCreateCommit(input);
      const changes = [...result.appliedMembership.changes];
      Object.defineProperty(changes, Symbol.iterator, {
        enumerable: false,
        value: function* () {
          deltaIteratorCalls += 1;
          throw new Error('hostile array iterator must not be consumed');
        },
      });
      return { ...result, appliedMembership: { changes } };
    };
    await expect(
      createTransition(coordinator, control(3, 'update', id(0xd2))),
    ).rejects.toThrow(/sparse or have extra properties/);
    expect(deltaIteratorCalls).toBe(0);
    expect(coordinator.publicState.epoch).toBe(0n);
    value.provider.createCommit = originalCreateCommit;

    value.provider.welcomeRecipientOverride = id(0xfd);
    await expect(
      createTransition(coordinator, control(4, 'add', id(0xd3))),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await value.store.load(storeKey)).toEqual(before);
  });

  test('rejects a receiving provider delta mismatch without advancing state and preserves received bindings across restart', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);

    const receivedControl = control(2, 'update', id(0xd4));
    await createTransition(sourceCoordinator, receivedControl);
    const [delivery] = await flushAndCollect(sourceCoordinator);
    const before = await target.store.load(storeKey);
    target.provider.applyDeltaOverride = {
      changes: [
        {
          kind: 'update',
          memberId: receivedControl.subjectId,
          keyPackageRef: id(0xfc),
        },
      ],
    };
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(targetCoordinator.publicState.epoch).toBe(0n);
    expect((await target.provider.getPublicState()).epoch).toBe(0n);
    expect(await target.store.load(storeKey)).toEqual(before);

    target.provider.applyDeltaOverride = undefined;
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'committed' });
    await flushAndCollect(targetCoordinator);

    const restartedProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(target, restartedProvider);
    restarted.authorization.requirePrevious = true;
    const restored = await GroupSecurityCoordinator.restore(config(restarted));
    expect(restored.publicState.epoch).toBe(1n);
    await expect(
      createTransition(restored, control(3, 'remove', receivedControl.subjectId)),
    ).resolves.toMatchObject({ status: 'committed' });
    expect(restarted.authorization.calls.at(-1)?.previousRecord?.epoch).toBe(1n);
  });

  test('times out a stalled outbox delivery without blocking later operations', async () => {
    const value = await context();
    const coordinator = await bootstrap(value, {
      outboxDeliveryTimeoutMs: 10,
    });
    let signal: AbortSignal | undefined;

    await expect(
      coordinator.flushOutbox(async (_delivery, deliverySignal) => {
        signal = deliverySignal;
        return new Promise<never>(() => undefined);
      }),
    ).rejects.toMatchObject({ code: 'delivery-failed' });
    expect(signal?.aborted).toBe(true);
    await expect(coordinator.pendingOutboxCount()).resolves.toBe(1);
  });

  test('intrinsically snapshots bounded outbox codec bytes before validation', async () => {
    const oversized = await context();
    oversized.codec.encode = () => {
      const payload = new Uint8Array(16 * 1024 * 1024 + 1);
      Object.defineProperty(payload, 'byteLength', { value: 1 });
      return payload;
    };
    await expect(bootstrap(oversized)).rejects.toMatchObject({
      code: 'control-mismatch',
    });
    expect(await oversized.store.load(storeKey)).toBeUndefined();

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = await context();
      const encode = shared.codec.encode.bind(shared.codec);
      shared.codec.encode = (delivery) => {
        const stable = encode(delivery);
        const payload = new Uint8Array(
          new SharedArrayBuffer(stable.byteLength),
        );
        payload.set(stable);
        Object.defineProperty(payload, 'buffer', {
          value: new ArrayBuffer(stable.byteLength),
        });
        return payload;
      };
      await expect(bootstrap(shared)).rejects.toMatchObject({
        code: 'control-mismatch',
      });
      expect(await shared.store.load(storeKey)).toBeUndefined();
    }
  });

  test('keeps sends retryable until an exact durable acceptance is returned', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));

    await expect(
      coordinator.flushOutbox(async () => {
        throw new Error('network unavailable');
      }),
    ).rejects.toMatchObject({ code: 'delivery-failed' });
    expect(await coordinator.pendingOutboxCount()).toBe(1);
    await expect(
      coordinator.flushOutbox(async () => undefined as never),
    ).rejects.toMatchObject({ code: 'delivery-failed' });
    expect(await coordinator.pendingOutboxCount()).toBe(1);
    await expect(
      coordinator.flushOutbox(async (delivery) => {
        const acceptance =
          await createGroupSecurityDurableAcceptance(delivery);
        acceptance.controlRecordId[0] ^= 0xff;
        return acceptance;
      }),
    ).rejects.toMatchObject({ code: 'delivery-failed' });
    expect(await coordinator.pendingOutboxCount()).toBe(1);
    await expect(
      coordinator.flushOutbox(async (delivery) => {
        const acceptance =
          await createGroupSecurityDurableAcceptance(delivery);
        return {
          ...acceptance,
          recipientKeyPackageRefs: [new Uint8Array([0xff])],
        };
      }),
    ).rejects.toMatchObject({ code: 'delivery-failed' });
    expect(await coordinator.pendingOutboxCount()).toBe(1);
    await expect(
      coordinator.flushOutbox((delivery) =>
        createGroupSecurityDurableAcceptance(delivery),
      ),
    ).resolves.toEqual({ delivered: 1, remaining: 0 });
    await expect(
      coordinator.flushOutbox(async () => {
        throw new Error('must not resend after ACK');
      }),
    ).resolves.toEqual({ delivered: 0, remaining: 0 });
  });

  test('enforces outbox/replay bounds and retains an authorization anchor while pruning stale replay', async () => {
    const outboxValue = await context();
    const outboxCoordinator = await bootstrap(outboxValue, {
      maxOutboxEntries: 1,
      maxReplayEntries: 2,
      replayWindowEpochs: 1n,
    });
    await expect(
      createTransition(outboxCoordinator, control(2)),
    ).rejects.toMatchObject({ code: 'outbox-overflow' });
    expect(outboxCoordinator.publicState.epoch).toBe(0n);

    const replayValue = await context();
    const replayCoordinator = await bootstrap(replayValue, {
      maxOutboxEntries: 4,
      maxReplayEntries: 2,
      replayWindowEpochs: 1n,
    });
    await createTransition(replayCoordinator, control(2));
    await expect(
      createTransition(replayCoordinator, control(3)),
    ).rejects.toMatchObject({ code: 'replay-overflow' });
    expect(replayCoordinator.publicState.epoch).toBe(1n);

    const pruneValue = await context();
    pruneValue.authorization.requirePrevious = true;
    const pruneCoordinator = await bootstrap(pruneValue, {
      maxOutboxEntries: 4,
      maxReplayEntries: 3,
      replayWindowEpochs: 2n,
    });
    await flushAndCollect(pruneCoordinator);
    const deliveries: GroupSecurityDelivery[] = [];
    for (let operation = 2; operation <= 5; operation++) {
      await createTransition(pruneCoordinator, control(operation));
      deliveries.push(...(await flushAndCollect(pruneCoordinator)));
    }
    const replay = (await pruneValue.store.load(storeKey))!.replay;
    expect(replay.map((entry) => entry.epoch)).toEqual([2n, 3n, 4n]);
    await expect(
      pruneCoordinator.applyCommit(
        deliveries[0].commit!,
        deliveries[0].controlRecord,
      ),
    ).rejects.toMatchObject({ code: 'stale-replay' });
    await expect(
      pruneCoordinator.applyCommit(
        deliveries[1].commit!,
        deliveries[1].controlRecord,
      ),
    ).resolves.toMatchObject({ status: 'duplicate' });
  });

  test('rejects a signature-only outbox mutation before calling send', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await mutateOnlyOutbox(value, (delivery) => ({
      ...delivery,
      controlRecord: {
        ...delivery.controlRecord,
        signature: new Uint8Array(delivery.controlRecord.signature.length),
      },
    }));
    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value)),
    );
    let sends = 0;
    await expect(
      restored.flushOutbox(async () => {
        sends += 1;
        return undefined as never;
      }),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(sends).toBe(0);
  });

  test('fully validates persisted Welcome metadata before delivery', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2, 'add'));
    await mutateOnlyOutbox(value, (delivery) => ({
      ...delivery,
      welcomes: [
        {
          ...delivery.welcomes[0],
          payload: new Uint8Array(delivery.welcomes[0].payload).fill(0xee),
        },
      ],
    }));
    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value)),
    );
    let sends = 0;
    await expect(
      restored.flushOutbox(async () => {
        sends += 1;
        return undefined as never;
      }),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(sends).toBe(0);
  });

  test('uses one bounded detached codec snapshot for validation and delivery', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2, 'add'));
    const decode = value.codec.decode.bind(value.codec);
    let mapReads = 0;
    value.codec.decode = (payload) => {
      const delivery = decode(payload);
      const validWelcomes = delivery.welcomes as GroupWelcome[];
      const tamperedWelcome: GroupWelcome = {
        ...validWelcomes[0],
        payload: new Uint8Array(validWelcomes[0].payload).fill(0xee),
      };
      const welcomes = new Proxy(validWelcomes, {
        get(target, property, receiver) {
          if (property === 'map') {
            mapReads += 1;
            return () => [tamperedWelcome];
          }
          return Reflect.get(target, property, receiver);
        },
      });
      return { ...delivery, welcomes };
    };

    let sent: GroupSecurityDelivery | undefined;
    await expect(
      coordinator.flushOutbox(async (delivery) => {
        sent = delivery;
        return createGroupSecurityDurableAcceptance(delivery);
      }),
    ).resolves.toEqual({ delivered: 1, remaining: 0 });
    expect(mapReads).toBe(0);
    expect(Array.from(sent!.welcomes[0].payload)).toEqual([0x55, 1]);
  });

  test('rejects tampered persisted actor authorization and broken linkage before provider import', async () => {
    const actorValue = await context();
    const actorCoordinator = await bootstrap(actorValue);
    await flushAndCollect(actorCoordinator);
    await createTransition(actorCoordinator, control(2));
    await flushAndCollect(actorCoordinator);
    await replaceReplayHead(actorValue, async (record) => {
      const { signature: _signature, ...unsignedRecord } = record;
      return signMembershipControlRecord(
        {
          ...unsignedRecord,
          actorId: actorValue.identities.attackerId,
        },
        async (payload, actorId) =>
          actorValue.identities.signAs(actorId, payload),
      );
    });
    const actorProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(actorValue, actorProvider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(actorProvider.importCalls).toBe(0);

    const linkValue = await context();
    const linkCoordinator = await bootstrap(linkValue);
    await flushAndCollect(linkCoordinator);
    await createTransition(linkCoordinator, control(2));
    await flushAndCollect(linkCoordinator);
    await replaceReplayHead(linkValue, async (record) =>
      {
        const { signature: _signature, ...unsignedRecord } = record;
        return signMembershipControlRecord(
          { ...unsignedRecord, parentRecordId: id(0xff) },
          linkValue.identities.sign,
        );
      },
    );
    const linkProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(linkValue, linkProvider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(linkProvider.importCalls).toBe(0);
  });

  test('rejects a tampered persisted control signature before provider import', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);
    await replaceReplayHead(value, async (record) => ({
      ...record,
      signature: new Uint8Array(record.signature.length),
    }));

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects a same-group/same-epoch encrypted-state fork not bound by the signed head', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);
    const forkedState: GroupSecurityPublicState = {
      ...publicState(1n),
      confirmedTranscriptHash: new Uint8Array(32).fill(0xee),
      treeHash: new Uint8Array(32).fill(0xdd),
    };
    const forkedEnvelope = await EncryptedGroupState.seal(
      forkedState,
      privateBytes(1n),
      value.protector,
    );
    await value.store.transaction(storeKey, (transaction) => {
      transaction.setEncryptedState(forkedEnvelope);
    });

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });
});

async function mutateOnlyOutbox(
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

async function advanceAnchorForUnchangedSecurityHead(
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
    throw new Error('test fixture cannot advance the unchanged rollback anchor');
  }
  if (
    !(await value.rollbackAnchor.advance(storeKey, current, {
      revision: snapshot.revision,
      epoch: current.epoch,
      controlHead: current.controlHead,
      storeCommitment:
        await groupSecurityStoreSnapshotCommitment(snapshot),
      forkPoison: undefined,
    }))
  ) {
    throw new Error('test fixture rollback anchor CAS failed');
  }
}

async function replaceReplayHead(
  value: TestContext,
  mutate: (
    record: MembershipControlRecord,
  ) => Promise<MembershipControlRecord>,
): Promise<void> {
  await value.store.transaction(storeKey, async (transaction) => {
    const head = [...transaction.replay].sort((a, b) =>
      a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0,
    ).at(-1)!;
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

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let index = 0; index < a.byteLength; index++) {
    if (a[index] !== b[index]) return false;
  }
  return true;
}

function toHex(bytes: Uint8Array): string {
  let value = '';
  for (let index = 0; index < bytes.byteLength; index++) {
    value += bytes[index].toString(16).padStart(2, '0');
  }
  return value;
}

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) {
    throw new Error('invalid test hex');
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
