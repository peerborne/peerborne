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
  canonicalGroupSecurityCommit,
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
  UnsignedMembershipControlRecord,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
  signMembershipControlRecord,
} from './membership-control-record.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';
import {
  protocol,
  groupId,
  storeKey,
  createGroupInput,
  id,
  publicState,
  ContractTestProvider,
  AuthorizationPolicy,
  StaticSnapshotStore,
  TestContext,
  context,
  config,
  bootstrap,
  cloneContextWithProvider,
} from './__mocks__/group-security-coordinator.js';

describe('GroupSecurityCoordinator bootstrap', () => {
  test('rejects accessor-backed config without invoking getters', async () => {
    const value = await context();
    let providerGetterCalls = 0;
    const accessorConfig = { ...config(value) };
    Object.defineProperty(accessorConfig, 'provider', {
      enumerable: true,
      get() {
        providerGetterCalls += 1;
        return value.provider;
      },
    });

    await expect(
      GroupSecurityCoordinator.bootstrap(accessorConfig, createGroupInput, {
        operationId: id(1),
        subjectId: value.identities.actorId,
      }),
    ).rejects.toThrow(/own data properties/);
    expect(providerGetterCalls).toBe(0);
    expect(value.provider.createGroupCalls).toBe(0);
  });

  test('uses one own-data config snapshot when a Proxy swaps field reads', async () => {
    const value = await context();
    const substitutedProvider = new ContractTestProvider();
    const mutableActorId = new Uint8Array(value.identities.actorId);
    const mutableProtocol = { ...protocol };
    const protocolDescriptorReads = new Map<PropertyKey, number>();
    const storeKeyDescriptorReads = new Map<PropertyKey, number>();
    const configDescriptorReads = new Map<PropertyKey, number>();
    const mutableStoreKey = {
      protocol: new Proxy(mutableProtocol, {
        get() {
          throw new Error('protocol fields must use descriptor snapshots');
        },
        getOwnPropertyDescriptor(target, property) {
          protocolDescriptorReads.set(
            property,
            (protocolDescriptorReads.get(property) ?? 0) + 1,
          );
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      }),
      groupId: new Uint8Array(groupId),
    };
    let providerReads = 0;
    const target = {
      ...config(value),
      actorId: mutableActorId,
      storeKey: new Proxy(mutableStoreKey, {
        get() {
          throw new Error('store-key fields must use descriptor snapshots');
        },
        getOwnPropertyDescriptor(current, property) {
          storeKeyDescriptorReads.set(
            property,
            (storeKeyDescriptorReads.get(property) ?? 0) + 1,
          );
          return Reflect.getOwnPropertyDescriptor(current, property);
        },
      }),
    };
    let configReads = 0;
    const proxiedConfig = new Proxy(target, {
      get(current, property, receiver) {
        configReads += 1;
        if (property === 'provider') {
          providerReads += 1;
          return providerReads === 1 ? value.provider : substitutedProvider;
        }
        return Reflect.get(current, property, receiver);
      },
      getOwnPropertyDescriptor(current, property) {
        configDescriptorReads.set(
          property,
          (configDescriptorReads.get(property) ?? 0) + 1,
        );
        return Reflect.getOwnPropertyDescriptor(current, property);
      },
    });

    const coordinator = await GroupSecurityCoordinator.bootstrap(
      proxiedConfig,
      createGroupInput,
      { operationId: id(1), subjectId: value.identities.actorId },
    );

    expect(coordinator.publicState.groupId).toEqual(groupId);
    expect(configReads).toBe(0);
    expect(providerReads).toBe(0);
    expect(value.provider.createGroupCalls).toBe(1);
    expect(substitutedProvider.createGroupCalls).toBe(0);
    for (const property of Reflect.ownKeys(target)) {
      expect(configDescriptorReads.get(property)).toBe(1);
    }
    for (const property of Reflect.ownKeys(mutableStoreKey)) {
      expect(storeKeyDescriptorReads.get(property)).toBe(1);
    }
    for (const property of Reflect.ownKeys(mutableProtocol)) {
      expect(protocolDescriptorReads.get(property)).toBe(1);
    }

    Object.defineProperties(target, {
      maxOutboxEntries: { enumerable: true, value: 1 },
      provider: { enumerable: true, value: substitutedProvider },
    });
    mutableActorId.fill(0);
    mutableStoreKey.groupId.fill(0);
    mutableProtocol.id = 'mutated.protocol';
    const captured = coordinator as unknown as {
      actorId: Uint8Array;
      maxOutboxEntries: number;
      provider: GroupSecurityProvider;
      storeKey: GroupStateStoreKey;
    };
    expect(captured.actorId).toEqual(value.identities.actorId);
    expect(captured.maxOutboxEntries).toBe(8);
    expect(captured.provider).toBe(value.provider);
    expect(captured.storeKey).toEqual(storeKey);
  });

  test('accepts genuine cross-realm Uint8Array configuration bytes', async () => {
    const value = await context();
    const crossRealmGroupId = runInNewContext('new Uint8Array(bytes)', {
      bytes: Array.from(groupId),
    }) as Uint8Array;
    const crossRealmActorId = runInNewContext('new Uint8Array(bytes)', {
      bytes: Array.from(value.identities.actorId),
    }) as Uint8Array;
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
          authorizeControl:
            (async () => ({})) as unknown as MembershipControlAuthorizer,
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

  test('rejects a bootstrap group mismatch before consulting the provider lifecycle', async () => {
    const value = await context();

    await expect(
      GroupSecurityCoordinator.bootstrap(
        config(value),
        { ...createGroupInput, groupId: new Uint8Array([0xff]) },
        { operationId: id(1), subjectId: value.identities.actorId },
      ),
    ).rejects.toMatchObject({ code: 'group-mismatch' });
    expect(value.provider.hasActiveGroupCalls).toBe(0);
    expect(value.provider.createGroupCalls).toBe(0);
    expect(value.provider.clearCalls).toBe(0);
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
        authenticatedCreatorMemberId: created.authenticatedCreatorMemberId,
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
        outbox: [
          {
            id: id(0x91),
            epoch: 0n,
            kind: GROUP_SECURITY_OUTBOX_KIND,
            payload: new Uint8Array([1]),
            createdAt: 1,
          },
        ],
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
      GroupSecurityCoordinator.bootstrap(config(value), createGroupInput, {
        operationId: id(1),
        subjectId: value.identities.attackerId,
      }),
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
      storeCommitment: await groupSecurityStoreSnapshotCommitment(
        snapshot,
        storeKey,
      ),
      forkPoison: undefined,
    });
  });
});
