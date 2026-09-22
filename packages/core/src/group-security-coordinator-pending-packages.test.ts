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
  id,
  ContractTestProvider,
  privateBytes,
  privateKeyPackageBytes,
  overrideEnvelopeAlgorithm,
  AdversarialStore,
  context,
  config,
  bootstrap,
  cloneContextWithProvider,
  createInvitation,
} from './__mocks__/group-security-coordinator.js';

describe('GroupSecurityCoordinator pending-packages', () => {
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
    expect(snapshot.pendingKeyPackages[0].serialize()).toEqual(
      first.serialize(),
    );
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
      GroupSecurityCoordinator.createPendingKeyPackage(config(memberValue), {
        operationId: id(0xd6),
        groupId,
        memberId: id(0x51),
        credential: id(0x51),
      }),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(memberIteratorReads).toBe(0);
    expect(memberValue.provider.clearKeyPackageCalls).toBe(1);
    expect(await memberValue.store.load(storeKey)).toBeUndefined();

    const requestValue = await context();
    let requestIteratorReads = 0;
    requestValue.provider.authenticateKeyPackageRequestCommitment = async () =>
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
      GroupSecurityCoordinator.createPendingKeyPackage(config(requestValue), {
        operationId: id(0xd7),
        groupId,
        memberId: id(0x52),
        credential: id(0x52),
      }),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(requestIteratorReads).toBe(0);
    expect(requestValue.provider.clearKeyPackageCalls).toBe(1);
    expect(await requestValue.store.load(storeKey)).toBeUndefined();

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedValue = await context();
      sharedValue.provider.authenticateKeyPackageRequestCommitment = async () =>
        new Uint8Array(new SharedArrayBuffer(32));
      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(config(sharedValue), {
          operationId: id(0xd8),
          groupId,
          memberId: id(0x53),
          credential: id(0x53),
        }),
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
                  throw new Error('hostile byte iterator must not be consumed');
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
        GroupSecurityCoordinator.createPendingKeyPackage(config(value), input),
      ).rejects.toMatchObject({ code: 'rollback-unavailable' });
      expect(hostileReads).toBe(0);
      expect(retainedReference).toBeDefined();
      expect(value.provider.hasPendingKeyPackage(retainedReference!)).toBe(
        true,
      );
      expect(value.provider.clearKeyPackageCalls).toBe(0);
      expect(await value.store.load(storeKey)).toBeUndefined();

      await expect(
        GroupSecurityCoordinator.createPendingKeyPackage(config(value), input),
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
    const extensions = new HostileExtensions([[7, new Uint8Array([0x61])]]);
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
      GroupSecurityCoordinator.createPendingKeyPackage(config(value), request),
    ).rejects.toThrow(/timeout after durable commit/);
    const committed = (await delegate.load(storeKey))!;
    expect(committed.pendingKeyPackages).toHaveLength(1);
    expect(committed.pendingKeyPackageRequests).toHaveLength(1);
    const committedPackage = committed.pendingKeyPackages[0].keyPackage;
    expect(
      value.provider.hasPendingKeyPackage(committedPackage.reference),
    ).toBe(false);

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
    expect(
      (await value.store.load(storeKey))?.pendingKeyPackages ?? [],
    ).toEqual([]);
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
});
