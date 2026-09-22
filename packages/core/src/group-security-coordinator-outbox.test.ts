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
  storeKey,
  publicState,
  context,
  config,
  bootstrap,
  control,
  createTransition,
  flushAndCollect,
  cloneContextWithProvider,
  mutateOnlyOutbox,
} from './__mocks__/group-security-coordinator.js';

describe('GroupSecurityCoordinator outbox', () => {
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
        const acceptance = await createGroupSecurityDurableAcceptance(delivery);
        acceptance.controlRecordId[0] ^= 0xff;
        return acceptance;
      }),
    ).rejects.toMatchObject({ code: 'delivery-failed' });
    expect(await coordinator.pendingOutboxCount()).toBe(1);
    await expect(
      coordinator.flushOutbox(async (delivery) => {
        const acceptance = await createGroupSecurityDurableAcceptance(delivery);
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
});
