import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
  GroupKeyPackage,
  GroupStateProtector,
  GroupSecurityPublicState,
} from './group-security-provider.js';
import {
  GroupStateOutboxEntry,
  GroupStateForkEvidence,
  GroupStateStoreKey,
  GroupStateStoreTransaction,
  InMemoryGroupStateStore,
  MAX_CONSUMED_KEY_PACKAGE_MARKERS,
  MAX_GROUP_STATE_STORE_COMMITTED_BYTES,
  MAX_PENDING_KEY_PACKAGE_ENTRIES,
} from './group-state-store.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';

const protocol = { id: 'store.test', version: 1 };
const key: GroupStateStoreKey = {
  protocol,
  groupId: new Uint8Array([1, 2, 3]),
};

function id(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

function state(epoch: bigint): GroupSecurityPublicState {
  return {
    protocol,
    groupId: key.groupId,
    epoch,
    confirmedTranscriptHash: new Uint8Array(32).fill(
      Number((epoch + 1n) & 0xffn),
    ),
    treeHash: new Uint8Array(32).fill(Number((epoch + 2n) & 0xffn)),
  };
}

function outbox(value: number, epoch: bigint): GroupStateOutboxEntry {
  return {
    id: id(value),
    kind: 'group.transition',
    epoch,
    payload: new Uint8Array([value]),
    createdAt: 1000 + value,
  };
}

function keyPackage(
  reference: Uint8Array,
  payload: Uint8Array = new Uint8Array([0xa1]),
  keyPackageProtocol = protocol,
  keyPackageGroupId: Uint8Array = key.groupId,
): GroupKeyPackage {
  return {
    protocol: keyPackageProtocol,
    groupId: new Uint8Array(keyPackageGroupId),
    reference,
    payload,
  };
}

async function encryptedKeyPackage(
  reference: Uint8Array,
  privateState: Uint8Array,
  protector: GroupStateProtector,
  payload?: Uint8Array,
  keyPackageProtocol = protocol,
  keyPackageGroupId: Uint8Array = key.groupId,
): Promise<EncryptedKeyPackageState> {
  return EncryptedKeyPackageState.seal(
    keyPackage(
      reference,
      payload,
      keyPackageProtocol,
      keyPackageGroupId,
    ),
    privateState,
    protector,
  );
}

function forkEvidence(
  first = 0x21,
  second = 0x22,
): GroupStateForkEvidence {
  return {
    epoch: 1n,
    parentRecordId: id(0x20),
    firstRecordId: id(first),
    firstControlRecord: new Uint8Array([first, 1]),
    secondRecordId: id(second),
    secondControlRecord: new Uint8Array([second, 2]),
  };
}

describe('InMemoryGroupStateStore', () => {
  test('atomically stores only encrypted state with outbox and replay metadata', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const encrypted = await EncryptedGroupState.seal(
      state(1n),
      new Uint8Array([0xaa]),
      protector,
    );
    await store.transaction(key, (transaction) => {
      transaction.setEncryptedState(encrypted);
      transaction.enqueueOutbox(outbox(1, 1n));
      transaction.markReplay({
        recordId: id(2),
        operationId: id(3),
        epoch: 1n,
        controlRecord: new Uint8Array([4, 5, 6]),
      });
    });

    const loaded = await store.load(key);
    expect(loaded).toMatchObject({ revision: 1 });
    expect(loaded?.outbox).toHaveLength(1);
    expect(loaded?.replay).toHaveLength(1);
    await expect(loaded?.encryptedState?.open(protector)).resolves.toEqual(
      new Uint8Array([0xaa]),
    );
  });

  test('rolls back state, outbox, and replay if the callback throws', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const initial = await EncryptedGroupState.seal(
      state(0n),
      new Uint8Array([0]),
      protector,
    );
    await store.transaction(key, (transaction) => {
      transaction.setEncryptedState(initial);
    });
    const next = await EncryptedGroupState.seal(
      state(1n),
      new Uint8Array([1]),
      protector,
    );

    await expect(
      store.transaction(key, (transaction) => {
        transaction.setEncryptedState(next);
        transaction.enqueueOutbox(outbox(4, 1n));
        transaction.markReplay({
          recordId: id(5),
          epoch: 1n,
          controlRecord: new Uint8Array([5]),
        });
        throw new Error('injected failure');
      }),
    ).rejects.toThrow(/injected failure/);
    expect((await store.load(key))?.revision).toBe(1);
    expect((await store.load(key))?.encryptedState?.state.epoch).toBe(0n);
    expect((await store.load(key))?.outbox).toEqual([]);
  });

  test('rejects plaintext and structural lookalikes at the store boundary', async () => {
    const store = new InMemoryGroupStateStore();
    await expect(
      store.transaction(key, (transaction) => {
        transaction.setEncryptedState(
          new Uint8Array([1, 2]) as unknown as EncryptedGroupState,
        );
      }),
    ).rejects.toThrow(/plaintext private state is forbidden/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage({
          keyPackage: keyPackage(new Uint8Array([1])),
          nonce: new Uint8Array([2]),
          ciphertext: new Uint8Array([3]),
        } as unknown as EncryptedKeyPackageState);
      }),
    ).rejects.toThrow(/plaintext private KeyPackage state is forbidden/);
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const malformed = await encryptedKeyPackage(
      new Uint8Array([4]),
      new Uint8Array([5]),
      protector,
    );
    const canonical = malformed.serialize();
    const trailing = new Uint8Array(canonical.byteLength + 1);
    trailing.set(canonical);
    Object.defineProperty(malformed, 'serialize', {
      value: () => trailing,
    });
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(malformed);
      }),
    ).rejects.toThrow(/EncryptedKeyPackageState/);
    await expect(store.load(key)).resolves.toBeUndefined();
  });

  test('persists pending encrypted KeyPackages before group state with strict defensive cloning', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const reference = new Uint8Array([0x31, 0x32]);
    const privateState = new TextEncoder().encode('private one-time key');
    const envelope = await encryptedKeyPackage(
      reference,
      privateState,
      protector,
    );

    await store.transaction(key, (transaction) => {
      expect(transaction.putPendingKeyPackage(envelope)).toBe(true);
      expect(
        transaction.putPendingKeyPackage(
          EncryptedKeyPackageState.deserialize(envelope.serialize()),
        ),
      ).toBe(false);
      expect(transaction.getPendingKeyPackage(reference)?.serialize()).toEqual(
        envelope.serialize(),
      );
      expect(
        transaction.bindPendingKeyPackageRequest({
          operationId: id(0x33),
          requestCommitment: id(0x34),
          keyPackageReference: reference,
        }),
      ).toBe(true);
    });

    const loaded = await store.load(key);
    expect(loaded).toMatchObject({ revision: 1, encryptedState: undefined });
    expect(loaded?.pendingKeyPackages).toHaveLength(1);
    expect(loaded?.pendingKeyPackages[0]).not.toBe(envelope);
    await expect(
      loaded?.pendingKeyPackages[0].open(protector),
    ).resolves.toEqual(privateState);
    expect(new TextDecoder().decode(loaded?.pendingKeyPackages[0].serialize()))
      .not.toContain('private one-time key');

    const exposed = loaded!.pendingKeyPackages[0].keyPackage;
    exposed.reference.fill(0xff);
    const serialized = loaded!.pendingKeyPackages[0].serialize();
    serialized.fill(0xff);
    expect(
      (await store.load(key))?.pendingKeyPackages[0].keyPackage.reference,
    ).toEqual(reference);
  });

  test('atomically binds pending KeyPackages to one stable request operation', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const reference = new Uint8Array([0x35]);
    const envelope = await encryptedKeyPackage(
      reference,
      new Uint8Array([0x36]),
      protector,
    );
    const request = {
      operationId: id(0x37),
      requestCommitment: id(0x38),
      keyPackageReference: reference,
    };

    await store.transaction(key, (transaction) => {
      expect(transaction.putPendingKeyPackage(envelope)).toBe(true);
      expect(transaction.bindPendingKeyPackageRequest(request)).toBe(true);
      expect(transaction.bindPendingKeyPackageRequest(request)).toBe(false);
      expect(
        transaction.getPendingKeyPackageRequest(request.operationId),
      ).toEqual(request);
    });
    const loaded = (await store.load(key))!;
    expect(loaded.pendingKeyPackageRequests).toEqual([request]);
    loaded.pendingKeyPackageRequests[0].requestCommitment.fill(0xff);
    expect(
      (await store.load(key))?.pendingKeyPackageRequests[0]
        .requestCommitment,
    ).toEqual(request.requestCommitment);

    await expect(
      store.transaction(key, (transaction) => {
        transaction.bindPendingKeyPackageRequest({
          ...request,
          requestCommitment: id(0x39),
        });
      }),
    ).rejects.toThrow(/different request binding/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.bindPendingKeyPackageRequest({
          ...request,
          operationId: id(0x3a),
        });
      }),
    ).rejects.toThrow(/another operationId/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.bindPendingKeyPackageRequest({
          operationId: id(0x3b),
          requestCommitment: id(0x3c),
          keyPackageReference: new Uint8Array([0xff]),
        });
      }),
    ).rejects.toThrow(/missing encrypted state/);
    expect((await store.load(key))?.revision).toBe(1);
  });

  test('rejects an unbound pending KeyPackage without committing it', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const envelope = await encryptedKeyPackage(
      new Uint8Array([0x3d]),
      new Uint8Array([0x3e]),
      protector,
    );

    await expect(
      store.transaction(key, (transaction) => {
        expect(transaction.putPendingKeyPackage(envelope)).toBe(true);
      }),
    ).rejects.toThrow(/exactly one request binding/);
    await expect(store.load(key)).resolves.toBeUndefined();
  });

  test('rejects conflicting references and protocol/group mismatches without changing revision', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const reference = new Uint8Array([0x41]);
    const original = await encryptedKeyPackage(
      reference,
      new Uint8Array([1]),
      protector,
    );
    const conflicting = await encryptedKeyPackage(
      reference,
      new Uint8Array([2]),
      protector,
      new Uint8Array([0xb2]),
    );
    const wrongProtocol = await encryptedKeyPackage(
      new Uint8Array([0x42]),
      new Uint8Array([3]),
      protector,
      undefined,
      { id: 'other.protocol', version: 1 },
    );
    const wrongGroup = await encryptedKeyPackage(
      new Uint8Array([0x43]),
      new Uint8Array([4]),
      protector,
      undefined,
      protocol,
      new Uint8Array([0xff]),
    );
    await store.transaction(key, (transaction) => {
      transaction.putPendingKeyPackage(original);
      transaction.bindPendingKeyPackageRequest({
        operationId: id(0x44),
        requestCommitment: id(0x45),
        keyPackageReference: reference,
      });
    });

    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(conflicting);
      }),
    ).rejects.toThrow(/different encrypted content/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(wrongProtocol);
      }),
    ).rejects.toThrow(/protocol does not match/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(wrongGroup);
      }),
    ).rejects.toThrow(/groupId does not match/);

    expect((await store.load(key))?.revision).toBe(1);
    expect((await store.load(key))?.pendingKeyPackages).toHaveLength(1);
  });

  test('atomically consumes a pending KeyPackage and retains an irreversible replay marker', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const reference = new Uint8Array([0x51, 0x52]);
    const privateState = new Uint8Array([9, 8, 7]);
    const envelope = await encryptedKeyPackage(
      reference,
      privateState,
      protector,
    );
    await store.transaction(key, (transaction) => {
      transaction.putPendingKeyPackage(envelope);
      transaction.bindPendingKeyPackageRequest({
        operationId: id(0x53),
        requestCommitment: id(0x54),
        keyPackageReference: reference,
      });
    });

    await expect(
      store.transaction(key, (transaction) => {
        transaction.consumePendingKeyPackage(reference);
      }),
    ).rejects.toThrow(/without encrypted group state/);
    expect((await store.load(key))?.pendingKeyPackages).toHaveLength(1);
    expect((await store.load(key))?.revision).toBe(1);

    const encrypted = await EncryptedGroupState.seal(
      state(1n),
      new Uint8Array([0xaa]),
      protector,
    );
    let consumed: EncryptedKeyPackageState | undefined;
    await store.transaction(key, (transaction) => {
      transaction.setEncryptedState(encrypted);
      consumed = transaction.consumePendingKeyPackage(reference);
      expect(transaction.getPendingKeyPackage(reference)).toBeUndefined();
      expect(transaction.hasConsumedKeyPackage(reference)).toBe(true);
    });
    await expect(consumed?.open(protector)).resolves.toEqual(privateState);

    const loaded = await store.load(key);
    expect(loaded?.pendingKeyPackages).toEqual([]);
    expect(loaded?.pendingKeyPackageRequests).toEqual([]);
    expect(loaded?.consumedKeyPackageRefs).toEqual([reference]);
    loaded!.consumedKeyPackageRefs[0].fill(0xff);
    expect((await store.load(key))?.consumedKeyPackageRefs).toEqual([
      reference,
    ]);

    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(envelope);
      }),
    ).rejects.toThrow(/already been consumed/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.consumePendingKeyPackage(reference);
      }),
    ).rejects.toThrow(/already been consumed/);
    expect((await store.load(key))?.revision).toBe(2);
  });

  test('bounds pending KeyPackages without evicting an earlier package', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const envelopes = await Promise.all(
      Array.from({ length: MAX_PENDING_KEY_PACKAGE_ENTRIES + 1 }, (_, index) =>
        encryptedKeyPackage(
          new Uint8Array([index + 1]),
          new Uint8Array([index + 2]),
          protector,
        ),
      ),
    );
    await store.transaction(key, (transaction) => {
      for (const [index, envelope] of envelopes.slice(0, -1).entries()) {
        transaction.putPendingKeyPackage(envelope);
        transaction.bindPendingKeyPackageRequest({
          operationId: id(index + 1),
          requestCommitment: id(index + 0x80),
          keyPackageReference: envelope.keyPackage.reference,
        });
      }
    });
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(envelopes.at(-1)!);
      }),
    ).rejects.toThrow(/pending KeyPackage entry limit/);

    const loaded = await store.load(key);
    expect(loaded?.revision).toBe(1);
    expect(loaded?.pendingKeyPackages).toHaveLength(
      MAX_PENDING_KEY_PACKAGE_ENTRIES,
    );
    expect(loaded?.pendingKeyPackages[0].keyPackage.reference).toEqual(
      new Uint8Array([1]),
    );
  });

  test('uses revision zero for absence and increments only successful transactions', async () => {
    const store = new InMemoryGroupStateStore();
    const failedBaseRevisions: number[] = [];
    await expect(
      store.transaction(key, (transaction) => {
        failedBaseRevisions.push(transaction.baseRevision);
        throw new Error('fail while absent');
      }),
    ).rejects.toThrow(/fail while absent/);
    await expect(store.load(key)).resolves.toBeUndefined();

    const firstResult = await store.transaction(key, (transaction) => {
      expect(transaction.baseRevision).toBe(0);
      return 'committed';
    });
    expect(firstResult).toBe('committed');
    expect((await store.load(key))?.revision).toBe(1);

    await expect(
      store.transaction(key, (transaction) => {
        failedBaseRevisions.push(transaction.baseRevision);
        throw new Error('fail after commit');
      }),
    ).rejects.toThrow(/fail after commit/);
    expect((await store.load(key))?.revision).toBe(1);

    await store.transaction(key, (transaction) => {
      expect(transaction.baseRevision).toBe(1);
    });
    expect((await store.load(key))?.revision).toBe(2);
    expect(failedBaseRevisions).toEqual([0, 1]);
  });

  test('fails closed at the consumed-marker bound without evicting prior markers', async () => {
    const store = new InMemoryGroupStateStore();
    const stateProtector = await WebCryptoGroupStateProtector.generate(
      'store-key',
    );
    const markerProtector: GroupStateProtector = {
      algorithm: 'TEST-ONLY',
      keyId: 'marker-bound',
      seal: async () => ({
        nonce: new Uint8Array([1]),
        ciphertext: new Uint8Array([2]),
      }),
      open: async () => new Uint8Array([3]),
    };
    const references = Array.from(
      { length: MAX_CONSUMED_KEY_PACKAGE_MARKERS + 1 },
      (_, index) => {
        const reference = new Uint8Array(4);
        new DataView(reference.buffer).setUint32(0, index, false);
        return reference;
      },
    );
    const envelopes = await Promise.all(
      references.map((reference) =>
        encryptedKeyPackage(
          reference,
          new Uint8Array([9]),
          markerProtector,
        ),
      ),
    );
    const encrypted = await EncryptedGroupState.seal(
      state(1n),
      new Uint8Array([1]),
      stateProtector,
    );

    await store.transaction(key, (transaction) => {
      transaction.setEncryptedState(encrypted);
      for (let index = 0; index < MAX_CONSUMED_KEY_PACKAGE_MARKERS; index++) {
        transaction.putPendingKeyPackage(envelopes[index]);
        transaction.consumePendingKeyPackage(references[index]);
      }
    });

    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(envelopes.at(-1)!);
        transaction.consumePendingKeyPackage(references.at(-1)!);
      }),
    ).rejects.toThrow(/marker limit reached/);

    const loaded = await store.load(key);
    expect(loaded?.revision).toBe(1);
    expect(loaded?.pendingKeyPackages).toEqual([]);
    expect(loaded?.consumedKeyPackageRefs).toHaveLength(
      MAX_CONSUMED_KEY_PACKAGE_MARKERS,
    );
    expect(loaded?.consumedKeyPackageRefs[0]).toEqual(references[0]);
  });

  test('serializes concurrent transactions without losing writes', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    await store.transaction(key, async (transaction) => {
      transaction.setEncryptedState(
        await EncryptedGroupState.seal(
          state(2n),
          new Uint8Array([2]),
          protector,
        ),
      );
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const revisions: number[] = [];
    const first = store.transaction(key, async (transaction) => {
      revisions.push(transaction.baseRevision);
      await gate;
      transaction.enqueueOutbox(outbox(6, 2n));
    });
    const second = store.transaction(key, (transaction) => {
      revisions.push(transaction.baseRevision);
      transaction.enqueueOutbox(outbox(7, 2n));
    });
    await Promise.resolve();
    release();
    await Promise.all([first, second]);

    expect(revisions).toEqual([1, 2]);
    expect((await store.load(key))?.outbox.map((entry) => entry.id[0])).toEqual([
      6, 7,
    ]);
  });

  test('removing replay metadata safely releases its operation identity', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    await store.transaction(key, async (transaction) => {
      transaction.setEncryptedState(
        await EncryptedGroupState.seal(
          state(2n),
          new Uint8Array([2]),
          protector,
        ),
      );
      transaction.markReplay({
        recordId: id(8),
        operationId: id(9),
        epoch: 1n,
        controlRecord: new Uint8Array([8]),
      });
      expect(transaction.removeReplay(id(8))).toBe(true);
      expect(transaction.removeReplay(id(8))).toBe(false);
      expect(
        transaction.markReplay({
          recordId: id(10),
          operationId: id(9),
          epoch: 2n,
          controlRecord: new Uint8Array([10]),
        }),
      ).toBe(true);
    });
    expect((await store.load(key))?.replay[0].recordId).toEqual(id(10));
  });

  test('returns defensive snapshots and invalidates escaped transactions', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    let escaped: GroupStateStoreTransaction | undefined;
    await store.transaction(key, async (transaction) => {
      escaped = transaction;
      transaction.setEncryptedState(
        await EncryptedGroupState.seal(
          state(1n),
          new Uint8Array([1]),
          protector,
        ),
      );
      transaction.enqueueOutbox(outbox(11, 1n));
    });
    const snapshot = await store.load(key);
    snapshot!.outbox[0].payload[0] = 0xff;
    snapshot!.encryptedState!.state.groupId[0] = 0xff;

    expect((await store.load(key))?.outbox[0].payload).toEqual(
      new Uint8Array([11]),
    );
    expect((await store.load(key))?.encryptedState?.state.groupId).toEqual(
      key.groupId,
    );
    expect(() => escaped!.removeOutbox(id(11))).toThrow(/no longer active/);
  });

  test('rejects state rollback, future metadata, and conflicting identities', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const encrypted = async (epoch: bigint) =>
      EncryptedGroupState.seal(
        state(epoch),
        new Uint8Array([Number(epoch & 0xffn)]),
        protector,
      );
    await store.transaction(key, async (transaction) => {
      transaction.setEncryptedState(await encrypted(4n));
      transaction.markReplay({
        recordId: id(12),
        operationId: id(13),
        epoch: 4n,
        controlRecord: new Uint8Array([12]),
      });
    });

    await expect(
      store.transaction(key, async (transaction) => {
        transaction.setEncryptedState(await encrypted(3n));
      }),
    ).rejects.toThrow(/rollback/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.enqueueOutbox(outbox(14, 5n));
      }),
    ).rejects.toThrow(/newer than encrypted state/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.markReplay({
          recordId: id(15),
          operationId: id(13),
          epoch: 4n,
          controlRecord: new Uint8Array([15]),
        });
      }),
    ).rejects.toThrow(/different replay recordId/);
  });

  test('durably normalizes and defensively clones irreversible fork evidence', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const evidence = forkEvidence(0x22, 0x21);
    await store.transaction(key, async (transaction) => {
      transaction.setEncryptedState(
        await EncryptedGroupState.seal(
          state(1n),
          new Uint8Array([1]),
          protector,
        ),
      );
      expect(transaction.markFork(evidence)).toBe(true);
    });
    evidence.parentRecordId.fill(0xee);
    evidence.firstRecordId.fill(0xee);
    evidence.firstControlRecord.fill(0xee);

    const loaded = await store.load(key);
    expect(loaded?.forkEvidence?.firstRecordId).toEqual(id(0x21));
    expect(loaded?.forkEvidence?.secondRecordId).toEqual(id(0x22));
    loaded!.forkEvidence!.firstControlRecord.fill(0xdd);
    expect((await store.load(key))?.forkEvidence?.firstControlRecord).toEqual(
      new Uint8Array([0x21, 2]),
    );

    await store.transaction(key, (transaction) => {
      expect(transaction.markFork(forkEvidence(0x22, 0x21))).toBe(false);
    });
    await expect(
      store.transaction(key, (transaction) => {
        transaction.markFork(forkEvidence(0x21, 0x23));
      }),
    ).rejects.toThrow(/different fork evidence/);
    expect((await store.load(key))?.forkEvidence).toBeDefined();
  });

  test('uses intrinsic typed-array metadata and rejects shared backing buffers', async () => {
    const store = new InMemoryGroupStateStore();
    const shadowedGroupId = new Uint8Array(key.groupId);
    Object.defineProperty(shadowedGroupId, 'byteLength', { value: 999 });
    Object.defineProperty(shadowedGroupId, 'buffer', {
      get: () => {
        throw new Error('shadow buffer getter must not run');
      },
    });
    await store.transaction(
      { protocol: { ...protocol }, groupId: shadowedGroupId },
      () => undefined,
    );
    expect((await store.load(key))?.revision).toBe(1);

    const shortId = new Uint8Array(31);
    Object.defineProperty(shortId, 'byteLength', { value: 32 });
    await expect(
      store.transaction(key, (transaction) => {
        transaction.enqueueOutbox({
          ...outbox(0x61, 0n),
          id: shortId,
        });
      }),
    ).rejects.toThrow(/invalid length or backing buffer/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedPayload = new Uint8Array(new SharedArrayBuffer(1));
      sharedPayload[0] = 0x62;
      Object.defineProperty(sharedPayload, 'buffer', {
        value: new ArrayBuffer(1),
      });
      await expect(
        store.transaction(key, (transaction) => {
          transaction.enqueueOutbox({
            ...outbox(0x62, 0n),
            payload: sharedPayload,
          });
        }),
      ).rejects.toThrow(/invalid length or backing buffer/);
    }
    expect((await store.load(key))?.revision).toBe(1);
  });

  test('accepts genuine cross-realm bytes and keeps detached snapshots', async () => {
    const store = new InMemoryGroupStateStore();
    const crossRealmGroupId = runInNewContext(
      'new Uint8Array([1, 2, 3])',
    ) as Uint8Array;
    const crossRealmId = runInNewContext(
      'new Uint8Array(32).fill(0x71)',
    ) as Uint8Array;
    const crossRealmPayload = runInNewContext(
      'new Uint8Array([0x72, 0x73])',
    ) as Uint8Array;
    expect(crossRealmGroupId instanceof Uint8Array).toBe(false);
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const encrypted = await EncryptedGroupState.seal(
      state(0n),
      new Uint8Array([0x70]),
      protector,
    );

    await store.transaction(
      { protocol: { ...protocol }, groupId: crossRealmGroupId },
      (transaction) => {
        transaction.setEncryptedState(encrypted);
        expect(
          transaction.enqueueOutbox({
            id: crossRealmId,
            kind: 'group.transition',
            epoch: 0n,
            payload: crossRealmPayload,
            createdAt: 1700,
          }),
        ).toBe(true);
      },
    );

    crossRealmGroupId.fill(0xff);
    crossRealmId.fill(0xff);
    crossRealmPayload.fill(0xff);
    const stableKey = {
      protocol: { ...protocol },
      groupId: new Uint8Array([1, 2, 3]),
    };
    const first = await store.load(stableKey);
    expect(first?.outbox[0]).toMatchObject({
      id: id(0x71),
      payload: new Uint8Array([0x72, 0x73]),
    });

    first!.outbox[0].id.fill(0xee);
    first!.outbox[0].payload.fill(0xee);
    const second = await store.load(stableKey);
    expect(second?.outbox[0]).toMatchObject({
      id: id(0x71),
      payload: new Uint8Array([0x72, 0x73]),
    });
  });

  test('rejects shared and non-Uint8 cross-realm byte views', async () => {
    const store = new InMemoryGroupStateStore();
    const clamped = runInNewContext(
      'new Uint8ClampedArray([1, 2, 3])',
    ) as unknown as Uint8Array;
    await expect(
      store.load({ protocol: { ...protocol }, groupId: clamped }),
    ).rejects.toThrow(/invalid length or backing buffer/);

    const spoofed = Object.create(Uint8Array.prototype) as Uint8Array;
    Object.defineProperties(spoofed, {
      byteLength: { value: 3 },
      buffer: { value: new ArrayBuffer(3) },
      0: { value: 1, enumerable: true },
      1: { value: 2, enumerable: true },
      2: { value: 3, enumerable: true },
    });
    expect(spoofed instanceof Uint8Array).toBe(true);
    await expect(
      store.load({ protocol: { ...protocol }, groupId: spoofed }),
    ).rejects.toThrow(/invalid length or backing buffer/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const crossRealmShared = runInNewContext(
        'new Uint8Array(new SharedArrayBuffer(3))',
      ) as Uint8Array;
      expect(crossRealmShared instanceof Uint8Array).toBe(false);
      await expect(
        store.load({
          protocol: { ...protocol },
          groupId: crossRealmShared,
        }),
      ).rejects.toThrow(/invalid length or backing buffer/);
    }
  });

  test('requires plain records with exact enumerable own data fields', async () => {
    const store = new InMemoryGroupStateStore();
    let accessorRead = false;
    const accessorKey = {
      get protocol() {
        accessorRead = true;
        return protocol;
      },
      groupId: key.groupId,
    } as GroupStateStoreKey;
    await expect(store.load(accessorKey)).rejects.toThrow(/own data property/);
    expect(accessorRead).toBe(false);

    const inheritedKey = Object.create(key) as GroupStateStoreKey;
    await expect(store.load(inheritedKey)).rejects.toThrow(/plain object/);

    const extraOutbox = {
      ...outbox(0x63, 0n),
      unexpected: true,
    } as GroupStateOutboxEntry;
    await expect(
      store.transaction(key, (transaction) => {
        transaction.enqueueOutbox(extraOutbox);
      }),
    ).rejects.toThrow(/unexpected or missing fields/);

    const replayAccessor = {
      recordId: id(0x64),
      epoch: 0n,
      get controlRecord() {
        accessorRead = true;
        return new Uint8Array([0x64]);
      },
    };
    await expect(
      store.transaction(key, (transaction) => {
        transaction.markReplay(
          replayAccessor as unknown as Parameters<
            GroupStateStoreTransaction['markReplay']
          >[0],
        );
      }),
    ).rejects.toThrow(/own data property/);

    const inheritedFork = Object.create(forkEvidence()) as GroupStateForkEvidence;
    await expect(
      store.transaction(key, (transaction) => {
        transaction.markFork(inheritedFork);
      }),
    ).rejects.toThrow(/plain object/);
    expect(accessorRead).toBe(false);
    await expect(store.load(key)).resolves.toBeUndefined();
  });

  test('rejects envelope overrides and reconstructs only authentic instances', async () => {
    const store = new InMemoryGroupStateStore();
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    const encrypted = await EncryptedGroupState.seal(
      state(1n),
      new Uint8Array([1]),
      protector,
    );
    Object.defineProperty(encrypted, 'state', {
      get: () => ({
        ...state(99n),
        groupId: new Uint8Array([0xff]),
      }),
    });
    const pending = await encryptedKeyPackage(
      new Uint8Array([0x65]),
      new Uint8Array([2]),
      protector,
    );
    Object.defineProperty(pending, 'keyPackage', {
      get: () => keyPackage(new Uint8Array([0xff])),
    });

    await expect(
      store.transaction(key, (transaction) => {
        transaction.setEncryptedState(encrypted);
      }),
    ).rejects.toThrow(/EncryptedGroupState/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(pending);
      }),
    ).rejects.toThrow(/EncryptedKeyPackageState/);
    await expect(store.load(key)).resolves.toBeUndefined();

    const authenticEncrypted = EncryptedGroupState.deserialize(
      encrypted.serialize(),
    );
    const authenticPending = EncryptedKeyPackageState.deserialize(
      pending.serialize(),
    );
    await store.transaction(key, (transaction) => {
      transaction.setEncryptedState(authenticEncrypted);
      transaction.putPendingKeyPackage(authenticPending);
      transaction.bindPendingKeyPackageRequest({
        operationId: id(0x66),
        requestCommitment: id(0x67),
        keyPackageReference: authenticPending.keyPackage.reference,
      });
    });
    const loaded = await store.load(key);
    expect(loaded?.encryptedState?.state.epoch).toBe(1n);
    expect(loaded?.pendingKeyPackages[0].keyPackage.reference).toEqual(
      new Uint8Array([0x65]),
    );

    const forgedGroupState = Object.create(
      EncryptedGroupState.prototype,
    ) as EncryptedGroupState;
    const forgedKeyPackageState = Object.create(
      EncryptedKeyPackageState.prototype,
    ) as EncryptedKeyPackageState;
    await expect(
      store.transaction(key, (transaction) => {
        transaction.setEncryptedState(forgedGroupState);
      }),
    ).rejects.toThrow(/EncryptedGroupState/);
    await expect(
      store.transaction(key, (transaction) => {
        transaction.putPendingKeyPackage(forgedKeyPackageState);
      }),
    ).rejects.toThrow(/EncryptedKeyPackageState/);

    const overriddenGroupState = EncryptedGroupState.deserialize(
      loaded!.encryptedState!.serialize(),
    );
    Object.defineProperty(overriddenGroupState, 'serialize', {
      value: () => loaded!.encryptedState!.serialize(),
    });
    await expect(
      store.transaction(key, (transaction) => {
        transaction.setEncryptedState(overriddenGroupState);
      }),
    ).rejects.toThrow(/EncryptedGroupState/);
    expect((await store.load(key))?.revision).toBe(1);
  });

  test('rejects aggregate committed metadata at a low-memory quota without changing revision', async () => {
    expect(MAX_GROUP_STATE_STORE_COMMITTED_BYTES).toBe(128 * 1024 * 1024);
    const store = new InMemoryGroupStateStore(2048);
    const protector = await WebCryptoGroupStateProtector.generate('store-key');
    await store.transaction(key, async (transaction) => {
      transaction.setEncryptedState(
        await EncryptedGroupState.seal(
          state(1n),
          new Uint8Array([1]),
          protector,
        ),
      );
    });

    await expect(
      store.transaction(key, (transaction) => {
        transaction.enqueueOutbox({
          ...outbox(0x66, 1n),
          payload: new Uint8Array(2048),
        });
      }),
    ).rejects.toThrow(/committed-byte limit/);
    const loaded = await store.load(key);
    expect(loaded?.revision).toBe(1);
    expect(loaded?.outbox).toEqual([]);
  });
});
