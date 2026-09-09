import { describe, expect, test } from '@jest/globals';

import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
  type GroupKeyPackage,
  type GroupSecurityPublicState,
} from './group-security-provider.js';
import {
  canonicalGroupSecurityStoreSnapshot,
  groupSecurityStoreSnapshotCommitment,
  validateAndCloneGroupStateStoreSnapshot,
} from './group-security-store-commitment.js';
import type { GroupStateStoreSnapshot } from './group-state-store.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';

const protocol = { id: 'store-commitment.test', version: 1 };
const groupId = new Uint8Array([1, 2, 3]);

function bytes(value: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function publicState(epoch = 2n): GroupSecurityPublicState {
  return {
    protocol,
    groupId: new Uint8Array(groupId),
    epoch,
    confirmedTranscriptHash: bytes(Number(epoch) + 10),
    treeHash: bytes(Number(epoch) + 20),
  };
}

function keyPackage(reference: number): GroupKeyPackage {
  return {
    protocol,
    groupId: new Uint8Array(groupId),
    reference: new Uint8Array([reference]),
    payload: new Uint8Array([reference, 0xaa]),
  };
}

async function fixture(): Promise<GroupStateStoreSnapshot> {
  const protector = await WebCryptoGroupStateProtector.generate('commitment-key');
  return {
    revision: 7,
    encryptedState: await EncryptedGroupState.seal(
      publicState(),
      new Uint8Array([9, 8, 7]),
      protector,
    ),
    pendingKeyPackages: [
      await EncryptedKeyPackageState.seal(
        keyPackage(1),
        new Uint8Array([0x91]),
        protector,
      ),
      await EncryptedKeyPackageState.seal(
        keyPackage(2),
        new Uint8Array([0x92]),
        protector,
      ),
    ],
    pendingKeyPackageRequests: [
      {
        operationId: bytes(0x61),
        requestCommitment: bytes(0x71),
        keyPackageReference: new Uint8Array([1]),
      },
      {
        operationId: bytes(0x62),
        requestCommitment: bytes(0x72),
        keyPackageReference: new Uint8Array([2]),
      },
    ],
    consumedKeyPackageRefs: [new Uint8Array([3]), new Uint8Array([4])],
    outbox: [
      {
        id: bytes(0x11),
        kind: 'group-security.transition.v1',
        epoch: 1n,
        payload: new Uint8Array([1, 2]),
        createdAt: 100,
      },
      {
        id: bytes(0x12),
        kind: 'group-security.transition.v1',
        epoch: 2n,
        payload: new Uint8Array([3, 4]),
        createdAt: 101,
      },
    ],
    replay: [
      {
        recordId: bytes(0x21),
        operationId: bytes(0x31),
        epoch: 1n,
        controlRecord: new Uint8Array([5, 6]),
      },
      {
        recordId: bytes(0x22),
        operationId: bytes(0x32),
        epoch: 2n,
        controlRecord: new Uint8Array([7, 8]),
      },
    ],
    forkEvidence: {
      epoch: 2n,
      parentRecordId: bytes(0x40),
      firstRecordId: bytes(0x41),
      firstControlRecord: new Uint8Array([0x51]),
      secondRecordId: bytes(0x42),
      secondControlRecord: new Uint8Array([0x52]),
    },
  };
}

describe('group-security store snapshot commitment', () => {
  test('is deterministic across storage iteration and fork-pair order', async () => {
    const original = await fixture();
    const reordered = cloneSnapshot(original);
    reordered.pendingKeyPackages.reverse();
    reordered.pendingKeyPackageRequests.reverse();
    reordered.consumedKeyPackageRefs.reverse();
    reordered.outbox.reverse();
    reordered.replay.reverse();
    reordered.forkEvidence = {
      ...reordered.forkEvidence!,
      firstRecordId: reordered.forkEvidence!.secondRecordId,
      firstControlRecord: reordered.forkEvidence!.secondControlRecord,
      secondRecordId: reordered.forkEvidence!.firstRecordId,
      secondControlRecord: reordered.forkEvidence!.firstControlRecord,
    };

    await expect(groupSecurityStoreSnapshotCommitment(reordered)).resolves.toEqual(
      await groupSecurityStoreSnapshotCommitment(original),
    );
  });

  test('binds same-revision pending requests, consumed, outbox, replay, and fork metadata', async () => {
    const original = await fixture();
    const expected = await groupSecurityStoreSnapshotCommitment(original);
    const variants = [
      mutate(original, (value) => {
        value.revision += 1;
      }),
      mutate(original, (value) => {
        value.pendingKeyPackages.pop();
        value.pendingKeyPackageRequests.pop();
      }),
      mutate(original, (value) => {
        value.pendingKeyPackageRequests[0].requestCommitment[0] ^= 0x40;
      }),
      mutate(original, (value) => {
        value.consumedKeyPackageRefs[0][0] ^= 0x40;
      }),
      mutate(original, (value) => {
        value.outbox[0].payload[0] ^= 0x40;
      }),
      mutate(original, (value) => {
        value.outbox[0].createdAt += 1;
      }),
      mutate(original, (value) => {
        value.replay[0].controlRecord[0] ^= 0x40;
      }),
      mutate(original, (value) => {
        value.replay[0].operationId![0] ^= 0x40;
      }),
      mutate(original, (value) => {
        value.forkEvidence!.secondControlRecord[0] ^= 0x40;
      }),
    ];

    for (const variant of variants) {
      expect(await groupSecurityStoreSnapshotCommitment(variant)).not.toEqual(
        expected,
      );
    }
  });

  test('rejects duplicate identities, pending/consumed overlap, and extra fields', async () => {
    const duplicate = cloneSnapshot(await fixture());
    duplicate.outbox.push(cloneSnapshot(duplicate).outbox[0]);
    await expect(
      groupSecurityStoreSnapshotCommitment(duplicate),
    ).rejects.toThrow(/outbox id is duplicated/);

    const duplicateRequest = cloneSnapshot(await fixture());
    duplicateRequest.pendingKeyPackageRequests[1] = {
      ...duplicateRequest.pendingKeyPackageRequests[1],
      operationId:
        duplicateRequest.pendingKeyPackageRequests[0].operationId,
    };
    await expect(
      groupSecurityStoreSnapshotCommitment(duplicateRequest),
    ).rejects.toThrow(/request operationId is duplicated/);

    const danglingRequest = cloneSnapshot(await fixture());
    danglingRequest.pendingKeyPackageRequests[0] = {
      ...danglingRequest.pendingKeyPackageRequests[0],
      keyPackageReference: new Uint8Array([0xff]),
    };
    await expect(
      groupSecurityStoreSnapshotCommitment(danglingRequest),
    ).rejects.toThrow(/references missing state/);

    const overlap = cloneSnapshot(await fixture());
    overlap.consumedKeyPackageRefs.push(new Uint8Array([1]));
    await expect(
      groupSecurityStoreSnapshotCommitment(overlap),
    ).rejects.toThrow(/both pending and consumed/);

    const extra = {
      ...(await fixture()),
      ignoredSecurityMetadata: true,
    };
    expect(() =>
      canonicalGroupSecurityStoreSnapshot(
        extra as unknown as GroupStateStoreSnapshot,
      ),
    ).toThrow(/unexpected or missing fields/);
  });

  test('snapshots mutable arrays and buffers before awaiting SHA-256', async () => {
    const value = cloneSnapshot(await fixture());
    const stable = cloneSnapshot(value);
    const pending = groupSecurityStoreSnapshotCommitment(value);
    value.revision += 1;
    value.outbox[0].payload.fill(0xff);
    value.replay.reverse();
    value.consumedKeyPackageRefs[0].fill(0xee);
    value.pendingKeyPackageRequests[0].requestCommitment.fill(0xdd);

    await expect(pending).resolves.toEqual(
      await groupSecurityStoreSnapshotCommitment(stable),
    );
  });

  test('returns a detached stable clone and rejects sparse arrays', async () => {
    const source = cloneSnapshot(await fixture());
    const stable = validateAndCloneGroupStateStoreSnapshot(source);
    const expected = await groupSecurityStoreSnapshotCommitment(stable);
    source.outbox[0].payload.fill(0xff);
    source.pendingKeyPackageRequests[0].requestCommitment.fill(0xee);
    source.replay.reverse();
    await expect(
      groupSecurityStoreSnapshotCommitment(stable),
    ).resolves.toEqual(expected);

    const sparse = cloneSnapshot(await fixture());
    sparse.outbox = new Array(1) as never;
    expect(() =>
      validateAndCloneGroupStateStoreSnapshot(sparse),
    ).toThrow(/sparse|array index|data property|missing/i);
  });

  test('rejects oversized arrays before requesting their property keys', async () => {
    const value = cloneSnapshot(await fixture());
    let ownKeysCalls = 0;
    value.outbox = new Proxy(new Array(65_537), {
      ownKeys() {
        ownKeysCalls += 1;
        throw new Error('oversized array keys must not be enumerated');
      },
    }) as never;
    expect(() => validateAndCloneGroupStateStoreSnapshot(value)).toThrow(
      /bounded plain array/,
    );
    expect(ownKeysCalls).toBe(0);
  });

  test('binds encrypted state and pending-envelope bytes', async () => {
    const original = await fixture();
    const expected = await groupSecurityStoreSnapshotCommitment(original);
    const protector = await WebCryptoGroupStateProtector.generate(
      'commitment-mutation-key',
    );

    const changedState = cloneSnapshot(original);
    changedState.encryptedState = await EncryptedGroupState.seal(
      publicState(3n),
      new Uint8Array([9, 8, 7]),
      protector,
    );
    expect(
      await groupSecurityStoreSnapshotCommitment(changedState),
    ).not.toEqual(expected);

    const changedPending = cloneSnapshot(original);
    changedPending.pendingKeyPackages[0] =
      await EncryptedKeyPackageState.seal(
        keyPackage(1),
        new Uint8Array([0xff]),
        protector,
      );
    expect(
      await groupSecurityStoreSnapshotCommitment(changedPending),
    ).not.toEqual(expected);
  });

  test('rejects forged, uninitialized, and overridden encrypted envelopes', async () => {
    const forgedGroup = cloneSnapshot(await fixture());
    const forgedGroupState = Object.create(EncryptedGroupState.prototype) as
      EncryptedGroupState & { serialize: () => Uint8Array };
    Object.defineProperty(forgedGroupState, 'serialize', {
      value: () => forgedGroup.encryptedState!.serialize(),
    });
    forgedGroup.encryptedState = forgedGroupState;
    await expect(
      groupSecurityStoreSnapshotCommitment(forgedGroup),
    ).rejects.toThrow(/branded EncryptedGroupState/);

    const forgedPending = cloneSnapshot(await fixture());
    forgedPending.pendingKeyPackages[0] = Object.create(
      EncryptedKeyPackageState.prototype,
    ) as EncryptedKeyPackageState;
    await expect(
      groupSecurityStoreSnapshotCommitment(forgedPending),
    ).rejects.toThrow(/not branded encrypted state/);

    const overridden = cloneSnapshot(await fixture());
    Object.defineProperty(overridden.encryptedState!, 'serialize', {
      value: () => overridden.encryptedState!.serialize(),
    });
    await expect(
      groupSecurityStoreSnapshotCommitment(overridden),
    ).rejects.toThrow(/branded EncryptedGroupState/);
  });

  test('rejects an own-property override of pending public metadata', async () => {
    const value = cloneSnapshot(await fixture());
    Object.defineProperty(value.pendingKeyPackages[0], 'keyPackage', {
      value: keyPackage(0xfe),
    });

    await expect(
      groupSecurityStoreSnapshotCommitment(value),
    ).rejects.toThrow(/not branded encrypted state/);
  });

  test('uses intrinsic typed-array length and buffer brands', async () => {
    const original = cloneSnapshot(await fixture());
    const expected = await groupSecurityStoreSnapshotCommitment(original);
    Object.defineProperties(original.outbox[0].payload, {
      byteLength: { value: 16 * 1024 * 1024 + 1 },
      buffer: {
        value:
          typeof SharedArrayBuffer === 'undefined'
            ? new ArrayBuffer(1)
            : new SharedArrayBuffer(1),
      },
    });
    await expect(
      groupSecurityStoreSnapshotCommitment(original),
    ).resolves.toEqual(expected);

    const shortId = cloneSnapshot(await fixture());
    shortId.outbox[0].id = bytes(0x22, 31);
    Object.defineProperty(shortId.outbox[0].id, 'byteLength', { value: 32 });
    await expect(
      groupSecurityStoreSnapshotCommitment(shortId),
    ).rejects.toThrow(/outbox entry 0 id.*invalid length/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = cloneSnapshot(await fixture());
      shared.outbox[0].id = new Uint8Array(new SharedArrayBuffer(32));
      Object.defineProperty(shared.outbox[0].id, 'buffer', {
        value: new ArrayBuffer(32),
      });
      await expect(
        groupSecurityStoreSnapshotCommitment(shared),
      ).rejects.toThrow(/backing buffer/);
    }
  });

  test('snapshots a proxied array count exactly once', async () => {
    const value = cloneSnapshot(await fixture());
    let lengthSnapshots = 0;
    value.outbox = new Proxy(value.outbox, {
      get(target, property, receiver) {
        if (property === 'length') {
          throw new Error('array length was read through a Proxy get trap');
        }
        return Reflect.get(target, property, receiver);
      },
      getOwnPropertyDescriptor(target, property) {
        if (property === 'length') lengthSnapshots += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    await expect(
      groupSecurityStoreSnapshotCommitment(value),
    ).resolves.toHaveLength(32);
    expect(lengthSnapshots).toBe(1);
  });

  test('preflights aggregate outbox bytes without duplicating shared payloads', () => {
    const sharedPayload = new Uint8Array(2048);
    const outbox = Array.from({ length: 65_536 }, (_, index) => {
      const id = new Uint8Array(32);
      new DataView(id.buffer).setUint32(28, index, false);
      return {
        id,
        kind: 'group-security.transition.v1',
        epoch: 1n,
        payload: sharedPayload,
        createdAt: index,
      };
    });
    const value: GroupStateStoreSnapshot = {
      revision: 1,
      pendingKeyPackages: [],
      pendingKeyPackageRequests: [],
      consumedKeyPackageRefs: [],
      outbox,
      replay: [],
    };

    expect(() => canonicalGroupSecurityStoreSnapshot(value)).toThrow(
      /canonical group-state snapshot exceeds its byte bound/,
    );
  });
});

interface MutableSnapshot {
  revision: number;
  encryptedState?: GroupStateStoreSnapshot['encryptedState'];
  pendingKeyPackages: Array<GroupStateStoreSnapshot['pendingKeyPackages'][number]>;
  pendingKeyPackageRequests: Array<
    GroupStateStoreSnapshot['pendingKeyPackageRequests'][number]
  >;
  consumedKeyPackageRefs: Uint8Array[];
  outbox: Array<{
    id: Uint8Array;
    kind: string;
    epoch: bigint;
    payload: Uint8Array;
    createdAt: number;
  }>;
  replay: Array<{
    recordId: Uint8Array;
    operationId?: Uint8Array;
    epoch: bigint;
    controlRecord: Uint8Array;
  }>;
  forkEvidence?: {
    epoch: bigint;
    parentRecordId: Uint8Array;
    firstRecordId: Uint8Array;
    firstControlRecord: Uint8Array;
    secondRecordId: Uint8Array;
    secondControlRecord: Uint8Array;
  };
}

function cloneSnapshot(value: GroupStateStoreSnapshot): MutableSnapshot {
  return {
    revision: value.revision,
    encryptedState: value.encryptedState,
    pendingKeyPackages: [...value.pendingKeyPackages],
    pendingKeyPackageRequests: value.pendingKeyPackageRequests.map(
      (request) => ({
        operationId: new Uint8Array(request.operationId),
        requestCommitment: new Uint8Array(request.requestCommitment),
        keyPackageReference: new Uint8Array(request.keyPackageReference),
      }),
    ),
    consumedKeyPackageRefs: value.consumedKeyPackageRefs.map(
      (reference) => new Uint8Array(reference),
    ),
    outbox: value.outbox.map((entry) => ({
      ...entry,
      id: new Uint8Array(entry.id),
      payload: new Uint8Array(entry.payload),
    })),
    replay: value.replay.map((entry) => ({
      ...entry,
      recordId: new Uint8Array(entry.recordId),
      operationId:
        entry.operationId === undefined
          ? undefined
          : new Uint8Array(entry.operationId),
      controlRecord: new Uint8Array(entry.controlRecord),
    })),
    forkEvidence:
      value.forkEvidence === undefined
        ? undefined
        : {
            epoch: value.forkEvidence.epoch,
            parentRecordId: new Uint8Array(value.forkEvidence.parentRecordId),
            firstRecordId: new Uint8Array(value.forkEvidence.firstRecordId),
            firstControlRecord: new Uint8Array(
              value.forkEvidence.firstControlRecord,
            ),
            secondRecordId: new Uint8Array(value.forkEvidence.secondRecordId),
            secondControlRecord: new Uint8Array(
              value.forkEvidence.secondControlRecord,
            ),
          },
  };
}

function mutate(
  value: GroupStateStoreSnapshot,
  operation: (snapshot: MutableSnapshot) => void,
): MutableSnapshot {
  const snapshot = cloneSnapshot(value);
  operation(snapshot);
  return snapshot;
}
