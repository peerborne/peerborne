import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  InMemoryGroupSecurityRollbackAnchor,
  cloneGroupSecurityRollbackAnchor,
  groupSecurityRollbackAnchorsEqual,
} from './group-security-rollback-anchor.js';
import type { GroupStateStoreKey } from './group-state-store.js';

const key: GroupStateStoreKey = {
  protocol: { id: 'anchor.test', version: 1 },
  groupId: new Uint8Array([1, 2, 3]),
};

function head(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

function commitment(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

describe('InMemoryGroupSecurityRollbackAnchor', () => {
  test('advances with compare-and-set semantics and defensive copies', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const first = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    expect(await anchor.advance(key, undefined, first)).toBe(true);

    first.controlHead[0] = 0xff;
    const loaded = await anchor.load(key);
    expect(loaded).toEqual({
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    });
    loaded!.controlHead[0] = 0xee;
    loaded!.storeCommitment[0] = 0xdd;
    expect((await anchor.load(key))?.controlHead).toEqual(head(1));
    expect((await anchor.load(key))?.storeCommitment).toEqual(commitment(1));

    expect(
      await anchor.advance(
        key,
        {
          revision: 1,
          epoch: 0n,
          controlHead: head(9),
          storeCommitment: commitment(1),
          forkPoison: undefined,
        },
        {
          revision: 2,
          epoch: 1n,
          controlHead: head(2),
          storeCommitment: commitment(2),
          forkPoison: undefined,
        },
      ),
    ).toBe(false);
    expect(await anchor.load(key)).toEqual({
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    });
  });

  test('serializes competing advances so exactly one succeeds', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const first = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    await anchor.advance(key, undefined, first);

    const results = await Promise.all([
      anchor.advance(firstKey(), first, {
        revision: 2,
        epoch: 1n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
      }),
      anchor.advance(firstKey(), first, {
        revision: 2,
        epoch: 1n,
        controlHead: head(3),
        storeCommitment: commitment(3),
        forkPoison: undefined,
      }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  test('rejects skips, regressions, and same-epoch head changes', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const first = {
      revision: 2,
      epoch: 2n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    await anchor.advance(key, undefined, first);
    await expect(
      anchor.advance(key, first, {
        revision: 4,
        epoch: 3n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
      }),
    ).rejects.toThrow(/revision.*exactly one/);
    await expect(
      anchor.advance(key, first, {
        revision: 3,
        epoch: 1n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
      }),
    ).rejects.toThrow(/epoch/);
    await expect(
      anchor.advance(key, first, {
        revision: 3,
        epoch: 2n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
      }),
    ).rejects.toThrow(/control head/);
  });

  test('atomically poisons one active position and makes it terminal', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const active = {
      revision: 3,
      epoch: 2n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    await anchor.advance(key, undefined, active);
    const poisoned = {
      ...active,
      forkPoison: {
        epoch: 2n,
        parentRecordId: head(4),
        firstRecordId: head(5),
        secondRecordId: head(6),
        evidenceHash: commitment(7),
      },
    };
    expect(await anchor.poison(key, poisoned.forkPoison)).toEqual(poisoned);
    const loaded = await anchor.load(key);
    expect(loaded).toEqual(poisoned);
    const loadedPoison = loaded!.forkPoison!;
    if ('reason' in loadedPoison) {
      throw new Error('expected authenticated fork poison');
    }
    loadedPoison.evidenceHash[0] = 0xff;
    expect((await anchor.load(key))?.forkPoison).toEqual(poisoned.forkPoison);
    await expect(
      anchor.advance(key, poisoned, {
        revision: 4,
        epoch: 3n,
        controlHead: head(8),
        storeCommitment: commitment(8),
        forkPoison: undefined,
      }),
    ).rejects.toThrow(/terminal/);
  });

  test('atomically poisons the latest value after queued active advances', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const values = [1, 2, 3, 4].map((revision) => ({
      revision,
      epoch: BigInt(revision - 1),
      controlHead: head(revision),
      storeCommitment: commitment(revision),
      forkPoison: undefined,
    }));
    await anchor.advance(key, undefined, values[0]);
    const advances = [
      anchor.advance(key, values[0], values[1]),
      anchor.advance(key, values[1], values[2]),
      anchor.advance(key, values[2], values[3]),
    ];
    const poison = {
      epoch: 1n,
      parentRecordId: head(4),
      firstRecordId: head(5),
      secondRecordId: head(6),
      evidenceHash: commitment(7),
    };
    const poisoned = anchor.poison(key, poison);

    await expect(Promise.all(advances)).resolves.toEqual([true, true, true]);
    await expect(poisoned).resolves.toEqual({
      ...values[3],
      forkPoison: poison,
    });
    expect(await anchor.load(key)).toEqual({
      ...values[3],
      forkPoison: poison,
    });
  });

  test('atomically installs poison during the first-anchor publication window', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const initial = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    const poison = {
      epoch: 0n,
      parentRecordId: head(0),
      firstRecordId: head(5),
      secondRecordId: head(6),
      evidenceHash: commitment(7),
    };
    await expect(anchor.poison(key, poison, initial)).resolves.toEqual({
      ...initial,
      forkPoison: poison,
    });
    await expect(anchor.advance(key, undefined, initial)).resolves.toBe(false);
    expect((await anchor.load(key))?.forkPoison).toEqual(poison);
  });

  test('compares anchors without exposing timing-dependent byte exits', () => {
    expect(
      groupSecurityRollbackAnchorsEqual(
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(7),
          forkPoison: undefined,
        },
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(7),
          forkPoison: undefined,
        },
      ),
    ).toBe(true);
    expect(
      groupSecurityRollbackAnchorsEqual(
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(7),
          forkPoison: undefined,
        },
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(8),
          storeCommitment: commitment(7),
          forkPoison: undefined,
        },
      ),
    ).toBe(false);
    expect(
      groupSecurityRollbackAnchorsEqual(
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(7),
          forkPoison: undefined,
        },
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(8),
          forkPoison: undefined,
        },
      ),
    ).toBe(false);
  });

  test('rejects accessor, shared, and shadowed-byte anchor values', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const accessor = Object.defineProperties(
      {},
      {
        revision: { value: 1, enumerable: true },
        epoch: { value: 0n, enumerable: true },
        controlHead: { get: () => head(1), enumerable: true },
        storeCommitment: { value: commitment(1), enumerable: true },
        forkPoison: { value: undefined, enumerable: true },
      },
    );
    await expect(
      anchor.advance(key, undefined, accessor as never),
    ).rejects.toThrow(/data property/);

    const oversized = new Uint8Array(64);
    Object.defineProperty(oversized, 'byteLength', { value: 32 });
    await expect(
      anchor.advance(key, undefined, {
        revision: 1,
        epoch: 0n,
        controlHead: head(1),
        storeCommitment: oversized,
        forkPoison: undefined,
      }),
    ).rejects.toThrow(/32 unshared bytes/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(new SharedArrayBuffer(32));
      Object.defineProperty(shared, 'buffer', {
        value: new ArrayBuffer(32),
      });
      await expect(
        anchor.advance(key, undefined, {
          revision: 1,
          epoch: 0n,
          controlHead: head(1),
          storeCommitment: shared,
          forkPoison: undefined,
        }),
      ).rejects.toThrow(/unshared/);
    }
  });

  test('snapshots proxy-backed anchor and poison fields without invoking getters', () => {
    let propertyReads = 0;
    const poison = new Proxy(
      {
        epoch: 0n,
        parentRecordId: head(2),
        firstRecordId: head(3),
        secondRecordId: head(4),
        evidenceHash: commitment(5),
      },
      {
        get(target, property, receiver) {
          propertyReads += 1;
          return Reflect.get(target, property, receiver);
        },
      },
    );
    const value = new Proxy(
      {
        revision: 1,
        epoch: 0n,
        controlHead: head(1),
        storeCommitment: commitment(1),
        forkPoison: poison,
      },
      {
        get(target, property, receiver) {
          propertyReads += 1;
          if (property === 'revision') return Number.MAX_SAFE_INTEGER;
          return Reflect.get(target, property, receiver);
        },
      },
    );

    const snapshot = cloneGroupSecurityRollbackAnchor(value);
    expect(snapshot.revision).toBe(1);
    expect(snapshot.forkPoison).toEqual({
      epoch: 0n,
      parentRecordId: head(2),
      firstRecordId: head(3),
      secondRecordId: head(4),
      evidenceHash: commitment(5),
    });
    expect(propertyReads).toBe(0);
    expect(groupSecurityRollbackAnchorsEqual(value, snapshot)).toBe(true);
    expect(propertyReads).toBe(0);
  });

  test('releases queue tails after distinct compare-and-set misses', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const internals = anchor as unknown as {
      values: Map<string, unknown>;
      tails: Map<string, Promise<void>>;
    };
    const expected = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    const next = {
      revision: 2,
      epoch: 1n,
      controlHead: head(2),
      storeCommitment: commitment(2),
      forkPoison: undefined,
    };
    const misses = Array.from({ length: 1000 }, (_, index) => {
      const groupId = new Uint8Array(4);
      new DataView(groupId.buffer).setUint32(0, index, false);
      return anchor.advance({ protocol: key.protocol, groupId }, expected, next);
    });

    await expect(Promise.all(misses)).resolves.toEqual(
      new Array(1000).fill(false),
    );
    expect(internals.values.size).toBe(0);
    expect(internals.tails.size).toBe(0);
  });

  test('preserves a queued successor when the prior tail settles', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const tails = (
      anchor as unknown as { tails: Map<string, Promise<void>> }
    ).tails;
    const nativeDelete = tails.delete.bind(tails);
    let deleteCalls = 0;
    Object.defineProperty(tails, 'delete', {
      value(encodedKey: string): boolean {
        deleteCalls += 1;
        return nativeDelete(encodedKey);
      },
    });
    const first = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
    };
    const second = {
      revision: 2,
      epoch: 1n,
      controlHead: head(2),
      storeCommitment: commitment(2),
      forkPoison: undefined,
    };

    await expect(
      Promise.all([
        anchor.advance(key, undefined, first),
        anchor.advance(key, first, second),
      ]),
    ).resolves.toEqual([true, true]);
    expect(await anchor.load(key)).toEqual(second);
    expect(deleteCalls).toBe(1);
    expect(tails.size).toBe(0);
  });

  test('accepts genuine cross-realm Uint8Arrays and rejects cross-realm shared backing', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const crossRealmHead = runInNewContext(
      'new Uint8Array(32).fill(6)',
    ) as Uint8Array;
    const crossRealmCommitment = runInNewContext(
      'new Uint8Array(32).fill(7)',
    ) as Uint8Array;
    expect(crossRealmHead instanceof Uint8Array).toBe(false);
    await expect(
      anchor.advance(key, undefined, {
        revision: 1,
        epoch: 0n,
        controlHead: crossRealmHead,
        storeCommitment: crossRealmCommitment,
        forkPoison: undefined,
      }),
    ).resolves.toBe(true);
    expect((await anchor.load(key))?.controlHead).toEqual(head(6));

    if (typeof SharedArrayBuffer !== 'undefined') {
      const crossRealmShared = runInNewContext(
        'new SharedArrayBuffer(32)',
      ) as SharedArrayBuffer;
      const localView = new Uint8Array(crossRealmShared);
      expect(localView instanceof Uint8Array).toBe(true);
      expect(crossRealmShared instanceof SharedArrayBuffer).toBe(false);
      await expect(
        new InMemoryGroupSecurityRollbackAnchor().advance(key, undefined, {
          revision: 1,
          epoch: 0n,
          controlHead: head(1),
          storeCommitment: localView,
          forkPoison: undefined,
        }),
      ).rejects.toThrow(/unshared/);
    }
  });
});

function firstKey(): GroupStateStoreKey {
  return {
    protocol: { ...key.protocol },
    groupId: new Uint8Array(key.groupId),
  };
}
