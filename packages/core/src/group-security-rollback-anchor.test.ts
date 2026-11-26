import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  InMemoryGroupSecurityRollbackAnchor,
  cloneGroupSecurityRollbackAnchor,
  cloneGroupSecurityRollbackIntent,
  groupSecurityRollbackAnchorsEqual,
  groupSecurityRollbackIntentExtends,
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
  const active = () => ({
    revision: 1,
    epoch: 0n,
    controlHead: head(1),
    storeCommitment: commitment(1),
    forkPoison: undefined,
    removal: undefined,
  });
  const removal = () => ({
    epoch: 1n,
    parentRecordId: head(1),
    recordId: head(2),
    memberId: new Uint8Array([7]),
  });

  test('retires an exact active position irreversibly and retries idempotently', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const first = active();
    await anchor.advance(key, undefined, first);
    const input = removal();
    const operation = anchor.retire(key, first, input);
    input.memberId[0] = 99;
    expect(await operation).toBe(true);
    expect(await anchor.retire(key, first, removal())).toBe(true);
    const retired = (await anchor.load(key))!;
    expect(retired.removal?.memberId).toEqual(new Uint8Array([7]));
    retired.removal!.recordId[0] = 99;
    expect((await anchor.load(key))?.removal?.recordId).toEqual(head(2));
    expect(
      await anchor.advance(key, first, {
        ...first,
        revision: 2,
        epoch: 1n,
        controlHead: head(3),
      }),
    ).toBe(false);
    await expect(
      anchor.advance(key, (await anchor.load(key))!, {
        ...first,
        revision: 2,
        epoch: 1n,
        controlHead: head(3),
      }),
    ).rejects.toThrow(/terminal/);
    expect(
      await anchor.retire(key, first, { ...removal(), recordId: head(3) }),
    ).toBe(false);
  });

  test.each([
    { epoch: 0n },
    { epoch: 2n },
    { parentRecordId: head(9) },
    { recordId: head(1) },
    { memberId: new Uint8Array(0) },
    { memberId: new Uint8Array(513) },
    { recordId: new Uint8Array(31) },
  ])(
    'rejects an invalid removal without changing the active anchor: %#',
    async (change) => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const first = active();
      await anchor.advance(key, undefined, first);
      await expect(
        anchor.retire(key, first, { ...removal(), ...change }),
      ).rejects.toThrow();
      expect(await anchor.load(key)).toEqual(first);
    },
  );

  test('serializes retirement against active advancement in either order', async () => {
    for (const retireFirst of [true, false]) {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const first = active();
      await anchor.advance(key, undefined, first);
      const advance = () =>
        anchor.advance(key, first, {
          ...first,
          revision: 2,
          epoch: 1n,
          controlHead: head(3),
        });
      const retire = () => anchor.retire(key, first, removal());
      const operations = retireFirst ? [retire, advance] : [advance, retire];
      expect(
        await Promise.all(operations.map((operation) => operation())),
      ).toEqual([true, false]);
      expect((await anchor.load(key))?.removal !== undefined).toBe(retireFirst);
    }
  });

  test('rejects accessors and shared removal bytes without invoking getters', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const first = active();
    await anchor.advance(key, undefined, first);
    const input = removal();
    let reads = 0;
    Object.defineProperty(input, 'memberId', {
      enumerable: true,
      get() {
        reads++;
        return new Uint8Array([7]);
      },
    });
    await expect(anchor.retire(key, first, input)).rejects.toThrow();
    expect(reads).toBe(0);
    await expect(
      anchor.retire(key, first, {
        ...removal(),
        memberId: new Uint8Array(new SharedArrayBuffer(1)),
      }),
    ).rejects.toThrow();
    expect(await anchor.load(key)).toEqual(first);
  });

  test('keeps the first terminal marker when retirement races fork poisoning', async () => {
    const poison = {
      epoch: 1n,
      parentRecordId: head(1),
      firstRecordId: head(2),
      secondRecordId: head(3),
      evidenceHash: commitment(4),
    };
    for (const retireFirst of [true, false]) {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const first = active();
      await anchor.advance(key, undefined, first);
      if (retireFirst) {
        expect(await anchor.retire(key, first, removal())).toBe(true);
        const result = await anchor.poison(key, poison);
        expect(result.removal).toEqual(removal());
        expect(result.forkPoison).toBeUndefined();
      } else {
        await anchor.poison(key, poison);
        expect(await anchor.retire(key, first, removal())).toBe(false);
        expect((await anchor.load(key))?.forkPoison).toEqual(poison);
        expect((await anchor.load(key))?.removal).toBeUndefined();
      }
    }
  });

  test('keeps store keys stable when the typed-array iterator is replaced', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const initial = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
      removal: undefined,
    };
    await anchor.advance(key, undefined, initial);
    const prototype = Object.getPrototypeOf(Uint8Array.prototype);
    const descriptor = Object.getOwnPropertyDescriptor(
      prototype,
      Symbol.iterator,
    )!;
    let loaded;
    try {
      Object.defineProperty(prototype, Symbol.iterator, {
        ...descriptor,
        value() {
          throw new Error('untrusted byte iterator');
        },
      });
      loaded = await anchor.load(key);
    } finally {
      Object.defineProperty(prototype, Symbol.iterator, descriptor);
    }
    expect(loaded).toEqual(initial);
  });

  test('advances with compare-and-set semantics and defensive copies', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const first = {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
      removal: undefined,
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
      removal: undefined,
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
          removal: undefined,
        },
        {
          revision: 2,
          epoch: 1n,
          controlHead: head(2),
          storeCommitment: commitment(2),
          forkPoison: undefined,
          removal: undefined,
        },
      ),
    ).toBe(false);
    expect(await anchor.load(key)).toEqual({
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
      removal: undefined,
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
      removal: undefined,
    };
    await anchor.advance(key, undefined, first);

    const results = await Promise.all([
      anchor.advance(firstKey(), first, {
        revision: 2,
        epoch: 1n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
        removal: undefined,
      }),
      anchor.advance(firstKey(), first, {
        revision: 2,
        epoch: 1n,
        controlHead: head(3),
        storeCommitment: commitment(3),
        forkPoison: undefined,
        removal: undefined,
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
      removal: undefined,
    };
    await anchor.advance(key, undefined, first);
    await expect(
      anchor.advance(key, first, {
        revision: 4,
        epoch: 3n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
        removal: undefined,
      }),
    ).rejects.toThrow(/revision.*exactly one/);
    await expect(
      anchor.advance(key, first, {
        revision: 3,
        epoch: 1n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
        removal: undefined,
      }),
    ).rejects.toThrow(/epoch/);
    await expect(
      anchor.advance(key, first, {
        revision: 3,
        epoch: 2n,
        controlHead: head(2),
        storeCommitment: commitment(2),
        forkPoison: undefined,
        removal: undefined,
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
      removal: undefined,
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
    loadedPoison.evidenceHash[0] = 0xff;
    expect((await anchor.load(key))?.forkPoison).toEqual(poisoned.forkPoison);
    await expect(
      anchor.advance(key, poisoned, {
        revision: 4,
        epoch: 3n,
        controlHead: head(8),
        storeCommitment: commitment(8),
        forkPoison: undefined,
        removal: undefined,
      }),
    ).rejects.toThrow(/terminal/);
  });

  test('rejects authenticated fork poison without two distinct records', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    await anchor.advance(key, undefined, {
      revision: 1,
      epoch: 0n,
      controlHead: head(1),
      storeCommitment: commitment(1),
      forkPoison: undefined,
      removal: undefined,
    });

    await expect(
      anchor.poison(key, {
        epoch: 0n,
        parentRecordId: head(2),
        firstRecordId: head(3),
        secondRecordId: head(3),
        evidenceHash: commitment(4),
      }),
    ).rejects.toThrow(/record IDs must be distinct/);
    expect((await anchor.load(key))?.forkPoison).toBeUndefined();
  });

  test('atomically poisons the latest value after queued active advances', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const values = [1, 2, 3, 4].map((revision) => ({
      revision,
      epoch: BigInt(revision - 1),
      controlHead: head(revision),
      storeCommitment: commitment(revision),
      forkPoison: undefined,
      removal: undefined,
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
      removal: undefined,
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
          removal: undefined,
        },
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(7),
          forkPoison: undefined,
          removal: undefined,
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
          removal: undefined,
        },
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(8),
          storeCommitment: commitment(7),
          forkPoison: undefined,
          removal: undefined,
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
          removal: undefined,
        },
        {
          revision: 3,
          epoch: 2n,
          controlHead: head(7),
          storeCommitment: commitment(8),
          forkPoison: undefined,
          removal: undefined,
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
        removal: undefined,
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
          removal: undefined,
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
        removal: undefined,
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
      removal: undefined,
    };
    const next = {
      revision: 2,
      epoch: 1n,
      controlHead: head(2),
      storeCommitment: commitment(2),
      forkPoison: undefined,
      removal: undefined,
    };
    const misses = Array.from({ length: 1000 }, (_, index) => {
      const groupId = new Uint8Array(4);
      new DataView(groupId.buffer).setUint32(0, index, false);
      return anchor.advance(
        { protocol: key.protocol, groupId },
        expected,
        next,
      );
    });

    await expect(Promise.all(misses)).resolves.toEqual(
      new Array(1000).fill(false),
    );
    expect(internals.values.size).toBe(0);
    expect(internals.tails.size).toBe(0);
  });

  test('preserves a queued successor when the prior tail settles', async () => {
    const anchor = new InMemoryGroupSecurityRollbackAnchor();
    const tails = (anchor as unknown as { tails: Map<string, Promise<void>> })
      .tails;
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
      removal: undefined,
    };
    const second = {
      revision: 2,
      epoch: 1n,
      controlHead: head(2),
      storeCommitment: commitment(2),
      forkPoison: undefined,
      removal: undefined,
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
        removal: undefined,
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
          removal: undefined,
        }),
      ).rejects.toThrow(/unshared/);
    }
  });

  describe('write-ahead intents', () => {
    const successor = (base = active()) => ({
      revision: base.revision + 1,
      epoch: base.epoch + 1n,
      controlHead: head(base.revision + 1),
      storeCommitment: commitment(base.revision + 1),
      forkPoison: undefined,
      removal: undefined,
    });
    const intentFrom = (
      base: ReturnType<typeof active>,
      next = successor(base),
    ) => ({
      baseRevision: base.revision,
      baseStoreCommitment: new Uint8Array(base.storeCommitment),
      next,
    });

    test('records an intent beside the active value and replaces it', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const base = active();
      await anchor.advance(key, undefined, base);
      const first = intentFrom(base);
      const operation = anchor.prepare(key, base, first);
      first.next.storeCommitment[0] = 0xee;
      expect(await operation).toBe(true);
      expect(await anchor.load(key)).toEqual(base);
      const loaded = (await anchor.loadIntent(key))!;
      expect(loaded.next.storeCommitment).toEqual(commitment(2));
      loaded.next.storeCommitment[0] = 0xee;
      expect((await anchor.loadIntent(key))!.next.storeCommitment).toEqual(
        commitment(2),
      );

      const replacement = intentFrom(base, {
        ...successor(base),
        storeCommitment: commitment(9),
      });
      expect(await anchor.prepare(key, base, replacement)).toBe(true);
      expect(await anchor.loadIntent(key)).toEqual(replacement);
      expect(groupSecurityRollbackIntentExtends(base, replacement)).toBe(true);
    });

    test('rejects a stale expected value without changing the intent', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const base = active();
      await anchor.advance(key, undefined, base);
      const pending = intentFrom(base);
      await anchor.prepare(key, base, pending);
      const other = {
        ...base,
        storeCommitment: commitment(4),
      };
      expect(await anchor.prepare(key, other, intentFrom(other))).toBe(false);
      expect(await anchor.prepare(key, undefined, intentFrom(base))).toBe(
        false,
      );
      expect(await anchor.loadIntent(key)).toEqual(pending);
    });

    test('rejects intents that do not extend the expected value by one step', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const base = active();
      await anchor.advance(key, undefined, base);
      const cases: Array<[unknown, RegExp]> = [
        [
          {
            ...intentFrom(base),
            baseRevision: 2,
            next: { ...successor(base), revision: 3 },
          },
          /extend the expected value/,
        ],
        [
          { ...intentFrom(base), baseStoreCommitment: commitment(8) },
          /extend the expected value/,
        ],
        [
          { ...intentFrom(base), next: { ...successor(base), revision: 3 } },
          /next revision/,
        ],
        [
          intentFrom(base, { ...successor(base), epoch: 2n }),
          /epoch must stay constant or advance by exactly one/,
        ],
        [
          intentFrom(base, { ...successor(base), epoch: 0n }),
          /control head cannot change without an epoch advance/,
        ],
        [
          intentFrom(base, {
            ...successor(base),
            forkPoison: {
              epoch: 1n,
              parentRecordId: head(1),
              firstRecordId: head(2),
              secondRecordId: head(3),
              evidenceHash: commitment(4),
            },
          } as never),
          /active value/,
        ],
      ];
      for (const [intent, message] of cases) {
        await expect(
          anchor.prepare(key, base, intent as never),
        ).rejects.toThrow(message);
        expect(groupSecurityRollbackIntentExtends(base, intent as never)).toBe(
          false,
        );
      }
      expect(await anchor.loadIntent(key)).toBeUndefined();
    });

    test('rejects malformed intent shapes', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const base = active();
      await anchor.advance(key, undefined, base);
      const accessor = Object.defineProperties(
        {},
        {
          baseRevision: { value: 1, enumerable: true },
          baseStoreCommitment: { get: () => commitment(1), enumerable: true },
          next: { value: successor(base), enumerable: true },
        },
      );
      const cases: Array<[unknown, RegExp]> = [
        [accessor, /data property/],
        [{ ...intentFrom(base), extra: true }, /unexpected or missing fields/],
        [
          { baseRevision: 1, next: successor(base) },
          /unexpected or missing fields/,
        ],
        [
          { ...intentFrom(base), baseRevision: -1 },
          /non-negative safe integer/,
        ],
        [
          { ...intentFrom(base), baseStoreCommitment: undefined },
          /present exactly when a base snapshot exists/,
        ],
        [
          {
            baseRevision: 0,
            baseStoreCommitment: commitment(1),
            next: { ...base },
          },
          /present exactly when a base snapshot exists/,
        ],
        [
          { ...intentFrom(base), baseStoreCommitment: new Uint8Array(31) },
          /32 unshared bytes/,
        ],
        [Object.create(intentFrom(base)), /plain object/],
      ];
      for (const [intent, message] of cases) {
        await expect(
          anchor.prepare(key, base, intent as never),
        ).rejects.toThrow(message);
        await expect(
          anchor.discard(key, base, intent as never),
        ).rejects.toThrow(message);
        expect(() => cloneGroupSecurityRollbackIntent(intent as never)).toThrow(
          message,
        );
      }
      expect(await anchor.loadIntent(key)).toBeUndefined();
    });

    test('records first-anchor intents bound to the pre-group snapshot', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const first = active();
      const empty = {
        baseRevision: 0,
        baseStoreCommitment: undefined,
        next: first,
      };
      expect(await anchor.prepare(key, undefined, empty)).toBe(true);
      expect(await anchor.load(key)).toBeUndefined();
      expect(await anchor.loadIntent(key)).toEqual(empty);
      const pending = {
        baseRevision: 4,
        baseStoreCommitment: commitment(4),
        next: { ...first, revision: 5 },
      };
      expect(await anchor.prepare(key, undefined, pending)).toBe(true);
      expect(await anchor.loadIntent(key)).toEqual(pending);
      expect(await anchor.advance(key, undefined, pending.next)).toBe(true);
      expect(await anchor.loadIntent(key)).toBeUndefined();
      expect(await anchor.prepare(key, undefined, empty)).toBe(false);
    });

    test('clears the intent on advance, poison and retirement', async () => {
      const base = active();
      const advanced = new InMemoryGroupSecurityRollbackAnchor();
      await advanced.advance(key, undefined, base);
      const pending = intentFrom(base);
      await advanced.prepare(key, base, pending);
      const unrelated = {
        ...successor(base),
        storeCommitment: commitment(0x44),
      };
      expect(await advanced.advance(key, base, unrelated)).toBe(true);
      expect(await advanced.loadIntent(key)).toBeUndefined();
      expect(await advanced.prepare(key, base, pending)).toBe(false);
      expect(await advanced.loadIntent(key)).toBeUndefined();

      const poisoned = new InMemoryGroupSecurityRollbackAnchor();
      await poisoned.advance(key, undefined, base);
      await poisoned.prepare(key, base, pending);
      await poisoned.poison(key, {
        epoch: 1n,
        parentRecordId: head(1),
        firstRecordId: head(2),
        secondRecordId: head(3),
        evidenceHash: commitment(4),
      });
      expect(await poisoned.loadIntent(key)).toBeUndefined();

      const initialized = new InMemoryGroupSecurityRollbackAnchor();
      await initialized.prepare(key, undefined, {
        baseRevision: 0,
        baseStoreCommitment: undefined,
        next: base,
      });
      await initialized.poison(
        key,
        {
          epoch: 0n,
          parentRecordId: head(1),
          firstRecordId: head(2),
          secondRecordId: head(3),
          evidenceHash: commitment(4),
        },
        base,
      );
      expect(await initialized.loadIntent(key)).toBeUndefined();

      const retired = new InMemoryGroupSecurityRollbackAnchor();
      await retired.advance(key, undefined, base);
      await retired.prepare(key, base, pending);
      expect(await retired.retire(key, base, removal())).toBe(true);
      expect(await retired.loadIntent(key)).toBeUndefined();
      await expect(retired.prepare(key, base, pending)).resolves.toBe(false);
    });

    test('discards only the exact recorded intent', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const base = active();
      await anchor.advance(key, undefined, base);
      const pending = intentFrom(base);
      await anchor.prepare(key, base, pending);
      const different = intentFrom(base, {
        ...successor(base),
        storeCommitment: commitment(0x55),
      });
      expect(await anchor.discard(key, base, different)).toBe(false);
      expect(
        await anchor.discard(
          key,
          { ...base, storeCommitment: commitment(9) },
          pending,
        ),
      ).toBe(false);
      expect(await anchor.loadIntent(key)).toEqual(pending);
      expect(await anchor.discard(key, base, pending)).toBe(true);
      expect(await anchor.loadIntent(key)).toBeUndefined();
      expect(await anchor.discard(key, base, pending)).toBe(true);
      expect(await anchor.load(key)).toEqual(base);
    });

    test('rejects the retired ambiguity poison format', async () => {
      const anchor = new InMemoryGroupSecurityRollbackAnchor();
      const base = active();
      await anchor.advance(key, undefined, base);
      await expect(
        anchor.poison(key, {
          reason: 'unreconciled-authenticated-candidate',
          epoch: 1n,
          baseRevision: 1,
          baseControlHead: head(1),
          baseStoreCommitment: commitment(1),
          candidateParentRecordId: head(1),
          candidateRecordId: head(2),
          observationHash: commitment(3),
        } as never),
      ).rejects.toThrow(/unexpected or missing fields/);
      expect(await anchor.load(key)).toEqual(base);
    });
  });
});

function firstKey(): GroupStateStoreKey {
  return {
    protocol: { ...key.protocol },
    groupId: new Uint8Array(key.groupId),
  };
}
