import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { CoordinatedDocument } from './coordinated-document.js';
import {
  DocumentCausalDependencyError,
  preparedDocumentChange,
} from './document-crdt-session.js';
import {
  documentFixture,
  testCRDT,
  testChanges,
} from './__testutils__/coordinated-document.js';
import { coordinatedGroupFixture } from './__testutils__/coordinated-group.js';
import { control } from './__testutils__/group-security-coordinator.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('libp2p', () => ({}), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: { Accept: 'accept', Ignore: 'ignore', Reject: 'reject' },
  }),
  { virtual: true },
);
jest.mock('@libp2p/peer-id', () => ({ peerIdFromString: jest.fn() }), {
  virtual: true,
});
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./helia-node.js', () => ({ createAndStartHeliaNode: jest.fn() }));
jest.mock('./peerborne-config.js', () => ({
  defaultBootstrapConfig: jest.fn(),
  defaultConfig: jest.fn(),
}));

type Fixture = Awaited<ReturnType<typeof documentFixture>>;
const create = (f: Fixture) =>
  new CoordinatedDocument(
    f.authority.documentId,
    [],
    testCRDT,
    testChanges,
    f.auth,
    f.identity,
    f.identity,
    { coordinator: f.coordinator, authority: f.authority },
  );

async function writes(document: ReturnType<typeof create>, values: number[]) {
  const frames: Uint8Array[] = [];
  for (const value of values)
    frames.push(
      await document.change((draft) => {
        draft.push(value);
      }),
    );
  return frames;
}

/** Each value v with v % 100 !== 0 natively depends on v - 1. */
const dependentCRDT: typeof testCRDT = {
  ...testCRDT,
  createDocumentSession(initial) {
    const session = testCRDT.createDocumentSession!(initial);
    const prepareRemote = session.prepareRemote.bind(session);
    return Object.assign(session, {
      prepareRemote(changes: number[]) {
        const known = new Set([...session.document, ...changes]);
        if (changes.some((value) => value % 100 !== 0 && !known.has(value - 1)))
          throw new DocumentCausalDependencyError();
        return prepareRemote(changes);
      },
    });
  },
};

/** The test CRDT without its 1,000-value remote bound, for large frames. */
const largeCRDT: typeof testCRDT = {
  ...testCRDT,
  createDocumentSession(initial) {
    let document = [...initial],
      closed = false;
    const prepare = (next: number[], changes: number[]) => {
      const base = document;
      return preparedDocumentChange(
        changes,
        () => !closed && base === document,
        () => {
          document = next;
        },
        () => {},
        () => [...next],
      );
    };
    return {
      get document() {
        return document;
      },
      prepareLocal(message, change) {
        const [next, changes] = testCRDT.localChange(document, message, change);
        return prepare(next, changes);
      },
      prepareRemote: (changes) => prepare([...document, ...changes], changes),
      prepareSnapshot: (changes) => prepare([...changes], [...changes]),
      close() {
        closed = true;
      },
    };
  },
};

const push =
  (...values: number[]) =>
  (draft: number[]): void => {
    draft.push(...values);
  };

describe('coordinated document held frames', () => {
  test('applies an author’s frames in sequence order from any arrival order', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 2, max: 24 }).chain((length) =>
          fc.tuple(
            fc.constant(length),
            fc.shuffledSubarray(
              Array.from({ length }, (_, index) => index),
              { minLength: length, maxLength: length },
            ),
            fc.boolean(),
          ),
        ),
        async ([length, order, duplicate]) => {
          const f = await documentFixture(),
            a = create(f),
            b = create(f);
          await a.activate();
          await b.activate();
          const values = Array.from({ length }, (_, index) => index * 3);
          const frames = await writes(a, values);
          let applied = 0;
          for (const index of duplicate ? [...order, ...order] : order) {
            if (await b.receive(frames[index])) applied++;
            const prefix = values.findIndex(
              (_, position) => !b.document.includes(values[position]),
            );
            expect(b.document).toEqual(
              values.slice(0, prefix === -1 ? length : prefix),
            );
          }
          expect(b.document).toEqual(values);
          expect(applied).toBeLessThanOrEqual(length);
          expect(await b.receive(await writes(a, [-1]).then(([x]) => x))).toBe(
            true,
          );
          await a.close();
          await b.close();
        },
      ),
      { seed: 202611251, numRuns: 25 },
    );
  }, 60_000);

  test('refuses an equivocating or damaged held frame and bounds each author', async () => {
    const f = await documentFixture(),
      a = create(f),
      twin = create(f),
      b = create(f);
    for (const document of [a, twin, b]) await document.activate();
    const frames = await writes(
      a,
      Array.from({ length: 34 }, (_, index) => index),
    );
    const [, forked] = await writes(twin, [100, 101]);
    expect(await b.receive(frames[1])).toBe(false);
    await expect(b.receive(forked)).rejects.toThrow('equivocated');
    expect(await b.receive(frames[1])).toBe(false);
    const damaged = frames[2].slice();
    damaged[damaged.length - 1] ^= 1;
    await expect(b.receive(damaged)).rejects.toThrow();
    for (const frame of frames.slice(2, 32))
      expect(await b.receive(frame)).toBe(false);
    expect(await b.receive(frames[32])).toBe(false);
    await expect(b.receive(frames[33])).rejects.toThrow('exceed their bound');
    expect(b.document).toEqual([]);
    expect(await b.receive(frames[0])).toBe(true);
    expect(b.document).toEqual(Array.from({ length: 33 }, (_, index) => index));
    expect(await b.receive(frames[33])).toBe(true);
    for (const document of [a, twin, b]) await document.close();
  });

  test('reports a different frame at the accepted sequence and drops copies of a held frame before verification', async () => {
    const f = await documentFixture(),
      a = create(f),
      twin = create(f),
      b = create(f);
    for (const document of [a, twin, b]) await document.activate();
    const frames = await writes(a, [1, 2, 3]);
    const [forked] = await writes(twin, [100]);
    expect(await b.receive(frames[0])).toBe(true);
    await expect(b.receive(forked)).rejects.toThrow('equivocated');
    expect(await b.receive(frames[2])).toBe(false);
    const verify = f.auth.verify;
    let verifications = 0;
    f.auth.verify = async (...args) => {
      verifications++;
      return verify(...args);
    };
    try {
      for (let copy = 0; copy < 10; copy++)
        expect(await b.receive(frames[2])).toBe(false);
      expect(await b.receive(frames[0])).toBe(false);
      expect(verifications).toBe(0);
      expect(await b.receive(frames[1])).toBe(true);
    } finally {
      f.auth.verify = verify;
    }
    expect(b.document).toEqual([1, 2, 3]);
    for (const document of [a, twin, b]) await document.close();
  });

  test('drops held frames at a new group context', async () => {
    const f = await documentFixture(),
      a = create(f),
      b = create(f);
    await a.activate();
    await b.activate();
    const old = await writes(a, [1, 2]);
    expect(await b.receive(old[1])).toBe(false);
    await f.coordinator.createCommit(
      { changes: [] },
      control(2, 'update', f.identity),
    );
    f.authority.context = f.coordinator.documentContext;
    await expect(b.receive(old[0])).rejects.toThrow();
    const current = await writes(a, [3, 4]);
    expect(await b.receive(current[1])).toBe(false);
    expect(await b.receive(current[0])).toBe(true);
    expect(b.document).toEqual([3, 4]);
    await a.close();
    await b.close();
  });

  test('holds a frame whose native dependency comes from another author', async () => {
    const g = await coordinatedGroupFixture(dependentCRDT, testChanges, {
      members: 3,
    });
    try {
      await g.addMember(1);
      await g.addMember(2);
      for (let index = 0; index < 3; index++) await g.open(index);
      await g.doc(2).change((draft) => {
        draft.push(100);
      });
      const [x] = g.take();
      expect(await g.deliver(x, [1])).toEqual([]);
      await g.doc(1).change((draft) => {
        draft.push(101);
      });
      const [y] = g.take();
      expect(await g.doc(0).receiveSecurityFrame(y.data)).toBe(false);
      expect(g.doc(0).document).toEqual([]);
      expect(await g.doc(0).receiveSecurityFrame(x.data)).toBe(true);
      expect(g.doc(0).document).toEqual([100, 101]);
      await g.doc(1).change((draft) => {
        draft.push(102);
      });
      expect(await g.deliver(g.take()[0], [0, 2])).toEqual([]);
      expect(g.doc(0).document).toEqual([100, 101, 102]);
      expect(g.doc(2).document).toEqual([100]);
      expect(await g.deliver(y, [2])).toEqual([]);
      expect(g.doc(2).document).toEqual([100, 101, 102]);
    } finally {
      await g.close();
    }
  });

  test('bounds each author’s held bytes so a far-ahead writer cannot starve another author', async () => {
    const g = await coordinatedGroupFixture(largeCRDT, testChanges, {
      members: 3,
    });
    try {
      await g.addMember(1);
      await g.addMember(2);
      for (let index = 0; index < 3; index++) await g.open(index);
      // Each frame carries about 477 KB, so 17 would fill the held bytes.
      const large = (round: number) =>
        push(
          ...Array.from(
            { length: 28_000 },
            (_, index) => 1e15 + round * 28_000 + index,
          ),
        );
      for (let round = 0; round < 20; round++)
        await g.doc(1).change(large(round));
      const heavy = g.take();
      await g.doc(2).change(push(1));
      await g.doc(2).change(push(2));
      const honest = g.take();
      for (const publication of heavy.slice(2).reverse())
        expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
          false,
        );
      expect(await g.doc(0).receiveSecurityFrame(honest[1].data)).toBe(false);
      expect(await g.doc(0).receiveSecurityFrame(honest[0].data)).toBe(true);
      expect(g.doc(0).document).toEqual([1, 2]);
      for (const publication of heavy.slice(0, 2))
        expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
          true,
        );
      // Only the eight nearest frames fit the author's 4 MiB share.
      expect(g.doc(0).document).toHaveLength(2 + 10 * 28_000);
      for (const publication of heavy.slice(10))
        expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
          true,
        );
      expect(g.doc(0).document).toEqual([1, 2, ...g.doc(1).document]);
    } finally {
      await g.close();
    }
  }, 120_000);

  test('evicts the farthest frame of the author with the largest share when held frames reach their bound', async () => {
    const g = await coordinatedGroupFixture(testCRDT, testChanges, {
      members: 4,
    });
    try {
      for (let index = 1; index < 4; index++) await g.addMember(index);
      for (let index = 0; index < 4; index++) await g.open(index);
      // The second writer's values are longer, so it holds more bytes.
      const values = (author: number, length: number) =>
        Array.from({ length }, (_, value) => author ** 7 * 1000 + value);
      const chains: Awaited<ReturnType<typeof g.take>>[] = [];
      for (const author of [1, 2]) {
        for (const value of values(author, 34))
          await g.doc(author).change(push(value));
        chains.push(g.take());
      }
      for (const chain of chains)
        for (const publication of chain.slice(2))
          expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
            false,
          );
      // The honest author's 17 KB frames hold more bytes than either writer,
      // but a far smaller share of its frame count.
      const big = (offset: number) =>
        Array.from({ length: 1000 }, (_, index) => 1e15 + offset + index);
      await g.doc(3).change(push(...big(0)));
      await g.doc(3).change(push(...big(1000)));
      const honest = g.take();
      expect(await g.doc(0).receiveSecurityFrame(honest[1].data)).toBe(false);
      expect(await g.doc(0).receiveSecurityFrame(honest[0].data)).toBe(true);
      expect(g.doc(0).document).toEqual([...big(0), ...big(1000)]);
      for (const chain of chains)
        for (const publication of chain.slice(0, 2))
          expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
            true,
          );
      expect(g.doc(0).document).toEqual([
        ...big(0),
        ...big(1000),
        ...values(1, 34),
        ...values(2, 33),
      ]);
      expect(await g.doc(0).receiveSecurityFrame(chains[1][33].data)).toBe(
        true,
      );
    } finally {
      await g.close();
    }
  }, 60_000);

  test('expires a held frame after two minutes', async () => {
    const f = await documentFixture(),
      a = create(f),
      b = create(f);
    await a.activate();
    await b.activate();
    const frames = await writes(a, [1, 2, 3]);
    const start = performance.now();
    const now = jest.spyOn(performance, 'now').mockReturnValue(start);
    try {
      expect(await b.receive(frames[2])).toBe(false);
      now.mockReturnValue(start + 120_001);
      expect(await b.receive(frames[1])).toBe(false);
      expect(await b.receive(frames[0])).toBe(true);
      expect(b.document).toEqual([1, 2]);
      expect(await b.receive(frames[2])).toBe(true);
      expect(b.document).toEqual([1, 2, 3]);
    } finally {
      now.mockRestore();
      await a.close();
      await b.close();
    }
  });

  test('retries a held frame before expiring it when its predecessor arrives late', async () => {
    const f = await documentFixture(),
      a = create(f),
      b = create(f);
    await a.activate();
    await b.activate();
    const frames = await writes(a, [1, 2]);
    const start = performance.now();
    const now = jest.spyOn(performance, 'now').mockReturnValue(start);
    try {
      expect(await b.receive(frames[1])).toBe(false);
      now.mockReturnValue(start + 120_001);
      expect(await b.receive(frames[0])).toBe(true);
      expect(b.document).toEqual([1, 2]);
    } finally {
      now.mockRestore();
      await a.close();
      await b.close();
    }
  });

  test('expires held frames in a document that receives nothing more', async () => {
    const f = await documentFixture(),
      a = create(f),
      b = create(f);
    await a.activate();
    await b.activate();
    const frames = await writes(a, [1, 2, 3]);
    const held = () =>
      (b as unknown as { held?: { frames: unknown[] } }).held?.frames.length ??
      0;
    jest.useFakeTimers({
      doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
    });
    try {
      expect(await b.receive(frames[2])).toBe(false);
      expect(held()).toBe(1);
      jest.advanceTimersByTime(119_000);
      expect(held()).toBe(1);
      jest.advanceTimersByTime(1_000);
      expect(held()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
    expect(await b.receive(frames[0])).toBe(true);
    expect(await b.receive(frames[1])).toBe(true);
    expect(b.document).toEqual([1, 2]);
    await a.close();
    await b.close();
  });

  test('retries a frame held for a native dependency only once that dependency is accepted', async () => {
    const attempts = new Map<number, number>();
    const namedCRDT: typeof testCRDT = {
      ...testCRDT,
      createDocumentSession(initial) {
        const session = testCRDT.createDocumentSession!(initial);
        const prepareRemote = session.prepareRemote.bind(session);
        return Object.assign(session, {
          prepareRemote(changes: number[]) {
            for (const value of changes)
              attempts.set(value, (attempts.get(value) ?? 0) + 1);
            const missing = changes
              .filter(
                (value) =>
                  value % 100 !== 0 &&
                  !changes.includes(value - 1) &&
                  !session.document.includes(value - 1),
              )
              .map((value) => value - 1);
            if (missing.length !== 0)
              throw new DocumentCausalDependencyError(() =>
                missing.every((value) => session.document.includes(value)),
              );
            return prepareRemote(changes);
          },
        });
      },
    };
    const g = await coordinatedGroupFixture(namedCRDT, testChanges, {
      members: 4,
    });
    try {
      for (let index = 1; index < 4; index++) await g.addMember(index);
      for (let index = 0; index < 4; index++) await g.open(index);
      await g.doc(2).change(push(100));
      const [x] = g.take();
      expect(await g.deliver(x, [1])).toEqual([]);
      await g.doc(1).change(push(101));
      const [y] = g.take();
      expect(await g.doc(0).receiveSecurityFrame(y.data)).toBe(false);
      for (let value = 200; value < 220; value++)
        await g.doc(3).change(push(value));
      for (const publication of g.take())
        expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
          true,
        );
      expect(attempts.get(101)).toBe(1);
      expect(await g.doc(0).receiveSecurityFrame(x.data)).toBe(true);
      expect(attempts.get(101)).toBe(2);
      expect(g.doc(0).document).toEqual([
        ...Array.from({ length: 20 }, (_, index) => 200 + index),
        100,
        101,
      ]);
    } finally {
      await g.close();
    }
  });

  test('evicts across documents when the process bound is full and refuses an author past its share before evicting others', async () => {
    type Group = Awaited<ReturnType<typeof coordinatedGroupFixture>>;
    const groups: Group[] = [];
    const heldIn = (g: Group) =>
      (
        g.doc(0) as unknown as {
          _coordinated: { held?: { frames: unknown[] } };
        }
      )._coordinated.held?.frames.length ?? 0;
    try {
      // Four writers each fill their quarter of the process-wide bound with
      // 32 far-ahead frames in each of eight documents.
      for (let index = 0; index < 17; index++) {
        const g = await coordinatedGroupFixture(testCRDT, testChanges, {
          members: 6,
          journal: false,
        });
        groups.push(g);
        for (let member = 1; member < 6; member++) await g.addMember(member);
        for (let member = 0; member < 6; member++) await g.open(member);
        if (index === 16) break;
        for (const author of index < 8 ? [1, 2] : [3, 4]) {
          for (let value = 0; value < 34; value++)
            await g.doc(author).change(push(value));
          for (const publication of g.take().slice(2))
            expect(await g.doc(0).receiveSecurityFrame(publication.data)).toBe(
              false,
            );
        }
        expect(heldIn(g)).toBe(64);
      }
      const crowded = groups[8];
      for (let value = 0; value < 3; value++)
        await crowded.doc(1).change(push(value));
      await expect(
        crowded.doc(0).receiveSecurityFrame(crowded.take()[2].data),
      ).rejects.toThrow('exceed their bound');
      expect(heldIn(crowded)).toBe(64);
      const idle = groups[16];
      await idle.doc(5).change(push(1));
      await idle.doc(5).change(push(2));
      const honest = idle.take();
      expect(await idle.doc(0).receiveSecurityFrame(honest[1].data)).toBe(
        false,
      );
      expect(groups.slice(0, 16).reduce((sum, g) => sum + heldIn(g), 0)).toBe(
        1023,
      );
      expect(await idle.doc(0).receiveSecurityFrame(honest[0].data)).toBe(true);
      expect(idle.doc(0).document).toEqual([1, 2]);
    } finally {
      for (const g of groups) await g.close();
    }
  }, 240_000);

  test('does not hold a frame whose receive finishes after close', async () => {
    const f = await documentFixture(),
      a = create(f),
      b = create(f);
    await a.activate();
    await b.activate();
    const [, second] = await writes(a, [1, 2]);
    const verify = f.auth.verify;
    let entered!: () => void, release!: () => void;
    const verifying = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    f.auth.verify = async (...args) => {
      entered();
      await released;
      return verify(...args);
    };
    try {
      const receiving = b.receive(second);
      await verifying;
      const closing = b.close();
      release();
      await expect(receiving).rejects.toThrow('reopened');
      await closing;
      expect((b as unknown as { held?: unknown }).held).toBeUndefined();
    } finally {
      f.auth.verify = verify;
      release();
      await a.close();
    }
  });
});
