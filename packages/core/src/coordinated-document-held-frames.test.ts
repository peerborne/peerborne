import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { CoordinatedDocument } from './coordinated-document.js';
import { DocumentCausalDependencyError } from './document-crdt-session.js';
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
  });

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
});
