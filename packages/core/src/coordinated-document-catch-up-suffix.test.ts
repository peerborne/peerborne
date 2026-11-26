import { describe, expect, jest, test } from '@jest/globals';
import { testCRDT, testChanges } from './__testutils__/coordinated-document.js';
import { coordinatedGroupFixture } from './__testutils__/coordinated-group.js';

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

/** Deltas carry `padding` filler values, so frames are large while snapshots stay small. */
const paddedCRDT = (padding: number): typeof testCRDT => ({
  ...testCRDT,
  createDocumentSession(initial) {
    const session = testCRDT.createDocumentSession!(initial);
    const local = session.prepareLocal.bind(session);
    const remote = session.prepareRemote.bind(session);
    return Object.assign(session, {
      prepareLocal(...args: Parameters<typeof local>) {
        const plan = local(...args);
        return { ...plan, changes: [...plan.changes, ...Array(padding).fill(0)] };
      },
      prepareRemote(changes: number[]) {
        return remote(changes.filter((value) => value !== 0));
      },
      prepareMergeSnapshot(snapshot: number[]) {
        return session.prepareSnapshot!([
          ...new Set([...session.document, ...snapshot]),
        ]);
      },
    });
  },
});

/** Member 2 misses `missed` frames of member 1 and one frame of the controller. */
async function missedTails(padding: number, missed: number) {
  const g = await coordinatedGroupFixture(paddedCRDT(padding), testChanges, {
    members: 3,
    catchUp: true,
  });
  await g.addMember(1);
  await g.addMember(2);
  for (let index = 0; index < 3; index++) await g.open(index);
  let next = 1000;
  const edit = async (author: number, recipients: number[]) => {
    const value = next++;
    await g.doc(author).change((draft) => {
      draft.push(value);
    });
    for (const publication of g.take())
      expect(await g.deliver(publication, recipients)).toEqual([]);
    return value;
  };
  const values = [await edit(1, [0, 2]), await edit(0, [1, 2])];
  values.push(await edit(0, [1]));
  for (let index = 0; index < missed; index++) values.push(await edit(1, [0]));
  const catchUp = async () => {
    const request = await g.doc(2).createSecurityCatchUpRequest();
    await g
      .doc(2)
      .applySecurityCatchUpCheckpoint(
        await g.doc(0).createSecurityCatchUpCheckpoint(request),
      );
  };
  return { g, values, edit, catchUp };
}

describe('catch-up suffixes beyond one checkpoint', () => {
  test('advances a writer whose missed tail exceeds one checkpoint over several rounds', async () => {
    const { g, values, edit, catchUp } = await missedTails(9000, 60);
    try {
      await catchUp();
      expect([...g.doc(2).document].sort()).toEqual([...values].sort());
      const controller = await edit(0, [2]);
      expect(g.doc(2).document).toContain(controller);
      const early = await edit(1, [2]);
      expect(g.doc(2).document).not.toContain(early);
      await catchUp();
      expect(g.doc(2).document).toContain(early);
      const writer = await edit(1, [2]);
      expect(g.doc(2).document).toContain(writer);
    } finally {
      await g.close();
    }
  }, 120_000);

  test('keeps another writer’s retained tail when one writer sends large frames', async () => {
    const { g, edit, catchUp } = await missedTails(160_000, 30);
    try {
      await catchUp();
      const controller = await edit(0, [2]);
      expect(g.doc(2).document).toContain(controller);
    } finally {
      await g.close();
    }
  }, 120_000);
});
