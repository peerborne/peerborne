import { describe, expect, jest, test } from '@jest/globals';
import { createGroupSecurityDurableAcceptance } from './group-security-durable-acceptance.js';
import type { GroupSecurityDelivery } from './group-security-coordinator.js';
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

const push =
  (value: number) =>
  (document: number[]): void => {
    document.push(value);
  };

async function group(members: number) {
  const g = await coordinatedGroupFixture(testCRDT, testChanges, { members });
  for (let index = 1; index < members; index++) await g.addMember(index);
  for (let index = 0; index < members; index++) await g.open(index);
  return g;
}

async function settled(condition: () => boolean) {
  for (let turn = 0; !condition() && turn < 1000; turn++)
    await new Promise((resolve) => setTimeout(resolve, 1));
  return condition();
}

describe('coordinated document delivery', () => {
  test('keeps publications that reached no topic peer and sends them in order', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      await g.doc(1).change(push(1));
      await g.doc(1).change(push(2));
      expect(g.take()).toHaveLength(2);
      g.offline.delete(1);
      await g.doc(1).retrySecurityPublications();
      const resent = g.take();
      expect(resent).toHaveLength(2);
      await g.doc(1).change(push(3));
      for (const publication of [...resent, ...g.take()])
        expect(await g.deliver(publication, [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([1, 2, 3]);
      await g.doc(1).retrySecurityPublications();
      expect(g.take()).toEqual([]);
    } finally {
      await g.close();
    }
  });

  test('retries kept publications when a peer subscribes to the document topic', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      await g.doc(1).change(push(7));
      const [first] = g.take();
      g.offline.delete(1);
      const subscription = (topic: string) =>
        new CustomEvent('subscription-change', {
          detail: { peerId: 'test-peer', subscriptions: [{ topic, subscribe: true }] },
        });
      g.pubsubs[1].dispatchEvent(subscription('another-topic'));
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(g.take()).toEqual([]);
      g.pubsubs[1].dispatchEvent(subscription(first.topic));
      expect(await settled(() => g.publications.length === 1)).toBe(true);
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([7]);
    } finally {
      await g.close();
    }
  });

  test('applies a burst larger than the local operation budget from the pubsub handler', async () => {
    const g = await group(2);
    try {
      const values = Array.from({ length: 40 }, (_, value) => value);
      for (const value of values) await g.doc(1).change(push(value));
      for (const publication of g.take()) g.dispatch(publication, 0);
      expect(
        await settled(() => g.doc(0).document.length === values.length),
      ).toBe(true);
      expect(g.doc(0).document).toEqual(values);
      await g.doc(1).change(push(40));
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([...values, 40]);
    } finally {
      await g.close();
    }
  });

  test('accepts content at the controller while a membership send is pending', async () => {
    const g = await group(2);
    try {
      await g.coordinators[0].createCommit(
        { changes: [] },
        {
          operationId: g.nextId(),
          requestDigest: g.nextId(),
          action: 'update',
          subjectId: g.members[0],
        },
      );
      let delivery!: GroupSecurityDelivery;
      await expect(
        g.coordinators[0].flushOutbox(async (pending) => {
          delivery = pending;
          throw new Error('recipient unreachable');
        }),
      ).rejects.toMatchObject({ code: 'delivery-failed' });
      const record = await g.signRoster();
      await g.doc(0).applySecurityAuthorityUpdate(record);
      await g.coordinators[1].applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        [],
      );
      await g.doc(1).applySecurityAuthorityUpdate(record);
      let entered!: () => void;
      let release!: () => void;
      const sending = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const flushing = g.coordinators[0].flushOutbox(async (pending) => {
        entered();
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return createGroupSecurityDurableAcceptance(pending);
      });
      await sending;
      await g.doc(1).change(push(5));
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([5]);
      release();
      await expect(flushing).resolves.toEqual({ delivered: 1, remaining: 0 });
    } finally {
      await g.close();
    }
  });
});
