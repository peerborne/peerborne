import { describe, expect, jest, test } from '@jest/globals';
import { createGroupSecurityDurableAcceptance } from './group-security-durable-acceptance.js';
import type { GroupSecurityDelivery } from './group-security-coordinator.js';
import { DocumentPublicationBacklogError } from './coordinated-document.js';
import {
  encodeEncryptedDocumentContent,
  splitDocumentPublication,
} from './document-security-wire.js';
import { testCRDT, testChanges } from './__testutils__/coordinated-document.js';
import {
  coordinatedGroupFixture,
  type CoordinatedGroupOptions,
} from './__testutils__/coordinated-group.js';

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

async function group(
  members: number,
  options: Omit<CoordinatedGroupOptions, 'members'> = {},
) {
  const g = await coordinatedGroupFixture(testCRDT, testChanges, {
    members,
    ...options,
  });
  for (let index = 1; index < members; index++) await g.addMember(index);
  for (let index = 0; index < members; index++) await g.open(index);
  return g;
}

async function settled(condition: () => boolean) {
  for (let turn = 0; !condition() && turn < 1000; turn++)
    await new Promise((resolve) => setTimeout(resolve, 1));
  return condition();
}

/** Publications waiting in a member's received queue. */
function queued(document: unknown): number {
  return (
    document as {
      _coordinated: { inbound: { usage: { operations: number } } };
    }
  )._coordinated.inbound.usage.operations;
}

function blockVerification(auth: { verify: (...args: never[]) => unknown }) {
  const verify = auth.verify;
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  auth.verify = (async (...args: never[]) => {
    await released;
    return verify(...args);
  }) as typeof verify;
  return () => {
    auth.verify = verify;
    release();
  };
}

describe('coordinated document delivery', () => {
  test('keeps publications that reached no topic peer, joins later frames to them and sends them in order', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      await g.doc(1).change(push(1));
      await g.doc(1).change(push(2));
      const attempts = g.take();
      expect(attempts).toHaveLength(2);
      expect(splitDocumentPublication(attempts[1].data)).toEqual([
        ...splitDocumentPublication(attempts[0].data),
        expect.any(Uint8Array),
      ]);
      g.offline.delete(1);
      await expect(g.doc(1).retrySecurityPublications()).resolves.toEqual({
        sent: 1,
        pending: false,
        dropped: 0,
      });
      const resent = g.take();
      expect(resent).toHaveLength(1);
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

  test('keeps editing offline across a restart far beyond the publication bound and converges once a peer appears', async () => {
    const g = await group(2, { subscribers: true });
    try {
      const values = Array.from({ length: 300 }, (_, value) => value);
      g.offline.add(1);
      for (const value of values.slice(0, 150))
        await g.doc(1).change(push(value));
      await g.doc(1).close();
      await g.open(1);
      for (const value of values.slice(150)) await g.doc(1).change(push(value));
      expect(g.take()).toEqual([]);
      g.offline.delete(1);
      const report = await g.doc(1).retrySecurityPublications();
      expect(report).toMatchObject({ pending: false, dropped: 0 });
      const sent = g.take();
      expect(sent.length).toBe(report.sent);
      expect(sent.length).toBeLessThanOrEqual(3);
      for (const publication of sent)
        expect(await g.deliver(publication, [0])).toEqual([]);
      expect(g.doc(0).document).toEqual(values);
      await g.doc(1).change(push(300));
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([...values, 300]);
    } finally {
      await g.close();
    }
  });

  test('refuses a change with a clear error once unsent frames fill the outbox, and resumes after delivery', async () => {
    const g = await group(2, { subscribers: true });
    try {
      // Each change seals close to half of one 1 MiB publication.
      const large =
        (offset: number) =>
        (document: number[]): void => {
          for (let index = 0; index < 28_000; index++)
            document.push(1e15 + offset * 28_000 + index);
        };
      g.offline.add(1);
      let accepted = 0,
        failure: unknown;
      for (let round = 0; round < 40 && failure === undefined; round++) {
        try {
          await g.doc(1).change(large(round));
          accepted++;
        } catch (error) {
          failure = error;
        }
      }
      expect(failure).toBeInstanceOf(DocumentPublicationBacklogError);
      expect((failure as Error).message).toMatch(/16 MiB/);
      expect(accepted).toBeGreaterThan(16);
      expect(g.doc(1).document).toHaveLength(accepted * 28_000);
      g.offline.delete(1);
      await expect(g.doc(1).retrySecurityPublications()).resolves.toMatchObject(
        { pending: false },
      );
      g.take();
      await g.doc(1).change(push(-1));
      expect(g.take()).toHaveLength(1);
    } finally {
      await g.close();
    }
  }, 120_000);

  test('retries restored publications at open for peers that subscribed before it', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      await g.doc(1).change(push(4));
      await g.doc(1).change(push(5));
      await g.doc(1).close();
      g.take();
      g.offline.delete(1);
      await g.open(1);
      expect(await settled(() => g.publications.length === 1)).toBe(true);
      for (const publication of g.take())
        expect(await g.deliver(publication, [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([4, 5]);
    } finally {
      await g.close();
    }
  });

  test('drops and reports unsent frames sealed for an earlier group epoch', async () => {
    const g = await group(2);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      g.offline.add(1);
      await g.doc(1).change(push(1));
      await g.doc(1).change(push(2));
      g.take();
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.applyRenewal(1, renewal);
      g.offline.delete(1);
      await expect(g.doc(1).retrySecurityPublications()).resolves.toEqual({
        sent: 0,
        pending: false,
        dropped: 2,
      });
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('dropped 2'));
      expect(g.take()).toEqual([]);
      await g.doc(1).change(push(3));
      for (const publication of g.take())
        expect(await g.deliver(publication, [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([3]);
    } finally {
      warn.mockRestore();
      await g.close();
    }
  });

  test('refuses frames that do not decrypt under the current epoch without holding queue capacity', async () => {
    const g = await group(2);
    try {
      await g.doc(1).change(push(0));
      const [genuine] = g.take();
      const tag = genuine.data.slice(4, 20);
      const junk = () =>
        encodeEncryptedDocumentContent(
          tag,
          crypto.getRandomValues(new Uint8Array(12)),
          crypto.getRandomValues(new Uint8Array(64)),
        );
      const values = Array.from({ length: 41 }, (_, value) => value + 1);
      for (const value of values) await g.doc(1).change(push(value));
      const honest = g.take();
      const resume = blockVerification(g.auth);
      try {
        g.dispatch(genuine, 0, 'writer');
        for (let index = 0; index < 255; index++)
          g.dispatch(
            { topic: genuine.topic, data: junk() },
            0,
            `intruder-${index % 4}`,
          );
        expect(await settled(() => queued(g.doc(0)) === 1)).toBe(true);
        for (const publication of honest) g.dispatch(publication, 0, 'writer');
        expect(queued(g.doc(0))).toBe(1 + honest.length);
      } finally {
        resume();
      }
      expect(await settled(() => g.doc(0).document.length === 42)).toBe(true);
      expect(g.doc(0).document).toEqual([0, ...values]);
    } finally {
      await g.close();
    }
  });

  test('limits one sender to half of the received queue', async () => {
    const g = await group(2);
    try {
      await g.doc(1).change(push(0));
      const [accepted] = g.take();
      expect(await g.deliver(accepted, [0])).toEqual([]);
      const values = Array.from({ length: 41 }, (_, value) => value + 1);
      for (const value of values) await g.doc(1).change(push(value));
      const honest = g.take();
      const resume = blockVerification(g.auth);
      try {
        g.dispatch(honest[0], 0, 'writer');
        for (let index = 0; index < 255; index++)
          g.dispatch(accepted, 0, 'replayer');
        expect(await settled(() => queued(g.doc(0)) === 129)).toBe(true);
        for (const publication of honest.slice(1))
          g.dispatch(publication, 0, 'writer');
        expect(queued(g.doc(0))).toBe(129 + honest.length - 1);
      } finally {
        resume();
      }
      expect(await settled(() => g.doc(0).document.length === 42)).toBe(true);
      expect(g.doc(0).document).toEqual([0, ...values]);
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
