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

interface Engine {
  inbound: { usage: { frames: number } };
  receive(frame: Uint8Array, sender?: string): Promise<boolean>;
  options: {
    journal: { pendingPublications(): Promise<readonly Uint8Array[]> };
  };
}
const engine = (document: unknown) =>
  (document as { _coordinated: Engine })._coordinated;

/** Frames waiting in a member's received queue. */
function queued(document: unknown): number {
  return engine(document).inbound.usage.frames;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(
    parts.reduce((sum, part) => sum + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}

function countVerifications(auth: { verify: (...args: never[]) => unknown }) {
  const verify = auth.verify;
  const counter = { calls: 0, restore: () => (auth.verify = verify) };
  auth.verify = ((...args: never[]) => {
    counter.calls++;
    return verify(...args);
  }) as typeof verify;
  return counter;
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
  }, 60_000);

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
      // Two changes share each publication, and the journal keeps one of
      // its 16 rows free to stage a replacement.
      expect(accepted).toBe(30);
      expect(
        await engine(g.doc(1)).options.journal.pendingPublications(),
      ).toHaveLength(15);
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

  test('re-signs unsent frames sealed for an earlier group epoch instead of dropping them', async () => {
    const dropped: number[] = [];
    const g = await group(2, {
      security: { onPublicationsDropped: (frames) => dropped.push(frames) },
    });
    try {
      g.offline.add(1);
      await g.doc(1).change(push(1));
      await g.doc(1).change(push(2));
      g.take();
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.applyRenewal(1, renewal);
      g.offline.delete(1);
      await g.doc(1).change(push(3));
      expect(dropped).toEqual([]);
      for (const publication of g.take())
        expect(await g.deliver(publication, [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([1, 2, 3]);
      await expect(g.doc(1).retrySecurityPublications()).resolves.toEqual({
        sent: 0,
        pending: false,
        dropped: 0,
      });
    } finally {
      await g.close();
    }
  });

  test('drops and reports retired frames its author can no longer re-sign', async () => {
    const dropped: number[] = [];
    const g = await group(2, {
      security: { onPublicationsDropped: (frames) => dropped.push(frames) },
    });
    try {
      g.offline.add(1);
      await g.doc(1).change(push(1));
      await g.doc(1).change(push(2));
      g.take();
      // As if the author's record of these frames had been evicted.
      (engine(g.doc(1)) as unknown as { own: { frames: unknown[] } }).own.frames.splice(0);
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.applyRenewal(1, renewal);
      g.offline.delete(1);
      // The change's own background retry reports the drop.
      await g.doc(1).change(push(3));
      expect(dropped).toEqual([2]);
      for (const publication of g.take())
        expect(await g.deliver(publication, [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([3]);
      await expect(g.doc(1).retrySecurityPublications()).resolves.toEqual({
        sent: 0,
        pending: false,
        dropped: 0,
      });
    } finally {
      await g.close();
    }
  });

  test('logs unsent frames dropped because their author became a reader when the application sets no handler', async () => {
    const g = await group(2);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      g.offline.add(1);
      await g.doc(1).change(push(1));
      g.take();
      g.roster[1] = { ...g.roster[1], role: 1 };
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.coordinators[1].applyCommit(
        renewal.delivery.commit!,
        renewal.delivery.controlRecord,
        [],
      );
      await expect(
        g.doc(1).applySecurityAuthorityUpdate(renewal.record),
      ).resolves.toMatchObject({ resent: 0, dropped: 1, diverged: false });
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('dropped 1'));
      g.offline.delete(1);
      await expect(g.doc(1).retrySecurityPublications()).resolves.toEqual({
        sent: 0,
        pending: false,
        dropped: 0,
      });
      expect(g.take()).toEqual([]);
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

  test('charges every frame and keeps one sender within a share that holds a full outbox', async () => {
    const g = await group(2);
    try {
      await g.doc(1).change(push(0));
      const [genuine] = g.take();
      const junk = encodeEncryptedDocumentContent(
        genuine.data.slice(4, 20),
        new Uint8Array(12),
        new Uint8Array(16),
      );
      const publication = concat(Array(1024).fill(junk));
      const receiver = engine(g.doc(0));
      const outcomes: Promise<unknown>[] = [];
      for (let index = 0; index < 20; index++)
        outcomes.push(receiver.receive(publication, 'flood').catch((e) => e));
      expect(queued(g.doc(0))).toBe(20 * 1024);
      await expect(
        receiver.receive(publication, 'flood'),
      ).rejects.toMatchObject({ code: 'capacity-exceeded' });
      outcomes.push(receiver.receive(publication, 'writer').catch((e) => e));
      expect(queued(g.doc(0))).toBe(21 * 1024);
      for (const outcome of await Promise.all(outcomes))
        expect((outcome as Error).message).toMatch(/does not decrypt/);
      expect(queued(g.doc(0))).toBe(0);
    } finally {
      await g.close();
    }
  });

  test('skips frames the author already delivered and refuses copies or mixed authors before any signature check', async () => {
    const g = await group(3);
    try {
      await g.doc(1).change(push(0));
      const [accepted] = g.take();
      expect(await g.deliver(accepted, [0])).toEqual([]);
      const copies = concat(
        Array(
          Math.min(1024, Math.floor((1024 * 1024) / accepted.data.length)),
        ).fill(accepted.data),
      );
      const verifications = countVerifications(g.auth);
      try {
        await expect(g.doc(0).receiveSecurityFrame(copies)).rejects.toThrow(
          /consecutive/,
        );
        await expect(
          g.doc(0).receiveSecurityFrame(accepted.data),
        ).resolves.toBe(false);
        expect(verifications.calls).toBe(0);
        await g.doc(1).change(push(1));
        const [next] = g.take();
        await g.doc(2).change(push(2));
        const [other] = g.take();
        // The authors' own changes verify their signatures locally.
        verifications.calls = 0;
        await expect(
          g.doc(0).receiveSecurityFrame(concat([next.data, other.data])),
        ).rejects.toThrow(/one author/);
        expect(verifications.calls).toBe(0);
        await expect(
          g.doc(0).receiveSecurityFrame(concat([accepted.data, next.data])),
        ).resolves.toBe(true);
        expect(verifications.calls).toBe(1);
      } finally {
        verifications.restore();
      }
      expect(g.doc(0).document).toEqual([0, 1]);
    } finally {
      await g.close();
    }
  });

  test('admits one copy of a publication that is still waiting and verifies each frame once', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      for (let value = 0; value < 50; value++)
        await g.doc(1).change(push(value));
      const publication = g.take().at(-1)!;
      expect(splitDocumentPublication(publication.data)).toHaveLength(50);
      const resume = blockVerification(g.auth);
      const verifications = countVerifications(g.auth);
      try {
        g.dispatch(publication, 0, 'writer');
        for (let index = 0; index < 5; index++)
          g.dispatch(publication, 0, `replayer-${index % 2}`);
        expect(queued(g.doc(0))).toBe(300);
        expect(await settled(() => queued(g.doc(0)) === 50)).toBe(true);
      } finally {
        resume();
      }
      expect(await settled(() => g.doc(0).document.length === 50)).toBe(true);
      expect(await settled(() => queued(g.doc(0)) === 0)).toBe(true);
      expect(verifications.calls).toBeLessThanOrEqual(50);
      verifications.restore();
      expect(g.doc(0).document).toEqual(
        Array.from({ length: 50 }, (_, value) => value),
      );
    } finally {
      await g.close();
    }
  }, 60_000);

  test('keeps room for another author while outsiders replay a waiting publication', async () => {
    const g = await group(3);
    try {
      g.offline.add(1);
      for (let value = 0; value < 200; value++)
        await g.doc(1).change(push(value));
      const publication = g.take().at(-1)!;
      g.offline.delete(1);
      await g.doc(2).change(push(-2));
      const [other] = g.take();
      const frames = splitDocumentPublication(publication.data);
      const resume = blockVerification(g.auth);
      let outcome: Promise<boolean>;
      try {
        g.dispatch(publication, 0, 'writer');
        // Two outsiders fill their whole shares synchronously.
        for (let index = 0; index < 102; index++)
          g.dispatch(publication, 0, 'r1');
        for (let index = 0; index < 102; index++)
          g.dispatch(publication, 0, 'r2');
        for (let index = 0; index < 1000; index++)
          g.dispatch(
            { topic: publication.topic, data: frames[index % 200] },
            0,
            'r3',
          );
        expect(queued(g.doc(0))).toBeLessThan(48 * 1024);
        outcome = engine(g.doc(0)).receive(other.data, 'member-2');
        expect(await settled(() => queued(g.doc(0)) === 201)).toBe(true);
      } finally {
        resume();
      }
      await expect(outcome).resolves.toBe(true);
      expect(await settled(() => g.doc(0).document.length === 201)).toBe(true);
    } finally {
      await g.close();
    }
  }, 60_000);

  test('gives a dropped copy another turn when the waiting frame it matched is neither applied nor held', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      for (let value = 0; value < 100; value++)
        await g.doc(1).change(push(value));
      const publication = g.take().at(-1)!;
      g.offline.delete(1);
      const frames = splitDocumentPublication(publication.data);
      const receiver = engine(g.doc(0));
      // A slice without the first frame overruns the author's held frames.
      const slice = receiver.receive(concat(frames.slice(1)), 'outsider');
      const genuine = receiver.receive(publication.data, 'writer');
      await expect(slice).rejects.toThrow('exceed their bound');
      await expect(genuine).resolves.toBe(true);
      const values = Array.from({ length: 100 }, (_, value) => value);
      expect(await settled(() => g.doc(0).document.length === 100)).toBe(true);
      expect(g.doc(0).document).toEqual(values);
      await g.doc(1).change(push(100));
      await expect(
        receiver.receive(g.take().at(-1)!.data, 'writer'),
      ).resolves.toBe(true);
      expect(g.doc(0).document).toEqual([...values, 100]);
    } finally {
      await g.close();
    }
  }, 60_000);

  test('releases each copy’s charge as soon as admission recognizes it', async () => {
    const g = await group(3);
    try {
      g.offline.add(1);
      for (let value = 0; value < 1024; value++)
        await g.doc(1).change(push(value));
      const publication = g.take().at(-1)!;
      g.offline.delete(1);
      expect(await g.deliver(publication, [0])).toEqual([]);
      await g.doc(2).change(push(-2));
      const [other] = g.take();
      const receiver = engine(g.doc(0));
      const copies: Promise<unknown>[] = [];
      for (let index = 0; index < 48; index++)
        copies.push(
          receiver.receive(publication.data, `r${index % 3}`).catch((e) => e),
        );
      expect(queued(g.doc(0))).toBe(48 * 1024);
      // Charges come back frame by frame, not a whole publication at a time.
      expect(
        await settled(() => {
          const frames = queued(g.doc(0));
          return frames > 0 && frames % 1024 !== 0;
        }),
      ).toBe(true);
      await expect(receiver.receive(other.data, 'member-2')).resolves.toBe(
        true,
      );
      expect(await Promise.all(copies)).toEqual(Array(48).fill(false));
      expect(queued(g.doc(0))).toBe(0);
    } finally {
      await g.close();
    }
  }, 110_000);

  test('recognizes copies of an accepted publication at thousands of frames per second', async () => {
    const g = await group(2);
    try {
      g.offline.add(1);
      for (let value = 0; value < 1024; value++)
        await g.doc(1).change(push(value));
      const publication = g.take().at(-1)!;
      g.offline.delete(1);
      expect(await g.deliver(publication, [0])).toEqual([]);
      const receiver = engine(g.doc(0));
      const start = performance.now();
      const copies = Array.from({ length: 16 }, (_, index) =>
        receiver.receive(publication.data, `r${index % 2}`),
      );
      expect(await Promise.all(copies)).toEqual(Array(16).fill(false));
      // Under a second locally; comparing contexts for every frame took nine.
      expect(performance.now() - start).toBeLessThan(5_000);
      expect(queued(g.doc(0))).toBe(0);
    } finally {
      await g.close();
    }
  }, 60_000);

  test('applies live edits sent while a reconnect backlog drains and keeps the author live', async () => {
    const g = await group(2, { subscribers: true });
    try {
      g.offline.add(1);
      const backlog = 300,
        live = 130;
      for (let value = 0; value < backlog; value++)
        await g.doc(1).change(push(value));
      g.offline.delete(1);
      await g.doc(1).retrySecurityPublications();
      const reconnect = g.take();
      const edits: typeof reconnect = [];
      for (let value = backlog; value < backlog + live; value++) {
        await g.doc(1).change(push(value));
        edits.push(...g.take());
      }
      for (const publication of [...reconnect, ...edits])
        g.dispatch(publication, 0, 'writer');
      const values = Array.from(
        { length: backlog + live },
        (_, value) => value,
      );
      for (
        let turn = 0;
        g.doc(0).document.length < values.length && turn < 6000;
        turn++
      )
        await new Promise((resolve) => setTimeout(resolve, 10));
      expect(g.doc(0).document).toEqual(values);
      await g.doc(1).change(push(-1));
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([...values, -1]);
    } finally {
      await g.close();
    }
  }, 120_000);

  test('joins concurrent offline changes into one publication and keeps editing far past 16 changes', async () => {
    const g = await group(2, { subscribers: true });
    try {
      g.offline.add(1);
      await Promise.all(
        Array.from({ length: 15 }, (_, value) => g.doc(1).change(push(value))),
      );
      const outbox = engine(g.doc(1)).options.journal;
      expect(await outbox.pendingPublications()).toHaveLength(1);
      for (let value = 15; value < 1100; value++)
        await g.doc(1).change(push(value));
      const rows = await outbox.pendingPublications();
      expect(rows).toHaveLength(2);
      expect(rows.map((row) => splitDocumentPublication(row).length)).toEqual([
        1024, 76,
      ]);
    } finally {
      await g.close();
    }
  }, 120_000);

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
