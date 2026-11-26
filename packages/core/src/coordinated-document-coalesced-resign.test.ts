import { describe, expect, jest, test } from '@jest/globals';
import {
  documentFrameNonce,
  splitDocumentPublication,
} from './document-security-wire.js';
import { documentBytesId } from './internal/document-binary.js';
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

interface Engine {
  apply(...args: unknown[]): Promise<Uint8Array>;
  options: {
    journal: { pendingPublications(): Promise<readonly Uint8Array[]> };
  };
}
const engine = (document: unknown) =>
  (document as { _coordinated: Engine })._coordinated;
const rows = (document: unknown) =>
  engine(document).options.journal.pendingPublications();

/** Fail every re-sign at `document` after the first `allowed`, until restored. */
function failResigns(document: unknown, allowed = 0) {
  const target = engine(document);
  const apply = target.apply;
  let resigns = 0;
  target.apply = async function (this: Engine, ...args: unknown[]) {
    if (args[4] !== undefined && ++resigns > allowed)
      throw new Error('transient re-sign failure');
    return apply.apply(this, args);
  };
  return () => {
    target.apply = apply;
  };
}

async function group(options: Omit<CoordinatedGroupOptions, 'members'> = {}) {
  const dropped: number[] = [];
  const g = await coordinatedGroupFixture(testCRDT, testChanges, {
    members: 2,
    subscribers: true,
    security: { onPublicationsDropped: (frames) => dropped.push(frames) },
    ...options,
  });
  await g.addMember(1);
  await g.open(0);
  await g.open(1);
  /** Member 1 writes `values` while it reaches no peer. */
  const offline = async (values: readonly number[]) => {
    g.offline.add(1);
    for (const value of values) await g.doc(1).change(push(value));
    g.take();
  };
  /** Bring member 1 online and deliver everything it sends to member 0. */
  const deliver = async () => {
    g.offline.delete(1);
    const report = await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    const sent = g.take();
    for (const publication of sent)
      errors.push(...(await g.deliver(publication, [0])));
    return { report, errors, sent };
  };
  return { g, dropped, offline, deliver };
}

const nonces = (publications: readonly Uint8Array[]) =>
  publications
    .flatMap((publication) => splitDocumentPublication(publication))
    .map((frame) => documentBytesId(documentFrameNonce(frame)));

const range = (count: number) =>
  Array.from({ length: count }, (_, value) => value + 1);

describe('coalesced coordinated publications across an epoch change', () => {
  test('re-signs an offline backlog of several full publications and delivers all of it', async () => {
    const { g, dropped, offline, deliver } = await group();
    try {
      const values = range(1100);
      await offline(values);
      const retired = await rows(g.doc(1));
      expect(retired).toHaveLength(2);
      expect(splitDocumentPublication(retired[0])).toHaveLength(1024);
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.coordinators[1].applyCommit(
        renewal.delivery.commit!,
        renewal.delivery.controlRecord,
        [],
      );
      await expect(
        g.doc(1).applySecurityAuthorityUpdate(renewal.record),
      ).resolves.toEqual({
        resent: 1100,
        waiting: 0,
        skipped: 0,
        dropped: 0,
        diverged: false,
      });
      // Every retired frame left the outbox once its re-signed copy was queued.
      const queued = await rows(g.doc(1));
      expect(queued).toHaveLength(2);
      const original = new Set(nonces(retired));
      expect(nonces(queued).filter((id) => original.has(id))).toEqual([]);
      expect(nonces(queued)).toHaveLength(1100);
      const { report, errors, sent } = await deliver();
      expect(report).toMatchObject({ pending: false, dropped: 0 });
      expect(sent).toHaveLength(2);
      expect(errors).toEqual([]);
      expect(g.doc(0).document).toEqual(values);
      expect(dropped).toEqual([]);
    } finally {
      await g.close();
    }
  }, 300_000);

  test('keeps an offline backlog re-signable across a restart past several journal checkpoints', async () => {
    const { g, dropped, offline, deliver } = await group();
    try {
      const values = range(300);
      await offline(values);
      await g.doc(1).close();
      await g.open(1);
      g.take();
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.coordinators[1].applyCommit(
        renewal.delivery.commit!,
        renewal.delivery.controlRecord,
        [],
      );
      await expect(
        g.doc(1).applySecurityAuthorityUpdate(renewal.record),
      ).resolves.toMatchObject({ resent: 300, waiting: 0, dropped: 0 });
      const { report, errors } = await deliver();
      expect(report).toMatchObject({ pending: false, dropped: 0 });
      expect(errors).toEqual([]);
      expect(g.doc(0).document).toEqual(values);
      await g.doc(1).change(push(301));
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([...values, 301]);
      expect(dropped).toEqual([]);
    } finally {
      await g.close();
    }
  }, 120_000);

  test('re-signs at open a backlog whose epoch changed while the document was closed', async () => {
    const { g, dropped, offline } = await group();
    try {
      const values = range(200);
      await offline(values);
      await g.doc(1).close();
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.coordinators[1].applyCommit(
        renewal.delivery.commit!,
        renewal.delivery.controlRecord,
        [],
      );
      await g.logs[1].applyUpdate(g.coordinators[1], renewal.record);
      g.offline.delete(1);
      g.take();
      // Opening retries publications while the retired ones still wait.
      await g.open(1);
      const report = await g.doc(1).retrySecurityPublications();
      expect(report.dropped).toBe(0);
      const errors: string[] = [];
      for (const publication of g.take())
        errors.push(...(await g.deliver(publication, [0])));
      expect(errors).toEqual([]);
      expect(g.doc(0).document).toEqual(values);
      expect(dropped).toEqual([]);
    } finally {
      await g.close();
    }
  }, 120_000);

  test('keeps waiting re-signs and their retired publication across a restart', async () => {
    const { g, dropped, offline, deliver } = await group();
    try {
      await offline([1, 2, 3]);
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.coordinators[1].applyCommit(
        renewal.delivery.commit!,
        renewal.delivery.controlRecord,
        [],
      );
      const restore = failResigns(g.doc(1));
      await expect(
        g.doc(1).applySecurityAuthorityUpdate(renewal.record),
      ).resolves.toMatchObject({ resent: 0, waiting: 3 });
      restore();
      await expect(g.doc(1).retrySecurityPublications()).resolves.toEqual({
        sent: 0,
        pending: true,
        dropped: 0,
      });
      // The role transition's checkpoint folded the frames' journal entries.
      await g.doc(1).close();
      await g.open(1);
      const { report, errors } = await deliver();
      expect(report).toMatchObject({ pending: false, dropped: 0 });
      expect(errors).toEqual([]);
      expect(g.doc(0).document).toEqual([1, 2, 3]);
      expect(dropped).toEqual([]);
    } finally {
      await g.close();
    }
  }, 60_000);

  test('rewrites a retired publication without its re-signed frames and keeps the rest queued', async () => {
    const { g, dropped, offline, deliver } = await group();
    try {
      await offline([1, 2, 3]);
      const [retired] = await rows(g.doc(1));
      const parts = splitDocumentPublication(retired);
      expect(parts).toHaveLength(3);
      const renewal = await g.renew();
      await g.applyRenewal(0, renewal);
      await g.coordinators[1].applyCommit(
        renewal.delivery.commit!,
        renewal.delivery.controlRecord,
        [],
      );
      const restore = failResigns(g.doc(1), 1);
      await expect(
        g.doc(1).applySecurityAuthorityUpdate(renewal.record),
      ).resolves.toMatchObject({ resent: 1, waiting: 2 });
      restore();
      const queued = await rows(g.doc(1));
      expect(queued).toHaveLength(2);
      // The retired publication keeps its place and its unsent frames.
      expect(splitDocumentPublication(queued[0])).toEqual(parts.slice(1));
      expect(splitDocumentPublication(queued[1])).toHaveLength(1);
      const { report, errors } = await deliver();
      expect(report).toMatchObject({ pending: false, dropped: 0 });
      expect(errors).toEqual([]);
      expect(g.doc(0).document).toEqual([1, 2, 3]);
      expect(await rows(g.doc(1))).toEqual([]);
      expect(dropped).toEqual([]);
    } finally {
      await g.close();
    }
  }, 60_000);
});
