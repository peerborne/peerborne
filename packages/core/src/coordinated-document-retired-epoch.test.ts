import { describe, expect, jest, test } from '@jest/globals';
import type { DocumentMemberAuthority } from './coordinated-document.js';
import { createGroupSecurityDurableAcceptance } from './group-security-durable-acceptance.js';
import type { GroupSecurityDelivery } from './group-security-coordinator.js';
import { documentBytesId } from './internal/document-binary.js';
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

/** Member 1 writes `values` while offline, then learns a renewed epoch with `writer` roles. */
async function offlineAcrossEpoch(
  values: number[],
  writer: Omit<DocumentMemberAuthority, 'memberId' | 'publicKey'>,
) {
  const g = await coordinatedGroupFixture(testCRDT, testChanges, { members: 2 });
  await g.addMember(1);
  await g.open(0);
  await g.open(1);
  const publish = g.pubsubs[1].publish;
  g.pubsubs[1].publish = async () => {
    throw new Error('offline');
  };
  for (const value of values)
    await expect(g.doc(1).change(push(value))).rejects.toThrow(
      'Document change committed',
    );
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
  await g.coordinators[0].flushOutbox(async (pending) => {
    delivery = pending;
    return createGroupSecurityDurableAcceptance(pending);
  });
  const record = await g.logs[0].signUpdate(
    g.coordinators[0].documentContext,
    [
      {
        memberId: g.members[0],
        publicKey: documentBytesId(g.members[0]),
        role: 3,
      },
      {
        memberId: g.members[1],
        publicKey: documentBytesId(g.members[1]),
        ...writer,
      },
    ],
    g.members[0],
  );
  await g.doc(0).applySecurityAuthorityUpdate(record);
  g.pubsubs[1].publish = publish;
  await g.coordinators[1].applyCommit(
    delivery.commit!,
    delivery.controlRecord,
    [],
  );
  const update = await g.doc(1).applySecurityAuthorityUpdate(record);
  await g.doc(1).retrySecurityPublications();
  const errors: string[] = [];
  const published = g.take();
  for (const publication of published)
    errors.push(...(await g.deliver(publication, [0])));
  return { g, update, published, errors };
}

describe('coordinated frames from a retired epoch', () => {
  test('re-signs a full outbox of unsent frames in order in the new epoch', async () => {
    const values = Array.from({ length: 16 }, (_, index) => index + 1);
    const { g, update, published, errors } = await offlineAcrossEpoch(values, {
      role: 2,
    });
    try {
      expect(update).toEqual({ resent: 16, dropped: 0 });
      expect(published).toHaveLength(16);
      expect(errors).toEqual([]);
      expect(g.doc(0).document).toEqual(values);
      await g.doc(1).change(push(17));
      expect(await g.deliver(g.take()[0], [0])).toEqual([]);
      expect(g.doc(0).document).toEqual([...values, 17]);
      await g.doc(1).retrySecurityPublications();
      expect(g.take()).toEqual([]);
    } finally {
      await g.close();
    }
  });

  test.each([
    ['a reader', { role: 1 as const }],
    ['a writer whose grants no longer cover the edit', { role: 2 as const, writePaths: [['other']] }],
  ])('drops and reports the unsent frames of %s', async (_label, writer) => {
    const { g, update, published } = await offlineAcrossEpoch([1, 2], writer);
    try {
      expect(update).toEqual({ resent: 0, dropped: 2 });
      expect(published).toEqual([]);
      expect(g.doc(0).document).toEqual([]);
      expect(g.doc(1).document).toEqual([1, 2]);
      await g.doc(1).retrySecurityPublications();
      expect(g.take()).toEqual([]);
    } finally {
      await g.close();
    }
  });
});
