import { expect, jest, test } from '@jest/globals';
import type { Doc } from 'yjs';
import { YjsJSONSerializer, YjsProvider } from './peerborne-yjs.js';
import { coordinatedGroupFixture } from '../../core/src/__testutils__/coordinated-group.js';
import { createGroupSecurityDurableAcceptance } from '../../core/src/group-security-durable-acceptance.js';
import type { GroupSecurityDelivery } from '../../core/src/group-security-coordinator.js';
import { DocumentDivergedError } from '../../core/src/coordinated-document.js';
import { documentBytesId } from '../../core/src/internal/document-binary.js';

jest.mock('@helia/unixfs', () => ({ unixfs: () => ({}) }));

const set =
  (key: string, value = 1) =>
  (document: Doc) => {
    document.getMap('m').set(key, value);
  };
const read = (document: Doc) => document.getMap('m').toJSON();

async function restrict(g: any, writePaths: string[][]) {
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
  await g.coordinators[0].flushOutbox(
    async (pending: GroupSecurityDelivery) => {
      delivery = pending;
      return createGroupSecurityDurableAcceptance(pending);
    },
  );
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
        role: 2,
        writePaths,
      },
    ],
    g.members[0],
  );
  await g.doc(0).applySecurityAuthorityUpdate(record);
  return async () => {
    await g.coordinators[1].applyCommit(
      delivery.commit!,
      delivery.controlRecord,
      [],
    );
    return g.doc(1).applySecurityAuthorityUpdate(record);
  };
}

async function offlineEdit(key: string) {
  const g: any = await coordinatedGroupFixture(
    new YjsProvider() as any,
    new YjsJSONSerializer() as any,
    { members: 2 },
  );
  await g.addMember(1);
  await g.open(0);
  await g.open(1);
  await g.doc(0).change(set('c'));
  for (const publication of g.take())
    expect(await g.deliver(publication, [1])).toEqual([]);
  const publish = g.pubsubs[1].publish;
  g.pubsubs[1].publish = async () => {
    throw new Error('offline');
  };
  await expect(g.doc(1).change(set(key))).rejects.toThrow(
    'Document change committed',
  );
  return { g, online: () => (g.pubsubs[1].publish = publish) };
}

const restart = async (g: any) => {
  await g.doc(1).close();
  await g.open(1);
};

test('a Yjs edit written unrestricted is re-signed after a restart under a grant that covers it', async () => {
  const { g, online } = await offlineEdit('a');
  try {
    const apply = await restrict(g, [['m', 'a']]);
    await restart(g);
    online();
    expect(await apply()).toEqual({
      resent: 1,
      waiting: 0,
      skipped: 0,
      dropped: 0,
      diverged: false,
    });
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    for (const publication of g.take())
      errors.push(...(await g.deliver(publication, [0])));
    await g.doc(1).change(set('a', 2));
    for (const publication of g.take())
      errors.push(...(await g.deliver(publication, [0])));
    expect(errors).toEqual([]);
    expect(read(g.doc(0).document)).toEqual({ a: 2, c: 1 });
  } finally {
    await g.close();
  }
}, 30_000);

test('a Yjs writer whose unsent edit falls outside its new grants stays diverged after a restart', async () => {
  const { g, online } = await offlineEdit('b');
  try {
    const apply = await restrict(g, [['m', 'a']]);
    await restart(g);
    online();
    expect(await apply()).toMatchObject({ dropped: 1, diverged: true });
    await g
      .doc(1)
      .close()
      .catch(() => {});
    await expect(g.open(1)).rejects.toThrow(DocumentDivergedError);
    expect(read(g.doc(0).document)).toEqual({ c: 1 });
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);
