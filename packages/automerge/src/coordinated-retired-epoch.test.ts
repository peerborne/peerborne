import { expect, jest, test } from '@jest/globals';
import type { Doc } from '@automerge/automerge';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import { coordinatedGroupFixture } from '../../core/src/__testutils__/coordinated-group.js';
import { createGroupSecurityDurableAcceptance } from '../../core/src/group-security-durable-acceptance.js';
import type { GroupSecurityDelivery } from '../../core/src/group-security-coordinator.js';
import type { DocumentMemberAuthority } from '../../core/src/coordinated-document.js';
import { documentBytesId } from '../../core/src/internal/document-binary.js';

jest.mock('@helia/unixfs', () => ({ unixfs: () => ({}) }));

type State = Record<string, number>;
const crdt = new AutomergeProvider<State>();
const serializer = new AutomergeJSONSerializer();
const set = (key: string) => (draft: State) => {
  draft[key] = 1;
};
const read = (document: Doc<State>) => JSON.parse(JSON.stringify(document));

async function rotate(
  g: any,
  writer: Omit<DocumentMemberAuthority, 'memberId' | 'publicKey'>,
) {
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
  await g.coordinators[0].flushOutbox(async (pending: GroupSecurityDelivery) => {
    delivery = pending;
    return createGroupSecurityDurableAcceptance(pending);
  });
  const record = await g.logs[0].signUpdate(
    g.coordinators[0].documentContext,
    [
      { memberId: g.members[0], publicKey: documentBytesId(g.members[0]), role: 3 },
      { memberId: g.members[1], publicKey: documentBytesId(g.members[1]), ...writer },
    ],
    g.members[0],
  );
  await g.doc(0).applySecurityAuthorityUpdate(record);
  return { delivery, record };
}

async function setup(keys: string[]) {
  const g: any = await coordinatedGroupFixture(crdt as any, serializer as any, {
    members: 2,
  });
  await g.addMember(1);
  await g.open(0);
  await g.open(1);
  const publish = g.pubsubs[1].publish;
  g.pubsubs[1].publish = async () => {
    throw new Error('offline');
  };
  for (const key of keys)
    await expect(g.doc(1).change(set(key))).rejects.toThrow(
      'Document change committed',
    );
  return { g, online: () => (g.pubsubs[1].publish = publish) };
}

async function flush(g: any, errors: string[]) {
  for (const publication of g.take())
    errors.push(...(await g.deliver(publication, [0])));
}

const blob = (size: number) => {
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536)
    crypto.getRandomValues(bytes.subarray(offset, Math.min(size, offset + 65536)));
  return bytes;
};


const keys = (g: any) => Object.keys(read(g.doc(0).document)).sort();

test('A: closes a writer whose narrowed grants deny an unsent edit instead of re-signing it', async () => {
  const { g, online } = await setup(['b']);
  try {
    const { delivery, record } = await rotate(g, { role: 2, writePaths: [['a']] });
    online();
    await g.coordinators[1].applyCommit(delivery.commit!, delivery.controlRecord, []);
    const update = await g.doc(1).applySecurityAuthorityUpdate(record);
    expect(update).toEqual({
      resent: 0,
      waiting: 0,
      skipped: 0,
      dropped: 1,
      diverged: true,
    });
    await expect(g.doc(1).change(set('a'))).rejects.toThrow('diverged');
    expect(keys(g)).toEqual([]);
  } finally {
    await g.close();
  }
}, 30_000);

test('C: a second epoch change during the re-sign loop keeps the remaining frames', async () => {
  const { g, online } = await setup(['x1', 'x2', 'x3']);
  try {
    const first = await rotate(g, { role: 2 });
    const second = await rotate(g, { role: 2 });
    online();
    await g.coordinators[1].applyCommit(first.delivery.commit!, first.delivery.controlRecord, []);
    const engine = g.doc(1)._coordinated;
    const original = engine.apply;
    let resends = 0;
    engine.apply = async function (...args: unknown[]) {
      if (args[3] !== undefined && ++resends === 2)
        await g.coordinators[1].applyCommit(
          second.delivery.commit!,
          second.delivery.controlRecord,
          [],
        );
      return original.apply(this, args);
    };
    const update1 = await g.doc(1).applySecurityAuthorityUpdate(first.record);
    engine.apply = original;
    expect(update1.dropped).toBe(0);
    expect(update1.waiting).toBeGreaterThan(0);
    const update2 = await g.doc(1).applySecurityAuthorityUpdate(second.record);
    expect(update2).toMatchObject({ dropped: 0, diverged: false, waiting: 0 });
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    await flush(g, errors);
    await g.doc(1).change(set('after'));
    await flush(g, errors);
    expect(keys(g)).toEqual(['after', 'x1', 'x2', 'x3']);
  } finally {
    await g.close();
  }
}, 30_000);

test('D: close() during the re-sign loop leaves the journal outbox intact', async () => {
  const { g, online } = await setup(['y1', 'y2', 'y3']);
  try {
    const first = await rotate(g, { role: 2 });
    online();
    await g.coordinators[1].applyCommit(first.delivery.commit!, first.delivery.controlRecord, []);
    const engine = g.doc(1)._coordinated;
    const journal = engine.options.journal;
    const before = (await journal.pendingPublications()).length;
    const original = engine.apply;
    let resends = 0;
    let closing: Promise<void> | undefined;
    engine.apply = async function (...args: unknown[]) {
      if (args[3] !== undefined && ++resends === 2) closing = engine.close();
      return original.apply(this, args);
    };
    const update = await g.doc(1).applySecurityAuthorityUpdate(first.record);
    await closing;
    expect(update).toMatchObject({ resent: 1, dropped: 0, waiting: 2 });
    expect((await journal.pendingPublications()).length).toBe(before);
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

test('E: an author’s own frames survive retention pressure from another writer', async () => {
  const { g, online } = await setup(['z1']);
  try {
    const errors: string[] = [];
    for (let index = 0; index < 18; index++) {
      const payload = blob(380_000);
      await g.doc(0).change((draft: any) => {
        draft[`big${index}`] = payload;
      });
      for (const publication of g.take())
        errors.push(...(await g.deliver(publication, [1])));
    }
    const first = await rotate(g, { role: 2 });
    online();
    await g.coordinators[1].applyCommit(first.delivery.commit!, first.delivery.controlRecord, []);
    const update = await g.doc(1).applySecurityAuthorityUpdate(first.record);
    expect(update).toMatchObject({ resent: 1, dropped: 0, skipped: 0 });
    await g.doc(1).retrySecurityPublications();
    await flush(g, errors);
    await g.doc(1).change(set('after'));
    await flush(g, errors);
    expect(keys(g)).toEqual(expect.arrayContaining(['after', 'z1']));
  } finally {
    await g.close();
  }
}, 110_000);

test('F: frames re-signed into an intermediate epoch are re-signed again at the next one', async () => {
  const { g, online } = await setup(['w1']);
  try {
    const first = await rotate(g, { role: 2 });
    const second = await rotate(g, { role: 2 });
    online();
    await g.coordinators[1].applyCommit(first.delivery.commit!, first.delivery.controlRecord, []);
    await g.doc(1).applySecurityAuthorityUpdate(first.record);
    await g.coordinators[1].applyCommit(second.delivery.commit!, second.delivery.controlRecord, []);
    const update2 = await g.doc(1).applySecurityAuthorityUpdate(second.record);
    expect(update2).toMatchObject({ resent: 1, dropped: 0 });
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    await flush(g, errors);
    await g.doc(1).change(set('after'));
    await flush(g, errors);
    expect(keys(g)).toEqual(['after', 'w1']);
  } finally {
    await g.close();
  }
}, 30_000);

test('G: frames already published into the retired epoch are re-signed after the commit arrives', async () => {
  const { g, online } = await setup(['v1']);
  try {
    const first = await rotate(g, { role: 2 });
    online();
    await g.doc(1).change(set('v2'));
    const errors: string[] = [];
    await flush(g, errors);
    await g.coordinators[1].applyCommit(first.delivery.commit!, first.delivery.controlRecord, []);
    const update = await g.doc(1).applySecurityAuthorityUpdate(first.record);
    expect(update).toMatchObject({ resent: 2, dropped: 0 });
    await g.doc(1).retrySecurityPublications();
    await flush(g, errors);
    await g.doc(1).change(set('after'));
    await flush(g, errors);
    expect(keys(g)).toEqual(['after', 'v1', 'v2']);
  } finally {
    await g.close();
  }
}, 30_000);

const restrict = (g: any, paths: string[][]) =>
  rotate(g, { role: 2, writePaths: paths });
async function applyAt1(
  g: any,
  step: { delivery: GroupSecurityDelivery; record: Uint8Array },
) {
  await g.coordinators[1].applyCommit(step.delivery.commit!, step.delivery.controlRecord, []);
  return g.doc(1).applySecurityAuthorityUpdate(step.record);
}

test('T1: narrowing grants after a delivered edit skips it and keeps the writer open', async () => {
  const { g, online } = await setup([]);
  online();
  try {
    const errors: string[] = [];
    await applyAt1(g, await restrict(g, [['a'], ['b']]));
    await g.doc(1).change(set('b'));
    await flush(g, errors);
    const update = await applyAt1(g, await restrict(g, [['a']]));
    expect(update).toMatchObject({ dropped: 0, diverged: false });
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(keys(g)).toEqual(['a', 'b']);
  } finally {
    await g.close();
  }
}, 30_000);

test('T1b: restricting a writer whose allowed edits were delivered keeps it open', async () => {
  const { g, online } = await setup([]);
  online();
  try {
    const errors: string[] = [];
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    const update = await applyAt1(g, await restrict(g, [['a']]));
    expect(update).toMatchObject({ dropped: 0, diverged: false });
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    expect(errors).toEqual([]);
  } finally {
    await g.close();
  }
}, 30_000);

test.each([false, true])(
  'T2: re-signs waiting for outbox space go before a new local edit (local edit: %s)',
  async (interleave) => {
    const { g, online } = await setup(Array.from({ length: 16 }, (_, index) => `k${index}`));
    try {
      const update = await applyAt1(g, await rotate(g, { role: 2 }));
      online();
      expect(update).toMatchObject({ waiting: 16 });
      const publish = g.pubsubs[1].publish;
      let calls = 0;
      g.pubsubs[1].publish = async (...args: any[]) => {
        if (calls++ >= 1) throw new Error('offline again');
        return publish(...args);
      };
      await g.doc(1).retrySecurityPublications().catch(() => {});
      g.pubsubs[1].publish = publish;
      if (interleave) await g.doc(1).change(set('L')).catch(() => {});
      await g.doc(1).retrySecurityPublications().catch(() => {});
      await g.doc(1).retrySecurityPublications().catch(() => {});
      const errors: string[] = [];
      await flush(g, errors);
      await g.doc(1).change(set('after'));
      await flush(g, errors);
      const expected = Array.from({ length: 16 }, (_, index) => `k${index}`);
      expect(keys(g)).toEqual(expect.arrayContaining([...expected, 'after']));
    } finally {
      await g.close();
    }
  },
  60_000,
);

test('T4: a restricted writer that restarted keeps writing when its grants are unchanged', async () => {
  const { g, online } = await setup([]);
  online();
  try {
    const errors: string[] = [];
    await applyAt1(g, await restrict(g, [['a']]));
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    await g.doc(1).close();
    await g.open(1);
    const update = await applyAt1(g, await restrict(g, [['a']]));
    expect(update).toMatchObject({ dropped: 0, diverged: false });
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    expect(errors).toEqual([]);
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);
