import { expect, jest, test } from '@jest/globals';
import type { Doc } from '@automerge/automerge';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import { coordinatedGroupFixture } from '../../core/src/__testutils__/coordinated-group.js';
import { createGroupSecurityDurableAcceptance } from '../../core/src/group-security-durable-acceptance.js';
import type { GroupSecurityDelivery } from '../../core/src/group-security-coordinator.js';
import {
  DocumentDivergedError,
  DocumentPublicationBacklogError,
  type DocumentMemberAuthority,
} from '../../core/src/coordinated-document.js';
import { bytesToHex } from '../../core/src/internal/hex.js';
import { splitDocumentPublication } from '../../core/src/document-security-wire.js';

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
      { memberId: g.members[0], publicKey: bytesToHex(g.members[0]), role: 3 },
      { memberId: g.members[1], publicKey: bytesToHex(g.members[1]), ...writer },
    ],
    g.members[0],
  );
  const controller = await g.doc(0).applySecurityAuthorityUpdate(record);
  return { delivery, record, controller };
}

async function setup(keys: string[], { catchUp = false } = {}) {
  const g: any = await coordinatedGroupFixture(crdt as any, serializer as any, {
    members: 2,
    catchUp,
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
      if (args[4] !== undefined && ++resends === 2)
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
    const frames = async () =>
      (await journal.pendingPublications()).flatMap(splitDocumentPublication)
        .length;
    const before = await frames();
    const original = engine.apply;
    let resends = 0;
    let closing: Promise<void> | undefined;
    engine.apply = async function (...args: unknown[]) {
      if (args[4] !== undefined && ++resends === 2) closing = engine.close();
      return original.apply(this, args);
    };
    const update = await g.doc(1).applySecurityAuthorityUpdate(first.record);
    await closing;
    expect(update).toMatchObject({ resent: 1, dropped: 0, waiting: 2 });
    expect(await frames()).toBe(before);
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

test.each([false, true])(
  'a controller that renews the epoch re-signs none of its published frames (restart: %s)',
  async (restarted) => {
    const { g, online } = await setup([]);
    online();
    try {
      const errors: string[] = [];
      for (const key of ['p', 'q']) {
        await g.doc(0).change(set(key));
        for (const publication of g.take())
          errors.push(...(await g.deliver(publication, [1])));
      }
      if (restarted) {
        await g.doc(0).close();
        await g.open(0);
      }
      const step = await rotate(g, { role: 2 });
      expect(step.controller).toEqual({
        resent: 0,
        waiting: 0,
        skipped: 2,
        dropped: 0,
        diverged: false,
      });
      await g.doc(0).retrySecurityPublications();
      expect(g.take()).toEqual([]);
      await applyAt1(g, step);
      await g.doc(0).change(set('r'));
      const published = g.take();
      expect(published).toHaveLength(1);
      errors.push(...(await g.deliver(published[0], [1])));
      expect(errors).toEqual([]);
      expect(Object.keys(read(g.doc(1).document)).sort()).toEqual([
        'p',
        'q',
        'r',
      ]);
    } finally {
      await g.close();
    }
  },
  30_000,
);

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
  'T2: re-signs still waiting go before a new local edit (local edit: %s)',
  async (interleave) => {
    const { g, online } = await setup(Array.from({ length: 16 }, (_, index) => `k${index}`));
    try {
      // The offline edits share one publication; a failing re-sign keeps them waiting.
      const engine = g.doc(1)._coordinated;
      const original = engine.apply;
      engine.apply = async function (...args: unknown[]) {
        if (args[4] !== undefined) throw new Error('transient');
        return original.apply(this, args);
      };
      const update = await applyAt1(g, await rotate(g, { role: 2 }));
      engine.apply = original;
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
    expect(update).toEqual({
      resent: 1,
      waiting: 0,
      skipped: 0,
      dropped: 0,
      diverged: false,
    });
    await g.doc(1).change((draft: State) => {
      draft.a = 2;
    });
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(read(g.doc(0).document)).toEqual({ a: 2 });
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

const restart = async (g: any) => {
  await g.doc(1).close();
  await g.open(1);
};

const bulk = (draft: any) => {
  for (let index = 0; index < 70; index++) draft.a[`x${index}`] = index;
  draft.b.c = 1;
};

async function bulkSetup() {
  const { g, online } = await setup([]);
  online();
  const errors: string[] = [];
  await applyAt1(g, await restrict(g, [['a'], ['b', 'c']]));
  await g.doc(0).change((draft: any) => {
    draft.a = {};
    draft.b = {};
  });
  for (const publication of g.take())
    errors.push(...(await g.deliver(publication, [1])));
  return { g, errors };
}

test.each([false, true])(
  'T5: an unsent bulk edit covered by unchanged grants is re-signed (restart: %s)',
  async (restarted) => {
    const { g, errors } = await bulkSetup();
    try {
      const publish = g.pubsubs[1].publish;
      g.pubsubs[1].publish = async () => {
        throw new Error('offline');
      };
      await expect(g.doc(1).change(bulk)).rejects.toThrow(
        'Document change committed',
      );
      expect(g.doc(1)._coordinated.own.frames.at(-1).paths).toHaveLength(71);
      const step = await restrict(g, [['a'], ['b', 'c']]);
      if (restarted) await restart(g);
      g.pubsubs[1].publish = publish;
      expect(await applyAt1(g, step)).toEqual({
        resent: 1,
        waiting: 0,
        skipped: 0,
        dropped: 0,
        diverged: false,
      });
      await g.doc(1).retrySecurityPublications();
      await flush(g, errors);
      await restart(g);
      await g.doc(1).change((draft: any) => {
        draft.b.c = 2;
      });
      await flush(g, errors);
      expect(errors).toEqual([]);
      const view = read(g.doc(0).document);
      expect(Object.keys(view.a)).toHaveLength(70);
      expect(view.b).toEqual({ c: 2 });
    } finally {
      await g.close().catch(() => {});
    }
  },
  60_000,
);

test('T5ctl: the same bulk edit sent online is accepted by the controller', async () => {
  const { g, errors } = await bulkSetup();
  try {
    await g.doc(1).change(bulk);
    await flush(g, errors);
    expect(errors).toEqual([]);
    const view = read(g.doc(0).document);
    expect(Object.keys(view.a)).toHaveLength(70);
    expect(view.b).toEqual({ c: 1 });
  } finally {
    await g.close().catch(() => {});
  }
}, 60_000);

async function bigPaste(restricted: boolean) {
  const { g, online } = await setup([]);
  await expect(
    g.doc(1).change((draft: any) => {
      draft.t = 'x'.repeat(140_000);
    }),
  ).rejects.toThrow('Document change committed');
  expect(g.doc(1)._coordinated.own.frames.at(-1).paths).toEqual([[]]);
  const step = restricted
    ? await restrict(g, [['t']])
    : await rotate(g, { role: 2 });
  online();
  return { g, update: await applyAt1(g, step) };
}

test('T6: an uninspected unsent edit is denied under a restriction and diverges the writer', async () => {
  const { g, update } = await bigPaste(true);
  try {
    expect(update).toEqual({
      resent: 0,
      waiting: 0,
      skipped: 0,
      dropped: 1,
      diverged: true,
    });
    await g.doc(1).retrySecurityPublications();
    expect(g.take()).toEqual([]);
    await expect(g.doc(1).change(set('t'))).rejects.toThrow(
      DocumentDivergedError,
    );
    await g.doc(1).close().catch(() => {});
    await expect(g.open(1)).rejects.toThrow(DocumentDivergedError);
  } finally {
    await g.close().catch(() => {});
  }
}, 110_000);

test('T6ctl: the same uninspected edit is re-signed and delivered for an unrestricted writer', async () => {
  const { g, update } = await bigPaste(false);
  try {
    expect(update).toEqual({
      resent: 1,
      waiting: 0,
      skipped: 0,
      dropped: 0,
      diverged: false,
    });
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    await flush(g, errors);
    await g.doc(1).change(set('after'));
    await flush(g, errors);
    expect(errors).toEqual([]);
    const view = read(g.doc(0).document);
    expect(view.t).toHaveLength(140_000);
    expect(view.after).toBe(1);
  } finally {
    await g.close().catch(() => {});
  }
}, 110_000);

test('an uninspected published edit is skipped under a restriction and the writer keeps writing', async () => {
  const { g, online } = await setup([]);
  online();
  try {
    const errors: string[] = [];
    await g.doc(1).change(set('x'.repeat(1025)));
    await flush(g, errors);
    expect(g.doc(1)._coordinated.own.frames.at(-1).paths).toEqual([[]]);
    expect(await applyAt1(g, await restrict(g, [['a']]))).toEqual({
      resent: 0,
      waiting: 0,
      skipped: 1,
      dropped: 0,
      diverged: false,
    });
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(keys(g)).toEqual(['a', 'x'.repeat(1025)]);
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

test('edits re-signed before a denied unsent edit are still published by the diverged writer', async () => {
  const { g, online } = await setup(['a', 'b']);
  try {
    const step = await restrict(g, [['a']]);
    online();
    expect(await applyAt1(g, step)).toEqual({
      resent: 1,
      waiting: 0,
      skipped: 0,
      dropped: 1,
      diverged: true,
    });
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(keys(g)).toEqual(['a']);
    expect(await g.doc(1)._coordinated.pendingPublications()).toEqual([]);
    await expect(g.doc(1).change(set('a'))).rejects.toThrow(
      DocumentDivergedError,
    );
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

test('a diverged writer drains one coalesced publication of the edits re-signed before the denial', async () => {
  const { g, online } = await setup(['a1', 'a2', 'a3', 'b']);
  try {
    const [retired] = await g.doc(1)._coordinated.pendingPublications();
    expect(splitDocumentPublication(retired)).toHaveLength(4);
    const step = await restrict(g, [['a1'], ['a2'], ['a3']]);
    online();
    expect(await applyAt1(g, step)).toEqual({
      resent: 3,
      waiting: 0,
      skipped: 0,
      dropped: 1,
      diverged: true,
    });
    const queued = await g.doc(1)._coordinated.pendingPublications();
    expect(queued).toHaveLength(1);
    expect(splitDocumentPublication(queued[0])).toHaveLength(3);
    await expect(g.doc(1).retrySecurityPublications()).resolves.toMatchObject({
      pending: false,
      dropped: 0,
    });
    const published = g.take();
    expect(
      published.map((publication: { data: Uint8Array }) => publication.data),
    ).toContainEqual(queued[0]);
    const errors: string[] = [];
    for (const publication of published)
      errors.push(...(await g.deliver(publication, [0])));
    expect(errors).toEqual([]);
    expect(keys(g)).toEqual(['a1', 'a2', 'a3']);
    expect(await g.doc(1)._coordinated.pendingPublications()).toEqual([]);
    await expect(g.doc(1).change(set('a1'))).rejects.toThrow(
      DocumentDivergedError,
    );
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

test('T3: a diverged writer is refused when it reopens', async () => {
  const { g, online } = await setup(['b']);
  try {
    const step = await restrict(g, [['a']]);
    online();
    expect(await applyAt1(g, step)).toMatchObject({
      dropped: 1,
      diverged: true,
    });
    await g.doc(1).close().catch(() => {});
    await expect(g.open(1)).rejects.toThrow(DocumentDivergedError);
    await expect(g.open(1)).rejects.toThrow(DocumentDivergedError);
    expect(keys(g)).toEqual([]);
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

test('a diverged writer rebuilt from a controller checkpoint into a new journal syncs again', async () => {
  const { g, online } = await setup(['b'], { catchUp: true });
  try {
    const step = await restrict(g, [['a']]);
    online();
    expect(await applyAt1(g, step)).toMatchObject({ diverged: true });
    const errors: string[] = [];
    await g.doc(0).change(set('c'));
    g.take();
    await g.doc(1).close().catch(() => {});
    await expect(g.open(1)).rejects.toThrow(DocumentDivergedError);
    g.resetJournal(1);
    await g.open(1);
    const request = await g.doc(1).createSecurityCatchUpRequest();
    await g
      .doc(1)
      .applySecurityCatchUpCheckpoint(
        await g.doc(0).createSecurityCatchUpCheckpoint(request),
      );
    expect(read(g.doc(1).document)).toEqual({ c: 1 });
    await g.doc(1).change(set('a'));
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(keys(g)).toEqual(['a', 'c']);
    await restart(g);
    await g.doc(1).change((draft: State) => {
      draft.a = 2;
    });
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(read(g.doc(0).document)).toEqual({ a: 2, c: 1 });
  } finally {
    await g.close().catch(() => {});
  }
}, 30_000);

test.each([false, true])(
  'an edit written unrestricted is re-signed under a grant that covers it (restart: %s)',
  async (restarted) => {
    const { g, online } = await setup(['a']);
    try {
      const step = await restrict(g, [['a']]);
      if (restarted) await restart(g);
      online();
      expect(await applyAt1(g, step)).toEqual({
        resent: 1,
        waiting: 0,
        skipped: 0,
        dropped: 0,
        diverged: false,
      });
      await g.doc(1).retrySecurityPublications();
      const errors: string[] = [];
      await flush(g, errors);
      await g.doc(1).change((draft: State) => {
        draft.a = 2;
      });
      await flush(g, errors);
      expect(errors).toEqual([]);
      expect(read(g.doc(0).document)).toEqual({ a: 2 });
      expect(await g.doc(1)._coordinated.pendingPublications()).toEqual([]);
    } finally {
      await g.close();
    }
  },
  30_000,
);

test.each([false, true])(
  'an unsent edit outside the new grants diverges the writer (restart: %s)',
  async (restarted) => {
    const { g, online } = await setup(['b']);
    try {
      const step = await restrict(g, [['a']]);
      if (restarted) await restart(g);
      online();
      expect(await applyAt1(g, step)).toEqual({
        resent: 0,
        waiting: 0,
        skipped: 0,
        dropped: 1,
        diverged: true,
      });
      await expect(g.doc(1).change(set('a'))).rejects.toThrow(
        DocumentDivergedError,
      );
      expect(g.take()).toEqual([]);
    } finally {
      await g.close().catch(() => {});
    }
  },
  30_000,
);

test.each([false, true])(
  'a published edit outside the new grants is skipped and the writer keeps writing (restart: %s)',
  async (restarted) => {
    const { g, online } = await setup([]);
    online();
    try {
      const errors: string[] = [];
      await g.doc(1).change(set('b'));
      await flush(g, errors);
      const step = await restrict(g, [['a']]);
      if (restarted) await restart(g);
      expect(await applyAt1(g, step)).toEqual({
        resent: 0,
        waiting: 0,
        skipped: 1,
        dropped: 0,
        diverged: false,
      });
      await g.doc(1).change(set('a'));
      await flush(g, errors);
      expect(errors).toEqual([]);
      expect(keys(g)).toEqual(['a', 'b']);
    } finally {
      await g.close();
    }
  },
  30_000,
);

test('T7: a re-sign interrupted while it drains a full outbox loses no edit across a restart', async () => {
  const { g, online } = await setup([]);
  try {
    // Two large edits fill each of the 15 rows local edits may use.
    for (let index = 0; index < 30; index++) {
      const payload = blob(380_000);
      await expect(
        g.doc(1).change((draft: any) => {
          draft[`big${index}`] = payload;
        }),
      ).rejects.toThrow('Document change committed');
    }
    const engine = g.doc(1)._coordinated;
    const journal = engine.options.journal;
    expect(await journal.pendingPublications()).toHaveLength(15);
    const step = await rotate(g, { role: 2 });
    online();
    await g.coordinators[1].applyCommit(step.delivery.commit!, step.delivery.controlRecord, []);
    const original = engine.apply;
    const document = g.doc(1);
    let resigns = 0;
    let closing: Promise<void> | undefined;
    engine.apply = async function (...args: unknown[]) {
      if (args[4] !== undefined && ++resigns === 5) closing = document.close();
      return original.apply(this, args);
    };
    await document.applySecurityAuthorityUpdate(step.record).catch(() => {});
    await closing;
    // No retired frame left the outbox before its re-signed copy was durable.
    const frames = (await journal.pendingPublications()).flatMap(
      splitDocumentPublication,
    );
    expect(frames.length).toBeGreaterThanOrEqual(30);
    await g.open(1);
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    await flush(g, errors);
    await g.doc(1).change(set('after'));
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(keys(g)).toEqual(
      [...Array.from({ length: 30 }, (_, index) => `big${index}`), 'after'].sort(),
    );
  } finally {
    await g.close().catch(() => {});
  }
}, 120_000);

test('T8: a restricted writer re-signs a large offline backlog after a restart with unchanged grants', async () => {
  const { g, online } = await setup([]);
  try {
    const errors: string[] = [];
    await applyAt1(g, await restrict(g, [['a']]));
    await g.doc(0).change((draft: any) => {
      draft.a = {};
    });
    for (const publication of g.take())
      errors.push(...(await g.deliver(publication, [1])));
    for (let frame = 0; frame < 260; frame++)
      await expect(
        g.doc(1).change((draft: any) => {
          for (let key = 0; key < 200; key++) draft.a[`k${frame}_${key}`] = key;
        }),
      ).rejects.toThrow('Document change committed');
    await g.doc(1).close();
    await g.open(1);
    const own = g.doc(1)._coordinated.own.frames;
    expect(own).toHaveLength(260);
    expect(
      own.filter((frame: any) =>
        frame.paths.some((path: string[]) => path.length === 0),
      ),
    ).toEqual([]);
    const step = await restrict(g, [['a']]);
    online();
    expect(await applyAt1(g, step)).toEqual({
      resent: 260,
      waiting: 0,
      skipped: 0,
      dropped: 0,
      diverged: false,
    });
    await g.doc(1).retrySecurityPublications();
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(Object.keys(read(g.doc(0).document).a)).toHaveLength(260 * 200);
    await g.doc(1).close();
    await g.open(1);
  } finally {
    await g.close().catch(() => {});
  }
}, 180_000);

test('refuses an offline edit whose paths no checkpoint could carry exactly, and resumes after delivery', async () => {
  const { g, online } = await setup([]);
  try {
    const wide = (prefix: string) => (draft: any) => {
      for (let key = 0; key < 1000; key++)
        draft[`${prefix}${key}${'x'.repeat(300)}`] = 1;
    };
    let accepted = 0,
      refusal: unknown;
    for (let round = 0; round < 20 && refusal === undefined; round++) {
      try {
        await g.doc(1).change(wide(`r${round}_`));
      } catch (error) {
        if ((error as Error).message.startsWith('Document change committed'))
          accepted++;
        else refusal = error;
      }
    }
    // Each edit records about 300 KiB of paths against the 4 MiB budget.
    expect(accepted).toBe(13);
    expect(refusal).toBeInstanceOf(DocumentPublicationBacklogError);
    online();
    await g.doc(1).retrySecurityPublications();
    const errors: string[] = [];
    await flush(g, errors);
    expect(errors).toEqual([]);
    await g.doc(1).change(wide('later_'));
    await flush(g, errors);
    expect(errors).toEqual([]);
    expect(keys(g)).toHaveLength(14_000);
  } finally {
    await g.close().catch(() => {});
  }
}, 120_000);
