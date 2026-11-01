import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  IDBFactory as FakeIDBFactory,
  IDBObjectStore as FakeObjectStore,
} from 'fake-indexeddb';
import { CoordinatedDocument } from './coordinated-document.js';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from './document-authority-log.js';
import { GroupSecurityCoordinator } from './group-security-coordinator.js';
import {
  context,
  config,
  protocol,
  groupId,
  id,
  control,
  createGroupInput,
  flushAndCollect,
} from './__testutils__/group-security-coordinator.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
  type DocumentJournalStore,
} from './document-replay-journal.js';
import {
  InMemoryDocumentJournalStore,
  IndexedDBDocumentJournalStore,
} from './document-journal-store.js';
import {
  documentFixture,
  testCRDT,
  testChanges,
  testAuth,
} from './__testutils__/coordinated-document.js';
import {
  documentBytesId,
  DocumentBinaryWriter,
} from './internal/document-binary.js';

const deviceKey = () =>
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
type Fixture = Awaited<ReturnType<typeof documentFixture>>;
function engine(
  f: Fixture,
  key: CryptoKey,
  store: DocumentJournalStore,
  anchor: InMemoryDocumentJournalRollbackAnchor,
  persistPublications = false,
) {
  return new CoordinatedDocument(
    f.authority.documentId,
    [],
    testCRDT,
    testChanges,
    f.auth,
    f.identity,
    f.identity,
    {
      coordinator: f.coordinator,
      authority: f.authority,
      persistPublications,
      journal: new DocumentReplayJournal(
        f.authority.documentId,
        f.authority.genesisId,
        key,
        store,
        anchor,
      ),
    },
  );
}

describe('accepted document WAL and replay persistence', () => {
  test.each(['memory', 'indexeddb'] as const)(
    'preserves accepted state and replay floors over generated %s restarts',
    async (backend) => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(
            fc.record({
              value: fc.integer({ min: -10000, max: 10000 }),
              restart: fc.boolean(),
            }),
            { minLength: 1, maxLength: 22 },
          ),
          async (actions) => {
            const f = await documentFixture(),
              key = await deviceKey(),
              anchor = new InMemoryDocumentJournalRollbackAnchor();
            const store =
              backend === 'memory'
                ? new InMemoryDocumentJournalStore()
                : new IndexedDBDocumentJournalStore(
                    'generated-journal',
                    new FakeIDBFactory(),
                  );
            if (backend === 'memory') {
              const stage = store.stage.bind(store),
                commit = store.commit.bind(store),
                compare = anchor.compareAndSwap.bind(anchor);
              store.stage = async (...args) => {
                await stage(...args);
                args[2].fill(0xff);
                args[3].fill(0xee);
              };
              store.commit = async (...args) => {
                await commit(...args);
                args[2].fill(0xdd);
              };
              anchor.compareAndSwap = async (...args) => {
                const result = await compare(...args);
                args[2].commitment.fill(0xcc);
                return result;
              };
            }
            let document = engine(f, key, store, anchor);
            await document.activate();
            const expected: number[] = [],
              frames: Uint8Array[] = [];
            for (const action of actions) {
              frames.push(
                await document.change((doc) => {
                  doc.push(action.value);
                }),
              );
              expected.push(action.value);
              if (action.restart) {
                await document.close();
                document = engine(f, key, store, anchor);
                await document.activate();
              }
              expect(document.document).toEqual(expected);
              expect(await document.receive(frames[0])).toBe(false);
            }
            await document.close();
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          },
        ),
        { seed: backend === 'memory' ? 2011141 : 2011142, numRuns: 18 },
      );
    },
  );

  test('compacts into a snapshot without forgetting author receipts or replaying the entire operation log', async () => {
    const f = await documentFixture(),
      key = await deviceKey(),
      store = new InMemoryDocumentJournalStore(),
      anchor = new InMemoryDocumentJournalRollbackAnchor();
    let document = engine(f, key, store, anchor);
    await document.activate();
    let first!: Uint8Array;
    for (let index = 0; index < 260; index++) {
      const frame = await document.change((doc) => {
        doc.push(index);
      });
      if (!index) first = frame;
    }
    const saved = await store.load(documentBytesId(f.authority.genesisId));
    expect(saved.revision).toBe(260);
    expect(saved.entries.length).toBeLessThan(128);
    expect(saved.pending).toBeUndefined();
    await document.close();
    document = engine(f, key, store, anchor);
    await document.activate();
    expect(document.document).toEqual(
      Array.from({ length: 260 }, (_, index) => index),
    );
    expect(await document.receive(first)).toBe(false);
    await document.change((doc) => {
      doc.push(260);
    });
    expect(document.document).toHaveLength(261);
    await document.close();
  });

  test.each([
    'staged',
    'before-marker',
    'after-marker',
    'after-anchor',
    'noop-marker',
    'noop-anchor',
  ] as const)(
    'recovers the defined durable result at the %s crash cut',
    async (cut) => {
      const f = await documentFixture(),
        key = await deviceKey(),
        backing = new InMemoryDocumentJournalStore(),
        anchor = new InMemoryDocumentJournalRollbackAnchor();
      let armed = true;
      const store: DocumentJournalStore = {
        load: (key) => backing.load(key),
        discard: (key, token) => backing.discard(key, token),
        stage: async (...args) => {
          await backing.stage(...args);
          if (armed && cut === 'staged') {
            armed = false;
            throw new Error('Simulated process cut');
          }
        },
        commit: async (...args) => {
          if (armed && cut === 'noop-marker') {
            armed = false;
            return;
          }
          if (armed && cut === 'before-marker') {
            armed = false;
            throw new Error('Simulated process cut');
          }
          await backing.commit(...args);
          if (armed && cut === 'after-marker') {
            armed = false;
            throw new Error('Simulated process cut');
          }
        },
      };
      const compare = anchor.compareAndSwap.bind(anchor);
      anchor.compareAndSwap = async (...args) => {
        if (armed && cut === 'noop-anchor') {
          armed = false;
          return true;
        }
        const accepted = await compare(...args);
        if (armed && cut === 'after-anchor') {
          armed = false;
          throw new Error('Simulated process cut');
        }
        return accepted;
      };
      const first = engine(f, key, store, anchor);
      await first.activate();
      await expect(
        first.change((doc) => {
          doc.push(77);
        }),
      ).rejects.toThrow();
      await first.close();
      const recovered = engine(f, key, backing, anchor);
      await recovered.activate();
      expect(recovered.document).toEqual(
        cut === 'after-marker' ||
          cut === 'after-anchor' ||
          cut === 'noop-anchor'
          ? [77]
          : [],
      );
      await recovered.change((doc) => {
        doc.push(88);
      });
      expect(recovered.document.at(-1)).toBe(88);
      await recovered.close();
    },
  );

  test('fails closed on rollback, ciphertext substitution, wrong device keys, and storage eviction', async () => {
    const f = await documentFixture(),
      key = await deviceKey(),
      backing = new InMemoryDocumentJournalStore(),
      anchor = new InMemoryDocumentJournalRollbackAnchor();
    const document = engine(f, key, backing, anchor);
    await document.activate();
    await document.change((doc) => {
      doc.push(1);
    });
    const old = await backing.load(documentBytesId(f.authority.genesisId));
    await document.change((doc) => {
      doc.push(2);
    });
    await document.close();
    const actual = await backing.load(documentBytesId(f.authority.genesisId));
    const modified = {
      ...actual,
      entries: actual.entries.map((entry) => entry.slice()),
    };
    modified.entries[1][modified.entries[1].length - 1] ^= 1;
    for (const snapshot of [old, modified, { revision: 0, entries: [] }]) {
      const store: DocumentJournalStore = {
        load: async () => snapshot,
        stage: async () => {},
        commit: async () => {},
        discard: async () => {},
      };
      const recovered = engine(f, key, store, anchor);
      await expect(recovered.activate()).rejects.toThrow();
      expect(() => recovered.document).toThrow();
      await recovered.close();
    }
    const wrongKey = engine(f, await deviceKey(), backing, anchor);
    await expect(wrongKey.activate()).rejects.toThrow();
    await wrongKey.close();
  });
});

test('retains a bounded encrypted outbox across generated restarts and resumes after capacity is freed', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.record({ send: fc.boolean(), restart: fc.boolean() }), {
        minLength: 18,
        maxLength: 30,
      }),
      async (actions) => {
        const f = await documentFixture(),
          key = await deviceKey(),
          store = new IndexedDBDocumentJournalStore(
            'outbox',
            new FakeIDBFactory(),
          ),
          anchor = new InMemoryDocumentJournalRollbackAnchor();
        let document = engine(f, key, store, anchor, true),
          accepted = 0;
        await document.activate();
        for (const action of actions) {
          const pending = await document.pendingPublications();
          if (pending.length === 16)
            await expect(
              document.change((doc) => {
                doc.push(99);
              }),
            ).rejects.toThrow('capacity');
          else {
            await document.change((doc) => {
              doc.push(accepted);
            });
            accepted++;
          }
          if (action.send)
            for (const frame of await document.pendingPublications())
              await document.publicationSent(frame);
          const unsent = await document.pendingPublications();
          expect(unsent.length).toBeLessThanOrEqual(16);
          if (action.restart) {
            await document.close();
            document = engine(f, key, store, anchor, true);
            await document.activate();
            expect(await document.pendingPublications()).toEqual(unsent);
          }
          expect(document.document).toHaveLength(accepted);
        }
        await document.close();
        await store.close();
      },
    ),
    { seed: 2011143, numRuns: 16 },
  );
});

test('IndexedDB delta commits and outbox draining never read or rewrite a two-megabyte checkpoint', async () => {
  const f = await documentFixture(),
    store = new IndexedDBDocumentJournalStore(
      'io-proportionality',
      new FakeIDBFactory(),
    ),
    key = await deviceKey();
  const journal = new DocumentReplayJournal(
    f.authority.documentId,
    f.authority.genesisId,
    key,
    store,
    new InMemoryDocumentJournalRollbackAnchor(),
  );
  await journal.restore();
  await (
    await journal.prepare({
      checkpoint: true,
      context: f.coordinator.documentContext,
      changes: new Uint8Array(2 * 1024 * 1024),
      receipts: [],
      authorityHead: f.authority.headId,
      authorityRecords: [],
    })
  ).commit();
  const get = FakeObjectStore.prototype.get,
    put = FakeObjectStore.prototype.put;
  let checkpointReads = 0,
    writtenBytes = 0;
  const getSpy = jest
    .spyOn(FakeObjectStore.prototype, 'get')
    .mockImplementation(function (this: any, ...args: any[]) {
      if (this.name === 'entries' && Array.isArray(args[0]) && args[0][1] === 1)
        checkpointReads++;
      return Reflect.apply(get, this, args);
    });
  const putSpy = jest
    .spyOn(FakeObjectStore.prototype, 'put')
    .mockImplementation(function (this: any, value: any, ...args: any[]) {
      if (this.name === 'entries') writtenBytes += value.byteLength;
      if (this.name === 'pending') writtenBytes += value.entry.byteLength;
      return Reflect.apply(put, this, [value, ...args]);
    });
  try {
    for (let sequence = 1; sequence <= 10; sequence++) {
      await (
        await journal.prepare({
          checkpoint: false,
          context: f.coordinator.documentContext,
          changes: new Uint8Array(17),
          receipts: [
            {
              memberId: f.identity,
              sequence,
              hash: new Uint8Array(32).fill(sequence),
            },
          ],
          authorityHead: f.authority.headId,
          authorityRecords: [],
          outboundFrame: new Uint8Array(32).fill(sequence),
        })
      ).commit();
      for (const frame of await journal.pendingPublications())
        await journal.publicationSent(frame);
    }
    expect(checkpointReads).toBe(0);
    expect(writtenBytes).toBeLessThan(32 * 1024);
  } finally {
    getSpy.mockRestore();
    putSpy.mockRestore();
    await store.close();
  }
});

test('captures a journal item before waiting on its independent anchor', async () => {
  const f = await documentFixture(),
    store = new InMemoryDocumentJournalStore(),
    anchor = new InMemoryDocumentJournalRollbackAnchor(),
    key = await deviceKey();
  const journal = new DocumentReplayJournal(
    f.authority.documentId,
    f.authority.genesisId,
    key,
    store,
    anchor,
  );
  await journal.restore();
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const originalLoad = anchor.load.bind(anchor);
  anchor.load = async (value) => {
    await blocked;
    return originalLoad(value);
  };
  const changes = new Uint8Array([1, 2, 3]);
  const receipt = {
    memberId: f.identity.slice(),
    sequence: 1,
    hash: new Uint8Array(32).fill(7),
  };
  const preparing = journal.prepare({
    checkpoint: false,
    context: f.coordinator.documentContext,
    changes,
    receipts: [receipt],
    authorityHead: f.authority.headId,
    authorityRecords: [],
  });
  changes.fill(99);
  receipt.hash.fill(88);
  receipt.sequence = 9;
  release();
  await (await preparing).commit();
  const restored = await new DocumentReplayJournal(
    f.authority.documentId,
    f.authority.genesisId,
    key,
    store,
    anchor,
  ).restore();
  expect(restored[0].changes).toEqual(new Uint8Array([1, 2, 3]));
  expect(restored[0].receipts[0].sequence).toBe(1);
  expect(restored[0].receipts[0].hash).toEqual(new Uint8Array(32).fill(7));
});

test('storage cannot promote a prepared ciphertext into an accepted journal entry', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 28, maxLength: 28 }),
      async (forgedMarker) => {
        const f = await documentFixture(),
          key = await deviceKey(),
          backing = new InMemoryDocumentJournalStore(),
          anchor = new InMemoryDocumentJournalRollbackAnchor();
        const journal = new DocumentReplayJournal(
          f.authority.documentId,
          f.authority.genesisId,
          key,
          backing,
          anchor,
        );
        await journal.restore();
        const pending = await journal.prepare({
          checkpoint: false,
          context: f.coordinator.documentContext,
          changes: testChanges.serializeChanges([99]),
          authorityHead: f.authority.headId,
          receipts: [
            {
              memberId: f.identity,
              sequence: 1,
              hash: new Uint8Array(32).fill(7),
            },
          ],
          authorityRecords: [],
        });
        const staged = await backing.load(
          documentBytesId(f.authority.genesisId),
        );
        const encoded = new DocumentBinaryWriter()
          .bytes(staged.pending!.entry)
          .fixed(forgedMarker)
          .finish();
        await pending.discard();
        const hostile: DocumentJournalStore = {
          load: async () => ({ revision: 1, entries: [encoded] }),
          stage: async () => {},
          commit: async () => {},
          discard: async () => {},
        };
        const recovered = engine(f, key, hostile, anchor);
        await expect(recovered.activate()).rejects.toThrow('acceptance');
        expect(
          await anchor.load(documentBytesId(f.authority.genesisId)),
        ).toBeUndefined();
        expect(() => recovered.document).toThrow();
        await recovered.close();
      },
    ),
    { seed: 2011144, numRuns: 24 },
  );
});

test.each([true, false])(
  'outbox reads wait for the complete journal anchor decision (%s)',
  async (accepted) => {
    const f = await documentFixture(),
      key = await deviceKey(),
      store = new InMemoryDocumentJournalStore(),
      anchor = new InMemoryDocumentJournalRollbackAnchor();
    const original = anchor.compareAndSwap.bind(anchor);
    let entered!: () => void, release!: () => void;
    const started = new Promise<void>((resolve) => {
        entered = resolve;
      }),
      blocked = new Promise<void>((resolve) => {
        release = resolve;
      });
    anchor.compareAndSwap = async (...args) => {
      entered();
      await blocked;
      return accepted ? original(...args) : false;
    };
    const document = engine(f, key, store, anchor, true);
    await document.activate();
    const mutation = document.change((doc) => {
      doc.push(1);
    });
    const mutationResult = mutation.then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    await started;
    let observed = false;
    const read = document.pendingPublications();
    const readResult = read.then(
      (value) => {
        observed = true;
        return { value };
      },
      (error) => ({ error }),
    );
    await new Promise((resolve) => setImmediate(resolve));
    expect(observed).toBe(false);
    expect(
      (await store.load(documentBytesId(f.authority.genesisId))).publications,
    ).toHaveLength(1);
    release();
    const changed = await mutationResult,
      publications = await readResult;
    if (accepted) {
      expect('value' in changed).toBe(true);
      expect('value' in publications && publications.value.length).toBe(1);
    } else {
      expect('error' in changed).toBe(true);
      expect('error' in publications).toBe(true);
      expect(observed).toBe(false);
    }
    await document.close();
  },
);

test('coordinated IndexedDB writes stay proportional to deltas with a large signed role history', async () => {
  const f = await context(),
    baseAuth = testAuth(f),
    padding = 'x'.repeat(3500);
  const auth = {
    ...baseAuth,
    serializePublicKey: async (key: Uint8Array) =>
      padding + (await baseAuth.serializePublicKey(key)),
    deserializePublicKey: async (key: string) => {
      if (!key.startsWith(padding)) throw new Error('Noncanonical fixture key');
      return baseAuth.deserializePublicKey(key.slice(padding.length));
    },
  };
  const authority = new DocumentGroupControlAuthority(
    protocol,
    groupId,
    f.identities.actorId,
  );
  const coordinator = await GroupSecurityCoordinator.bootstrap(
    { ...config(f), authorizeControl: authority.authorize },
    createGroupInput,
    { operationId: id(1), subjectId: f.identities.actorId },
  );
  const roster = [
    {
      memberId: f.identities.actorId,
      publicKey: await auth.serializePublicKey(f.identities.actorId),
      role: 3 as const,
    },
    {
      memberId: f.identities.attackerId,
      publicKey: await auth.serializePublicKey(f.identities.attackerId),
      role: 2 as const,
    },
  ];
  const log = await DocumentAuthorityLog.create(
    '/history-cost',
    coordinator.documentContext,
    roster,
    f.identities.actorId,
    auth,
    authority,
  );
  for (let index = 0; index < 12; index++) {
    await flushAndCollect(coordinator);
    await coordinator.createCommit(
      { changes: [] },
      control(index + 2, 'update', f.identities.actorId),
    );
    await log.applyUpdate(
      coordinator,
      await log.signUpdate(
        coordinator.documentContext,
        roster,
        f.identities.actorId,
      ),
    );
  }
  expect(
    log.exportRecords().reduce((sum, record) => sum + record.byteLength, 0),
  ).toBeGreaterThan(90 * 1024);
  const store = new IndexedDBDocumentJournalStore(
      'authority-cost',
      new FakeIDBFactory(),
    ),
    key = await deviceKey(),
    anchor = new InMemoryDocumentJournalRollbackAnchor();
  const document = new CoordinatedDocument(
    log.documentId,
    [],
    testCRDT,
    testChanges,
    auth,
    f.identities.actorId,
    f.identities.actorId,
    {
      coordinator,
      authority: log,
      journal: new DocumentReplayJournal(
        log.documentId,
        log.genesisId,
        key,
        store,
        anchor,
      ),
    },
  );
  await document.activate();
  await document.change((draft) => {
    draft.push(0);
  });
  const exportSpy = jest.spyOn(log, 'exportRecords');
  const put = FakeObjectStore.prototype.put;
  let writtenBytes = 0;
  const putSpy = jest
    .spyOn(FakeObjectStore.prototype, 'put')
    .mockImplementation(function (this: any, value: any, ...args: any[]) {
      if (this.name === 'entries') writtenBytes += value.byteLength;
      if (this.name === 'pending') writtenBytes += value.entry.byteLength;
      return Reflect.apply(put, this, [value, ...args]);
    });
  try {
    for (let index = 1; index <= 10; index++)
      await document.change((draft) => {
        draft.push(index);
      });
    expect(exportSpy).not.toHaveBeenCalled();
    expect(writtenBytes).toBeLessThan(32 * 1024);
  } finally {
    putSpy.mockRestore();
    exportSpy.mockRestore();
    await document.close();
    await store.close();
  }
});
