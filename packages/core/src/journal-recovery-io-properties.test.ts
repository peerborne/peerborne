import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  IDBFactory as FakeIDBFactory,
  IDBObjectStore as FakeObjectStore,
} from 'fake-indexeddb';
import { IndexedDBDocumentJournalStore } from './document-journal-store.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
  type DocumentJournalStore,
} from './document-replay-journal.js';
import { documentFixture } from './__testutils__/coordinated-document.js';
import { documentBytesId } from './internal/document-binary.js';

async function fixture(changes: Uint8Array, pending: boolean) {
  const f = await documentFixture();
  const factory = new FakeIDBFactory();
  const name = 'journal-recovery-io';
  const store = new IndexedDBDocumentJournalStore(name, factory);
  const anchor = new InMemoryDocumentJournalRollbackAnchor();
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const create = (source: DocumentJournalStore = store) =>
    new DocumentReplayJournal(
      f.authority.documentId,
      f.authority.genesisId,
      key,
      source,
      anchor,
    );
  const journal = create();
  await journal.restore();
  await (
    await journal.prepare({
      checkpoint: true,
      context: f.coordinator.documentContext,
      changes,
      receipts: [],
      authorityHead: f.authority.headId,
      authorityRecords: [],
      outboundFrame: changes,
    })
  ).commit();
  if (pending)
    await journal.prepare({
      checkpoint: false,
      context: f.coordinator.documentContext,
      changes: new Uint8Array([99]),
      receipts: [
        { memberId: f.identity, sequence: 1, hash: new Uint8Array(32).fill(9) },
      ],
      authorityHead: f.authority.headId,
      authorityRecords: [],
    });
  return {
    factory,
    name,
    store,
    anchor,
    create,
    storageKey: documentBytesId(f.authority.genesisId),
  };
}

function countReads(name: string) {
  const get = FakeObjectStore.prototype.get;
  const counts = { heads: 0, entries: 0, pending: 0, publications: 0 };
  const scopes = new Set<string>();
  const spy = jest
    .spyOn(FakeObjectStore.prototype, 'get')
    .mockImplementation(function (this: IDBObjectStore, query) {
      if (
        this.transaction.db.name === name &&
        Object.hasOwn(counts, this.name)
      ) {
        counts[this.name as keyof typeof counts]++;
        scopes.add(
          Array.from(this.transaction.objectStoreNames).sort().join(','),
        );
      }
      return Reflect.apply(get, this, [query]);
    });
  return { counts, scopes, restore: () => spy.mockRestore() };
}

async function mutateDatabase(
  f: Awaited<ReturnType<typeof fixture>>,
  action: (transaction: IDBTransaction) => void,
) {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = f.factory.open(f.name, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
        ['entries', 'pending'],
        'readwrite',
      );
      action(transaction);
      transaction.oncomplete = () => resolve();
      transaction.onerror = transaction.onabort = () =>
        reject(transaction.error);
    });
  } finally {
    database.close();
  }
}

test('recovery reads accepted entries once, no pending body, and each publication once', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 128 }),
      fc.boolean(),
      async (changes, pending) => {
        const f = await fixture(changes, pending);
        const reads = countReads(f.name);
        const restored = f.create();
        try {
          try {
            const items = await restored.restore();
            expect(items.map((item) => item.changes)).toEqual([changes]);
            expect(reads.counts).toEqual({
              heads: pending ? 3 : 2,
              entries: 1,
              pending: 0,
              publications: 1,
            });
          } finally {
            reads.restore();
          }
          expect(await restored.pendingPublications()).toEqual([changes]);
          expect((await f.store.load(f.storageKey)).pending).toBeUndefined();
        } finally {
          await f.store.close();
        }
      },
    ),
    { seed: 2011601, numRuns: 12 },
  );
});

test.each(['anchor', 'acceptance'] as const)(
  'a rejected %s never fetches pending or publication bodies',
  async (kind) => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        async (changes) => {
          const f = await fixture(changes, true);
          if (kind === 'anchor') {
            const load = f.anchor.load.bind(f.anchor);
            f.anchor.load = async (key) => {
              const actual = (await load(key))!;
              const commitment = actual.commitment.slice();
              commitment[0] ^= 1;
              return { revision: actual.revision, commitment };
            };
          } else {
            await mutateDatabase(f, (transaction) => {
              const store = transaction.objectStore('entries');
              const request = store.get([f.storageKey, 1]);
              request.onsuccess = () => {
                const value = request.result as Uint8Array;
                value[value.length - 1] ^= 1;
                store.put(value, [f.storageKey, 1]);
              };
            });
          }
          const reads = countReads(f.name);
          try {
            await expect(f.create().restore()).rejects.toThrow();
            expect(reads.counts.publications).toBe(0);
            expect(reads.counts.pending).toBe(0);
          } finally {
            reads.restore();
            await f.store.close();
          }
        },
      ),
      { seed: 2011602, numRuns: 12 },
    );
  },
);

test('garbage in an unaccepted pending body cannot block accepted recovery or be replayed', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      fc.constantFrom('missing', 'token', 'body'),
      async (changes, corruption) => {
        const f = await fixture(changes, true);
        await mutateDatabase(f, (transaction) => {
          const store = transaction.objectStore('pending');
          if (corruption === 'missing') {
            store.delete(f.storageKey);
          } else {
            const request = store.get(f.storageKey);
            request.onsuccess = () => {
              const value = request.result;
              if (corruption === 'token') {
                const token = (value.token as Uint8Array).slice();
                token[0] ^= 1;
                value.token = token;
              } else value.entry = new Uint8Array();
              store.put(value, f.storageKey);
            };
          }
        });
        try {
          const recovered = f.create();
          expect(
            (await recovered.restore()).map((item) => item.changes),
          ).toEqual([changes]);
          expect(await recovered.pendingPublications()).toEqual([changes]);
          expect((await f.store.load(f.storageKey)).pending).toBeUndefined();
        } finally {
          await f.store.close();
        }
      },
    ),
    { seed: 2011603, numRuns: 18 },
  );
});

test('full and recovery snapshot modes return distinct owned fields', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 128 }),
      fc.boolean(),
      async (changes, pending) => {
        const f = await fixture(changes, pending);
        try {
          const full = await f.store.load(f.storageKey);
          const reads = countReads(f.name);
          try {
            const recovery = await f.store.loadRecoverySnapshot(f.storageKey);
            expect(recovery.revision).toBe(full.revision);
            expect(recovery.entries).toEqual(full.entries);
            expect(Object.hasOwn(recovery, 'publications')).toBe(false);
            expect(recovery.pending?.token).toEqual(full.pending?.token);
            if (recovery.pending)
              expect(Object.keys(recovery.pending)).toEqual(['token']);
            expect(reads.counts).toEqual({
              heads: 1,
              entries: 1,
              pending: 0,
              publications: 0,
            });
            expect([...reads.scopes]).toEqual(['entries,heads']);
            for (const entry of recovery.entries) entry.fill(0);
            recovery.pending?.token.fill(0);
          } finally {
            reads.restore();
          }
          const again = await f.store.load(f.storageKey);
          expect(again).toEqual(full);
          expect(again.publications).toHaveLength(1);
          if (pending) expect(again.pending!.entry.length).toBeGreaterThan(0);
        } finally {
          await f.store.close();
        }
      },
    ),
    { seed: 2011604, numRuns: 12 },
  );
});

test('recovery captures the new snapshot capability before anchor awaits and preserves its receiver', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 128 }),
      async (changes) => {
        const f = await fixture(changes, true);
        try {
          const snapshot = await f.store.loadRecoverySnapshot(f.storageKey);
          const loadAnchor = f.anchor.load.bind(f.anchor);
          f.anchor.load = async (key) => {
            for (const entry of snapshot.entries) entry.fill(0);
            snapshot.pending!.token[0] ^= 1;
            return loadAnchor(key);
          };
          let captures = 0;
          const source: DocumentJournalStore = {
            load: async () => {
              throw new Error('Unexpected full snapshot read');
            },
            loadRecoverySnapshot() {
              expect(this).toBe(source);
              captures++;
              return Promise.resolve(snapshot);
            },
            loadPublications: f.store.loadPublications.bind(f.store),
            stage: f.store.stage.bind(f.store),
            commit: f.store.commit.bind(f.store),
            discard: f.store.discard.bind(f.store),
            publicationSent: f.store.publicationSent.bind(f.store),
          };
          const recovered = f.create(source);
          expect(
            (await recovered.restore()).map((item) => item.changes),
          ).toEqual([changes]);
          expect(captures).toBe(1);
          expect(await recovered.pendingPublications()).toEqual([changes]);
          expect((await f.store.load(f.storageKey)).pending).toBeUndefined();
        } finally {
          await f.store.close();
        }
      },
    ),
    { seed: 2011605, numRuns: 12 },
  );
});
