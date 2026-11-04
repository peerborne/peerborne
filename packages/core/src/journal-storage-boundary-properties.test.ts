import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  IDBFactory as FakeIDBFactory,
  IDBObjectStore as FakeObjectStore,
} from 'fake-indexeddb';
import {
  IndexedDBDocumentJournalStore,
  InMemoryDocumentJournalStore,
} from './document-journal-store.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
  type DocumentJournalStore,
} from './document-replay-journal.js';
import { documentBytesId } from './internal/document-binary.js';
import { documentFixture } from './__testutils__/coordinated-document.js';
import * as byteUtilities from './utils.js';

const storageKey = 'synthetic-journal';
const publicationId = new Uint8Array(32).fill(5);
const pendingToken = new Uint8Array(32).fill(9);

async function seedStorage(
  head: unknown,
  entries: Uint8Array[] = [],
  pending?: unknown,
  publication?: unknown,
) {
  const factory = new FakeIDBFactory();
  const name = 'journal-boundary';
  const store = new IndexedDBDocumentJournalStore(name, factory);
  await store.load(storageKey);
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(name, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
        ['heads', 'entries', 'pending', 'publications'],
        'readwrite',
      );
      transaction.objectStore('heads').put(head, storageKey);
      entries.forEach((entry, index) => {
        transaction.objectStore('entries').put(entry, [storageKey, index + 1]);
      });
      if (pending) transaction.objectStore('pending').put(pending, storageKey);
      if (publication)
        transaction
          .objectStore('publications')
          .put(publication, [storageKey, documentBytesId(publicationId)]);
      transaction.oncomplete = () => resolve();
      transaction.onerror = transaction.onabort = () =>
        reject(transaction.error);
    });
  } finally {
    database.close();
  }
  return store;
}

function countCopies(label: string) {
  const original = byteUtilities.copyUnsharedUint8Array;
  let bytes = 0;
  const spy = jest
    .spyOn(byteUtilities, 'copyUnsharedUint8Array')
    .mockImplementation((...args: Parameters<typeof original>) => {
      const result = original(...args);
      if (args[3] === label) bytes += result.byteLength;
      return result;
    });
  return {
    get bytes() {
      return bytes;
    },
    restore: () => spy.mockRestore(),
  };
}

test('corrupt retained rows cannot exceed the declared owned-copy budget before rejection', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.integer({ min: 2, max: 32 }), { minLength: 2, maxLength: 8 }),
      fc.boolean(),
      async (lengths, corrupt) => {
        const total = lengths.reduce((sum, length) => sum + length, 0);
        const declared = total - (corrupt ? 1 : 0);
        const entries = lengths.map((length) => new Uint8Array(length));
        const store = await seedStorage(
          {
            revision: lengths.length,
            revisions: lengths.map((_, index) => index + 1),
            bytes: declared,
            publications: [],
          },
          entries,
        );
        const copies = countCopies('stored journal entry');
        try {
          if (corrupt) {
            await expect(store.load(storageKey)).rejects.toThrow();
          } else {
            const loaded = await store.load(storageKey);
            expect(loaded.entries).toEqual(entries);
            expect(copies.bytes).toBe(total);
            for (let index = 0; index < entries.length; index++)
              expect(loaded.entries[index]).not.toBe(entries[index]);
          }
          expect(copies.bytes).toBeLessThanOrEqual(declared);
        } finally {
          copies.restore();
          await store.close();
        }
      },
    ),
    {
      seed: 2011501,
      numRuns: 24,
      examples: [
        [[2, 2], false],
        [[2, 2], true],
      ],
    },
  );
});

test('gapped revision indexes are rejected before any entry request', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 1, max: 1000 }),
      fc.integer({ min: 2, max: 10 }),
      async (start, count) => {
        const revisions = Array.from(
          { length: count },
          (_, index) => start + index * 2,
        );
        const store = await seedStorage({
          revision: revisions[count - 1],
          revisions,
          bytes: count,
          publications: [],
        });
        let requests = 0;
        const get = FakeObjectStore.prototype.get;
        const spy = jest
          .spyOn(FakeObjectStore.prototype, 'get')
          .mockImplementation(function (this: IDBObjectStore, key) {
            if (this.name === 'entries') requests++;
            return Reflect.apply(get, this, [key]);
          });
        try {
          await expect(store.load(storageKey)).rejects.toThrow();
          expect(requests).toBe(0);
        } finally {
          spy.mockRestore();
          await store.close();
        }
      },
    ),
    { seed: 2011505, numRuns: 24 },
  );
});

test('a failed owned copy aborts the read without changing stored rows or copying later entries', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.uint8Array({ minLength: 1, maxLength: 32 }), {
        minLength: 1,
        maxLength: 8,
      }),
      fc.nat(7),
      async (entries, failure) => {
        const failAt = failure % entries.length;
        const store = await seedStorage(
          {
            revision: entries.length,
            revisions: entries.map((_, index) => index + 1),
            bytes: entries.reduce((sum, entry) => sum + entry.byteLength, 0),
            publications: [],
          },
          entries,
        );
        const original = byteUtilities.copyUnsharedUint8Array;
        let attempts = 0;
        const spy = jest
          .spyOn(byteUtilities, 'copyUnsharedUint8Array')
          .mockImplementation((...args: Parameters<typeof original>) => {
            if (args[3] === 'stored journal entry' && attempts++ === failAt)
              throw new Error('Injected journal copy failure');
            return original(...args);
          });
        try {
          try {
            await expect(store.load(storageKey)).rejects.toThrow(
              'Injected journal copy failure',
            );
            expect(attempts).toBe(failAt + 1);
          } finally {
            spy.mockRestore();
          }
          expect((await store.load(storageKey)).entries).toEqual(entries);
        } finally {
          await store.close();
        }
      },
    ),
    { seed: 2011506, numRuns: 24 },
  );
});

test.each(['head', 'pending'] as const)(
  '%s rows must respect indexed byte sizes before copying',
  async (kind) => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 64 }), async (declared) => {
        const entry = new Uint8Array(declared + 1);
        const store = await seedStorage(
          kind === 'head'
            ? { revision: 1, revisions: [1], bytes: declared, publications: [] }
            : {
                revision: 0,
                revisions: [],
                bytes: 0,
                publications: [],
                pending: {
                  token: pendingToken,
                  bytes: declared,
                  checkpoint: false,
                  publicationBytes: 0,
                },
              },
          kind === 'head' ? [entry] : [],
          kind === 'pending' ? { token: pendingToken, entry } : undefined,
        );
        const copies = countCopies(
          kind === 'head' ? 'accepted journal entry' : 'pending entry',
        );
        try {
          await expect(
            kind === 'head'
              ? store.loadAcceptedHead(storageKey)
              : store.load(storageKey),
          ).rejects.toThrow();
          expect(copies.bytes).toBeLessThanOrEqual(declared);
        } finally {
          copies.restore();
          await store.close();
        }
      }),
      { seed: 2011502, numRuns: 24 },
    );
  },
);

test.each(['load', 'loadPublications'] as const)(
  '%s rejects mismatched publication sizes before copying their frame',
  async (read) => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 64 }), async (declared) => {
        const store = await seedStorage(
          {
            revision: 0,
            revisions: [],
            bytes: 0,
            publications: [
              { id: documentBytesId(publicationId), bytes: declared },
            ],
          },
          [],
          undefined,
          { id: publicationId, frame: new Uint8Array(declared + 1) },
        );
        const copies = countCopies('publication frame');
        try {
          await expect(store[read](storageKey)).rejects.toThrow();
          expect(copies.bytes).toBe(0);
        } finally {
          copies.restore();
          await store.close();
        }
      }),
      { seed: 2011503, numRuns: 24 },
    );
  },
);

test('authenticated replay copies each stored ciphertext once while isolating later provider mutations', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.uint8Array({ minLength: 1, maxLength: 128 }), {
        minLength: 1,
        maxLength: 6,
      }),
      async (changes) => {
        const f = await documentFixture();
        const key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        );
        const backing = new InMemoryDocumentJournalStore();
        const anchor = new InMemoryDocumentJournalRollbackAnchor();
        const journal = new DocumentReplayJournal(
          f.authority.documentId,
          f.authority.genesisId,
          key,
          backing,
          anchor,
        );
        await journal.restore();
        for (let index = 0; index < changes.length; index++) {
          await (
            await journal.prepare({
              checkpoint: index === 0,
              context: f.coordinator.documentContext,
              changes: changes[index],
              receipts:
                index === 0
                  ? []
                  : [
                      {
                        memberId: f.identity,
                        sequence: index,
                        hash: new Uint8Array(32).fill(index),
                      },
                    ],
              authorityHead: f.authority.headId,
              authorityRecords: [],
            })
          ).commit();
        }
        const snapshot = await backing.load(
          documentBytesId(f.authority.genesisId),
        );
        const expectedBytes = snapshot.entries.reduce(
          (sum, entry) => sum + entry.byteLength,
          0,
        );
        const loadAnchor = anchor.load.bind(anchor);
        anchor.load = async (key) => {
          for (const entry of snapshot.entries) entry.fill(0);
          return loadAnchor(key);
        };
        const store: DocumentJournalStore = {
          load: async () => snapshot,
          loadPublications: backing.loadPublications.bind(backing),
          stage: backing.stage.bind(backing),
          commit: backing.commit.bind(backing),
          discard: backing.discard.bind(backing),
        };
        const restored = new DocumentReplayJournal(
          f.authority.documentId,
          f.authority.genesisId,
          key,
          store,
          anchor,
        );
        const copies = countCopies('journal entry');
        try {
          const items = await restored.restore();
          expect(items.map((item) => item.changes)).toEqual(changes);
          expect(copies.bytes).toBe(expectedBytes);
        } finally {
          copies.restore();
        }
      },
    ),
    { seed: 2011504, numRuns: 12 },
  );
});
