import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  IDBFactory,
  IDBDatabase as FakeDatabase,
  IDBObjectStore as FakeObjectStore,
} from 'fake-indexeddb';
import {
  InMemoryDocumentJournalStore,
  IndexedDBDocumentJournalStore,
} from './document-journal-store.js';
import {
  DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD,
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
  MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
  MAX_DOCUMENT_JOURNAL_BYTES,
  MAX_DOCUMENT_JOURNAL_ENTRIES,
  type DocumentJournalPublication,
  type DocumentJournalSnapshot,
} from './document-replay-journal.js';
import { planJournalPublication } from './policy/journal-store.js';
import * as byteUtilities from './utils.js';
import {
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import { documentFixture } from './__testutils__/coordinated-document.js';

type Backend = 'memory' | 'indexeddb';
function createStore(backend: Backend) {
  return backend === 'memory'
    ? new InMemoryDocumentJournalStore()
    : new IndexedDBDocumentJournalStore('transition-history', new IDBFactory());
}

async function storedRows(factory: IDBFactory, name: string) {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(name, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise<
      Record<string, { keys: IDBValidKey[]; rows: unknown[] }>
    >((resolve, reject) => {
      const names = ['heads', 'entries', 'pending', 'publications'];
      const transaction = database.transaction(names, 'readonly');
      const result: Record<string, { keys: IDBValidKey[]; rows: unknown[] }> =
        {};
      for (const name of names) {
        const objectStore = transaction.objectStore(name);
        const keys = objectStore.getAllKeys(),
          rows = objectStore.getAll();
        result[name] = { keys: [], rows: [] };
        keys.onsuccess = () => {
          result[name].keys = keys.result;
        };
        rows.onsuccess = () => {
          result[name].rows = rows.result;
        };
      }
      transaction.oncomplete = () => resolve(result);
      transaction.onabort = transaction.onerror = () =>
        reject(transaction.error);
    });
  } finally {
    database.close();
  }
}

test.each(['memory', 'indexeddb'] as const)(
  '%s captures a publication byte reservation once before validating it',
  async (backend) => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        async (frame) => {
          const store = createStore(backend);
          let reads = 0;
          const publication = {
            id: syntheticId(4),
            get bytes() {
              return ++reads === 1 ? frame.length : NaN;
            },
          };
          try {
            await store.stage(
              'doc',
              0,
              syntheticId(1),
              new Uint8Array([1]),
              publication,
            );
            expect(reads).toBe(1);
            expect((await store.load('doc')).pending?.publication?.bytes).toBe(
              frame.length,
            );
            await store.commit(
              'doc',
              0,
              syntheticId(1),
              false,
              new Uint8Array(33),
              { id: syntheticId(4), frame },
            );
            expect((await store.load('doc')).revision).toBe(1);
          } finally {
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          }
        },
      ),
      { seed: 2012009, numRuns: 16 },
    );
  },
);

const action = fc.record({
  kind: fc.constantFrom('stage', 'commit', 'ack', 'discard'),
  id: fc.integer({ min: 0, max: 6 }),
  checkpoint: fc.boolean(),
  publishes: fc.boolean(),
  stale: fc.boolean(),
  fault: fc.constantFrom(
    'none',
    'token',
    'checkpoint',
    'length',
    'publication',
  ),
  entry: fc.uint8Array({ minLength: 1, maxLength: 24 }),
  frame: fc.uint8Array({ minLength: 1, maxLength: 24 }),
});
type Action = typeof action extends fc.Arbitrary<infer Value> ? Value : never;
const syntheticId = (value: number) => new Uint8Array(32).fill(value);

interface Model {
  revision: number;
  entries: Uint8Array[];
  publications: DocumentJournalPublication[];
  pending?: {
    token: Uint8Array;
    entry: Uint8Array;
    checkpoint: boolean;
    publication?: DocumentJournalPublication;
  };
}

function expectSnapshot(snapshot: DocumentJournalSnapshot, model: Model) {
  expect(snapshot.revision).toBe(model.revision);
  expect(snapshot.entries).toEqual(model.entries);
  expect(snapshot.publications ?? []).toEqual(model.publications);
  expect(snapshot.pending).toEqual(
    model.pending && {
      token: model.pending.token,
      entry: model.pending.entry,
      ...(model.pending.publication
        ? {
            publication: {
              id: model.pending.publication.id,
              bytes: model.pending.publication.frame.length,
            },
          }
        : {}),
    },
  );
}

async function executeAction(
  store: ReturnType<typeof createStore>,
  model: Model,
  command: Action,
) {
  const before = await store.load('doc');
  const expectedRevision = command.stale
    ? Math.max(0, model.revision - 1)
    : model.revision;
  if (command.kind === 'stage') {
    const id = syntheticId(command.id),
      token = syntheticId(command.id + 10);
    const publication = command.publishes
      ? { id, frame: command.frame.slice() }
      : undefined;
    const admissible =
      !model.pending &&
      expectedRevision === model.revision &&
      (command.checkpoint || model.entries.length < 128) &&
      (!publication ||
        (model.publications.length < 16 &&
          model.publications.every(
            (existing) => !documentBytesEqual(existing.id, id),
          )));
    const operation = (async () =>
      store.stage(
        'doc',
        expectedRevision,
        token,
        command.entry,
        publication && { id, bytes: publication.frame.length },
        command.checkpoint,
      ))();
    if (admissible) {
      await operation;
      model.pending = {
        token: token.slice(),
        entry: command.entry.slice(),
        checkpoint: command.checkpoint,
        publication,
      };
    } else {
      await expect(operation).rejects.toThrow();
      expect(await store.load('doc')).toEqual(before);
    }
  } else if (command.kind === 'commit') {
    const pending = model.pending;
    const token = pending?.token.slice() ?? syntheticId(9);
    if (command.fault === 'token') token[0] ^= 0x80;
    const checkpoint =
      command.fault === 'checkpoint'
        ? !pending?.checkpoint
        : (pending?.checkpoint ?? false);
    const accepted = new Uint8Array(
      (pending?.entry.length ?? 1) +
        DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD +
        (command.fault === 'length' ? 1 : 0),
    );
    accepted.fill(command.id);
    let publication = pending?.publication && {
      id: pending.publication.id.slice(),
      frame: pending.publication.frame.slice(),
    };
    if (command.fault === 'publication') {
      publication ??= { id: syntheticId(8), frame: new Uint8Array([1]) };
      publication.id[0] ^= 0x80;
    }
    const admissible =
      !!pending &&
      expectedRevision === model.revision &&
      documentBytesEqual(token, pending.token) &&
      checkpoint === pending.checkpoint &&
      accepted.length ===
        pending.entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD &&
      !!publication === !!pending.publication &&
      (!publication ||
        documentBytesEqual(publication.id, pending.publication!.id));
    const operation = (async () =>
      store.commit(
        'doc',
        expectedRevision,
        token,
        checkpoint,
        accepted,
        publication,
      ))();
    if (admissible) {
      await operation;
      model.entries = checkpoint
        ? [accepted.slice()]
        : [...model.entries, accepted.slice()];
      if (publication) model.publications.push(publication);
      model.revision++;
      model.pending = undefined;
    } else {
      await expect(operation).rejects.toThrow();
      expect(await store.load('doc')).toEqual(before);
    }
  } else if (command.kind === 'ack') {
    const id = syntheticId(command.id);
    await store.publicationSent('doc', id);
    model.publications = model.publications.filter(
      (publication) => !documentBytesEqual(publication.id, id),
    );
  } else {
    const token = model.pending?.token.slice() ?? syntheticId(9);
    if (command.fault === 'token') token[0] ^= 0x80;
    await store.discard('doc', token);
    if (model.pending && documentBytesEqual(model.pending.token, token))
      model.pending = undefined;
  }
  expectSnapshot(await store.load('doc'), model);
}

test.each(['memory', 'indexeddb'] as const)(
  '%s rejects a duplicate queued publication before staging changes',
  async (backend) => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        fc.boolean(),
        async (frame, checkpoint) => {
          const store =
            backend === 'memory'
              ? new InMemoryDocumentJournalStore()
              : new IndexedDBDocumentJournalStore(
                  'journal-transitions',
                  new IDBFactory(),
                );
          const id = new Uint8Array(32).fill(7);
          const token = new Uint8Array(32).fill(1);
          const entry = new Uint8Array([9]);
          try {
            await store.stage('doc', 0, token, entry, {
              id,
              bytes: frame.length,
            });
            await store.commit(
              'doc',
              0,
              token,
              false,
              new Uint8Array(entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD),
              { id, frame },
            );
            const before = await store.load('doc');
            await expect(
              (async () =>
                store.stage(
                  'doc',
                  1,
                  new Uint8Array(32).fill(2),
                  entry,
                  { id, bytes: frame.length },
                  checkpoint,
                ))(),
            ).rejects.toThrow();
            expect(await store.load('doc')).toEqual(before);
          } finally {
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          }
        },
      ),
      { seed: 2012001, numRuns: 12 },
    );
  },
);

test.each(['memory', 'indexeddb'] as const)(
  '%s binds commit compaction to the staged checkpoint flag',
  async (backend) => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        async (checkpoint, entry) => {
          const store =
            backend === 'memory'
              ? new InMemoryDocumentJournalStore()
              : new IndexedDBDocumentJournalStore(
                  'checkpoint-binding',
                  new IDBFactory(),
                );
          const token = new Uint8Array(32).fill(3);
          const accepted = new Uint8Array(
            entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD,
          );
          try {
            await store.stage('doc', 0, token, entry, undefined, checkpoint);
            const before = await store.load('doc');
            await expect(
              store.commit('doc', 0, token, !checkpoint, accepted),
            ).rejects.toThrow();
            expect(await store.load('doc')).toEqual(before);
            await store.commit('doc', 0, token, checkpoint, accepted);
            expect((await store.load('doc')).revision).toBe(1);
          } finally {
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          }
        },
      ),
      { seed: 2012002, numRuns: 12 },
    );
  },
);

test.each(['memory', 'indexeddb'] as const)(
  '%s rejects malformed checkpoint flags without persisting an invalid pending record',
  async (backend) => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(fc.integer(), fc.string(), fc.constant(null)),
        async (checkpoint) => {
          const store =
            backend === 'memory'
              ? new InMemoryDocumentJournalStore()
              : new IndexedDBDocumentJournalStore(
                  'checkpoint-shape',
                  new IDBFactory(),
                );
          try {
            await expect(
              (async () =>
                store.stage(
                  'doc',
                  0,
                  new Uint8Array(32),
                  new Uint8Array([1]),
                  undefined,
                  checkpoint as unknown as boolean,
                ))(),
            ).rejects.toThrow();
            expect(await store.load('doc')).toEqual(
              expect.objectContaining({ revision: 0, entries: [] }),
            );
          } finally {
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          }
        },
      ),
      { seed: 2012003, numRuns: 12 },
    );
  },
);

test('both stores agree with an independent model through rejected commits, acknowledgements and compaction', async () => {
  const example: Action = {
    kind: 'stage',
    id: 0,
    checkpoint: false,
    publishes: true,
    stale: false,
    fault: 'none',
    entry: new Uint8Array([1]),
    frame: new Uint8Array([2]),
  };
  await fc.assert(
    fc.asyncProperty(
      fc.array(action, { minLength: 1, maxLength: 45 }),
      async (program) => {
        const stores = [createStore('memory'), createStore('indexeddb')];
        const models: Model[] = stores.map(() => ({
          revision: 0,
          entries: [],
          publications: [],
        }));
        try {
          for (const command of program) {
            for (let index = 0; index < stores.length; index++)
              await executeAction(stores[index], models[index], command);
            expect(models[0]).toEqual(models[1]);
          }
        } finally {
          await (stores[1] as IndexedDBDocumentJournalStore).close();
        }
      },
    ),
    {
      seed: 2012004,
      numRuns: 80,
      examples: [
        [
          [
            example,
            { ...example, kind: 'ack' },
            { ...example, kind: 'commit' },
            { ...example, id: 1, checkpoint: true },
            { ...example, kind: 'discard', fault: 'token' },
            { ...example, kind: 'ack' },
            { ...example, kind: 'commit', fault: 'checkpoint' },
            { ...example, kind: 'commit' },
          ],
        ],
      ],
    },
  );
});

test('native publication plans preserve owned records and match BigInt queue budgets and array projection', () => {
  expect(MAX_DOCUMENT_STORED_PUBLICATION_BYTES).toBe(1048648);
  expect(MAX_DOCUMENT_JOURNAL_BYTES).toBe(134217728);
  expect(MAX_DOCUMENT_JOURNAL_ENTRIES).toBe(128);
  expect(DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD).toBe(32);
  const row = fc.record({
    id: fc.integer({ min: 0, max: 24 }).map(String),
    bytes: fc.integer({ min: 1, max: MAX_DOCUMENT_STORED_PUBLICATION_BYTES }),
  });
  fc.assert(
    fc.property(
      fc.uniqueArray(row, { maxLength: 16, selector: (row) => row.id }),
      fc.integer({ min: 0, max: 24 }).map(String),
      fc.integer({ min: 1, max: MAX_DOCUMENT_STORED_PUBLICATION_BYTES }),
      fc.boolean(),
      (rows, id, bytes, append) => {
        const inputs = Object.freeze(
          rows.map((row) => Object.freeze({ ...row })),
        );
        const retained = rows.flatMap((row, index) =>
          append || row.id !== id ? [index] : [],
        );
        const selected = retained.map((index) => rows[index]);
        const total = selected.reduce(
          (sum, row) => sum + BigInt(row.bytes),
          append ? BigInt(bytes) : 0n,
        );
        const duplicate = append && rows.some((row) => row.id === id);
        const decision = duplicate
          ? 'duplicate'
          : (append && rows.length === 16) || total > 16n * 1024n * 1024n
            ? 'capacity'
            : 'accept';
        const expected = {
          decision,
          publications:
            decision === 'accept'
              ? [...selected, ...(append ? [{ id, bytes }] : [])]
              : [],
          retained: decision === 'accept' ? retained : [],
          bytes: decision === 'accept' ? Number(total) : 0,
        };
        const plan = planJournalPublication(
          inputs,
          id,
          append ? bytes : 0,
          append,
        );
        expect(plan).toEqual(expected);
        if (plan.publications.length)
          (plan.publications[0] as { id: string; bytes: number }).id =
            'changed';
        (plan.retained as number[]).fill(-1);
        expect(inputs).toEqual(rows);
        expect(
          planJournalPublication(inputs, id, append ? bytes : 0, append),
        ).toEqual(expected);
      },
    ),
    {
      seed: 2012005,
      numRuns: 350,
      examples: [
        [
          Array.from({ length: 16 }, (_, index) => ({
            id: String(index),
            bytes: MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
          })),
          'missing',
          1,
          false,
        ],
        [
          Array.from({ length: 16 }, (_, index) => ({
            id: String(index),
            bytes: MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
          })),
          '0',
          1,
          false,
        ],
        [
          Array.from({ length: 16 }, (_, index) => ({
            id: String(index),
            bytes: MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
          })),
          '0',
          1,
          true,
        ],
        [[], 'fresh', 1, true],
      ],
    },
  );
});

test.each(['memory', 'indexeddb'] as const)(
  '%s rejects malformed scalar mutations before payload copying or write transactions',
  async (backend) => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          -1,
          NaN,
          Infinity,
          1.5,
          Number.MAX_SAFE_INTEGER + 1,
          '0',
          null,
        ),
        fc.boolean(),
        fc.boolean(),
        async (invalid, invalidFlag, commit) => {
          const store = createStore(backend);
          await store.load('doc');
          const copy = byteUtilities.copyUnsharedUint8Array;
          const transaction = FakeDatabase.prototype.transaction;
          let copies = 0,
            writes = 0;
          const copySpy = jest
            .spyOn(byteUtilities, 'copyUnsharedUint8Array')
            .mockImplementation((...args: Parameters<typeof copy>) => {
              copies++;
              return copy(...args);
            });
          const transactionSpy = jest
            .spyOn(FakeDatabase.prototype, 'transaction')
            .mockImplementation(function (this: IDBDatabase, ...args) {
              if (args[1] === 'readwrite') writes++;
              return Reflect.apply(transaction, this, args);
            });
          try {
            const revision = (invalidFlag ? 0 : invalid) as number;
            const checkpoint = (invalidFlag ? invalid : false) as boolean;
            await expect(
              (async () =>
                commit
                  ? store.commit(
                      'doc',
                      revision,
                      syntheticId(0),
                      checkpoint,
                      new Uint8Array([1]),
                    )
                  : store.stage(
                      'doc',
                      revision,
                      syntheticId(0),
                      new Uint8Array([1]),
                      undefined,
                      checkpoint,
                    ))(),
            ).rejects.toThrow();
            expect(copies).toBe(0);
            expect(writes).toBe(0);
          } finally {
            copySpy.mockRestore();
            transactionSpy.mockRestore();
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          }
        },
      ),
      { seed: 2012006, numRuns: 24 },
    );
  },
);

test('aborted IndexedDB stage and checkpoint commit transactions preserve every prior row', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      fc.boolean(),
      async (entry, duringCommit) => {
        const factory = new IDBFactory(),
          name = 'aborted-transition';
        const store = new IndexedDBDocumentJournalStore(name, factory);
        const accepted = new Uint8Array(
          entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD,
        );
        const token = syntheticId(1),
          id = syntheticId(2),
          frame = new Uint8Array([3]);
        try {
          await store.stage('doc', 0, token, entry, { id, bytes: 1 });
          await store.commit('doc', 0, token, false, accepted, { id, frame });
          const nextId = syntheticId(4);
          if (duringCommit)
            await store.stage(
              'doc',
              1,
              token,
              entry,
              { id: nextId, bytes: 1 },
              true,
            );
          const before = await store.load('doc');
          const beforeRows = await storedRows(factory, name);
          const put = FakeObjectStore.prototype.put;
          let precedingWrites = 0;
          const spy = jest
            .spyOn(FakeObjectStore.prototype, 'put')
            .mockImplementation(function (this: IDBObjectStore, ...args) {
              if (this.name === 'heads')
                throw new Error('Injected head write failure');
              precedingWrites++;
              return Reflect.apply(put, this, args);
            });
          try {
            await expect(
              (async () =>
                duringCommit
                  ? store.commit('doc', 1, token, true, accepted, {
                      id: nextId,
                      frame,
                    })
                  : store.stage(
                      'doc',
                      1,
                      token,
                      entry,
                      { id: nextId, bytes: 1 },
                      true,
                    ))(),
            ).rejects.toThrow();
            expect(precedingWrites).toBeGreaterThan(0);
          } finally {
            spy.mockRestore();
          }
          expect(await store.load('doc')).toEqual(before);
          expect(await storedRows(factory, name)).toEqual(beforeRows);
          if (!duringCommit)
            await store.stage(
              'doc',
              1,
              token,
              entry,
              { id: nextId, bytes: 1 },
              true,
            );
          await store.commit('doc', 1, token, true, accepted, {
            id: nextId,
            frame,
          });
          const after = await store.load('doc');
          expect(after.revision).toBe(2);
          expect(after.entries).toEqual([accepted]);
          expect(after.publications).toEqual([
            { id, frame },
            { id: nextId, frame },
          ]);
        } finally {
          await store.close();
        }
      },
    ),
    { seed: 2012007, numRuns: 20 },
  );
});

test.each(['memory', 'indexeddb'] as const)(
  '%s remains recoverable after rejecting an encrypted duplicate publication',
  async (backend) => {
    const fixture = await documentFixture();
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 48 }),
        fc.boolean(),
        async (frame, checkpoint) => {
          const key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
          );
          const store = createStore(backend),
            anchor = new InMemoryDocumentJournalRollbackAnchor();
          const make = () =>
            new DocumentReplayJournal(
              fixture.authority.documentId,
              fixture.authority.genesisId,
              key,
              store,
              anchor,
            );
          const item = {
            checkpoint,
            context: fixture.coordinator.documentContext,
            changes: new Uint8Array([1]),
            receipts: [
              { memberId: fixture.identity, sequence: 1, hash: syntheticId(7) },
            ],
            authorityHead: fixture.authority.headId,
            authorityRecords: [],
            outboundFrame: frame,
          };
          try {
            const journal = make();
            await journal.restore();
            await (await journal.prepare(item)).commit();
            const before = await store.load(
              documentBytesId(fixture.authority.genesisId),
            );
            await expect(
              journal.prepare({ ...item, checkpoint: !checkpoint }),
            ).rejects.toThrow();
            expect(
              await store.load(documentBytesId(fixture.authority.genesisId)),
            ).toEqual(before);
            const recovered = make();
            expect(await recovered.restore()).toHaveLength(1);
            expect(await recovered.pendingPublications()).toEqual([frame]);
            await recovered.publicationSent(frame);
            await (
              await recovered.prepare({ ...item, checkpoint: false })
            ).commit();
            expect(recovered.revision).toBe(2);
            expect(await recovered.pendingPublications()).toEqual([frame]);
          } finally {
            if (store instanceof IndexedDBDocumentJournalStore)
              await store.close();
          }
        },
      ),
      { seed: 2012008, numRuns: 16 },
    );
  },
);
