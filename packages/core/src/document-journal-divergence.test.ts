import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import { IDBFactory as FakeIDBFactory } from 'fake-indexeddb';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
  type DocumentJournalItem,
  type DocumentJournalSnapshot,
  type DocumentJournalStore,
} from './document-replay-journal.js';
import {
  InMemoryDocumentJournalStore,
  IndexedDBDocumentJournalStore,
} from './document-journal-store.js';
import { documentFixture } from './__testutils__/coordinated-document.js';
import {
  DocumentBinaryWriter,
  documentBytesId,
} from './internal/document-binary.js';
import { writeDocumentContext } from './document-security-wire.js';
import {
  MAX_RECORDED_OPERATION_PATHS,
  recordDocumentOperationPaths,
} from './document-field-authorization.js';
import {
  firstUnauthorizedFieldPath,
  isFieldPathPrefix,
} from './policy/field-authorization.js';

type Fixture = Awaited<ReturnType<typeof documentFixture>>;
type Writer = (writer: DocumentBinaryWriter) => void;

let databases = 0;

async function setup(kind: 'memory' | 'indexeddb' = 'memory') {
  const f = await documentFixture();
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const anchor = new InMemoryDocumentJournalRollbackAnchor();
  const store =
    kind === 'memory'
      ? new InMemoryDocumentJournalStore()
      : new IndexedDBDocumentJournalStore(
          `journal-divergence-${++databases}`,
          new FakeIDBFactory(),
        );
  const make = (
    backing: DocumentJournalStore = store,
    rollback = anchor,
    documentId = f.authority.documentId,
  ) =>
    new DocumentReplayJournal(
      documentId,
      f.authority.genesisId,
      key,
      backing,
      rollback,
    );
  const checkpoint = (): DocumentJournalItem => ({
    checkpoint: true,
    context: f.coordinator.documentContext,
    changes: new Uint8Array([0]),
    receipts: [],
    authorityHead: f.authority.headId,
    authorityRecords: [],
  });
  const entry = (
    sequence: number,
    operationPaths: readonly (readonly string[])[] = [['a']],
    outboundFrame?: Uint8Array,
  ): DocumentJournalItem => ({
    checkpoint: false,
    context: f.coordinator.documentContext,
    changes: new Uint8Array([sequence]),
    receipts: [
      {
        memberId: f.identity,
        sequence,
        hash: new Uint8Array(32).fill(sequence),
      },
    ],
    authorityHead: f.authority.headId,
    authorityRecords: [],
    operationPaths,
    ...(outboundFrame ? { outboundFrame } : {}),
  });
  return {
    f,
    store,
    anchor,
    make,
    checkpoint,
    entry,
    storageKey: documentBytesId(f.authority.genesisId),
    close: async () => {
      if (store instanceof IndexedDBDocumentJournalStore) await store.close();
    },
  };
}

async function append(
  journal: DocumentReplayJournal,
  item: DocumentJournalItem,
) {
  await (await journal.prepare(item)).commit();
}

/** Seal arbitrary plaintext under the device key and accept it on the anchored path. */
async function appendRaw(
  journal: DocumentReplayJournal,
  store: DocumentJournalStore,
  storageKey: string,
  marker: number,
  plaintext: Uint8Array,
) {
  const internal = journal as any;
  const expected = internal.head,
    revision = journal.revision + 1,
    token = crypto.getRandomValues(new Uint8Array(32)),
    checkpoint = marker === 1;
  const sealed = await internal.sealEntry(
    expected,
    revision,
    marker,
    plaintext,
  );
  await store.stage(
    storageKey,
    expected?.revision ?? 0,
    token,
    sealed,
    undefined,
    checkpoint,
  );
  internal.head = (
    await internal.acceptStaged(expected, revision, token, checkpoint, sealed)
  ).next;
}

/** The current entry plaintext with a caller-written operation path tail. */
function encodeEntry(f: Fixture, checkpoint: boolean, tail?: Writer) {
  const writer = new DocumentBinaryWriter(4 * 1024 * 1024);
  writeDocumentContext(writer, f.coordinator.documentContext);
  writer.fixed(f.authority.headId).bytes(new Uint8Array([1]));
  if (checkpoint) writer.integer(0, 2);
  else
    writer
      .integer(1, 2)
      .fixed(f.identity)
      .integer(1, 8)
      .fixed(new Uint8Array(32).fill(1));
  writer.integer(0, 2).integer(0, 1);
  tail?.(writer);
  return writer.finish();
}

const pathList =
  (paths: readonly (readonly string[])[]): Writer =>
  (writer) => {
    writer.integer(paths.length, 2);
    for (const path of paths) {
      writer.integer(path.length, 1);
      for (const segment of path) writer.text(segment, 4096);
    }
  };

function hostile(
  store: DocumentJournalStore,
  snapshot: DocumentJournalSnapshot,
): DocumentJournalStore {
  return {
    load: async () => snapshot,
    loadPublications: async () => [],
    stage: store.stage.bind(store),
    commit: store.commit.bind(store),
    discard: store.discard.bind(store),
    publicationSent: store.publicationSent!.bind(store),
  };
}

test.each(['memory', 'indexeddb'] as const)(
  'a divergence marker survives restart and closes the %s journal to new entries',
  async (kind) => {
    const s = await setup(kind);
    try {
      const journal = s.make();
      await journal.restore();
      expect(journal.diverged).toBe(false);
      await append(journal, s.checkpoint());
      await append(journal, s.entry(1));
      await journal.markDiverged();
      expect(journal.diverged).toBe(true);
      await expect(journal.prepare(s.entry(2))).rejects.toThrow('unavailable');
      await journal.markDiverged();
      expect(journal.revision).toBe(3);

      const reopened = s.make();
      const items = await reopened.restore();
      expect(reopened.diverged).toBe(true);
      expect(items.map((item) => item.checkpoint)).toEqual([true, false]);
      expect(items[1].operationPaths).toEqual([['a']]);
      await expect(reopened.prepare(s.checkpoint())).rejects.toThrow(
        'unavailable',
      );

      const fresh = s.make(
        kind === 'memory'
          ? new InMemoryDocumentJournalStore()
          : new IndexedDBDocumentJournalStore(
              `journal-divergence-${++databases}`,
              new FakeIDBFactory(),
            ),
        new InMemoryDocumentJournalRollbackAnchor(),
      );
      expect(await fresh.restore()).toEqual([]);
      expect(fresh.diverged).toBe(false);
      await append(fresh, s.checkpoint());
      expect(fresh.revision).toBe(1);
    } finally {
      await s.close();
    }
  },
);

test('storage rolled back to before the divergence marker is rejected', async () => {
  const s = await setup();
  const journal = s.make();
  await journal.restore();
  await append(journal, s.checkpoint());
  await append(journal, s.entry(1));
  const before = await s.store.load(s.storageKey);
  await journal.markDiverged();
  await expect(s.make(hostile(s.store, before)).restore()).rejects.toThrow(
    'rollback',
  );
  const restored = s.make();
  await restored.restore();
  expect(restored.diverged).toBe(true);
});

test.each([0, 1, 3, 255])(
  'a divergence marker whose header flag reads %s is rejected',
  async (flag) => {
    const s = await setup();
    const journal = s.make();
    await journal.restore();
    await append(journal, s.checkpoint());
    await journal.markDiverged();
    const snapshot = await s.store.load(s.storageKey);
    const tampered = snapshot.entries.map((value) => value.slice());
    expect(tampered[1][12]).toBe(2);
    tampered[1][12] = flag;
    await expect(
      s.make(hostile(s.store, { ...snapshot, entries: tampered })).restore(),
    ).rejects.toThrow(/causal chain|acceptance marker/);
  },
);

test('a divergence marker with content, or an entry after one, is rejected', async () => {
  const withContent = await setup();
  const first = withContent.make();
  await first.restore();
  await append(first, withContent.checkpoint());
  await appendRaw(
    first,
    withContent.store,
    withContent.storageKey,
    2,
    new Uint8Array([0]),
  );
  await expect(withContent.make().restore()).rejects.toThrow(
    'divergence marker',
  );

  const followed = await setup();
  const second = followed.make();
  await second.restore();
  await append(second, followed.checkpoint());
  await second.markDiverged();
  (second as any).divergedMarker = false;
  await append(second, followed.entry(1));
  await expect(followed.make().restore()).rejects.toThrow(
    'follows a divergence marker',
  );
});

test('a divergence marker or path list replayed into another document or position is rejected', async () => {
  const s = await setup();
  const journal = s.make();
  await journal.restore();
  await append(journal, s.checkpoint());
  await append(journal, s.entry(1, [['x', 'y']]));
  await journal.markDiverged();
  const snapshot = await s.store.load(s.storageKey);
  const other = new InMemoryDocumentJournalRollbackAnchor();
  await expect(
    s.make(hostile(s.store, snapshot), other, '/other-document').restore(),
  ).rejects.toThrow('acceptance marker');
  const [base, delta, marker] = snapshot.entries;
  for (const entries of [
    [base, delta, delta],
    [base, marker],
    [base, marker, delta],
  ])
    await expect(
      s
        .make(
          hostile(s.store, { revision: entries.length, entries }),
          new InMemoryDocumentJournalRollbackAnchor(),
        )
        .restore(),
    ).rejects.toThrow();
});

test('restores each entry with its operation paths and its still-unsent publication', async () => {
  const s = await setup();
  const journal = s.make();
  await journal.restore();
  await append(journal, s.checkpoint());
  const sent = new Uint8Array([7, 7]),
    unsent = new Uint8Array([8, 8]);
  await append(journal, s.entry(1, [['a'], ['b', 'c']], sent));
  await append(journal, s.entry(2, [], unsent));
  await journal.publicationSent(sent);
  const items = await s.make().restore();
  expect(items[1].operationPaths).toEqual([['a'], ['b', 'c']]);
  expect(items[1].outboundFrame).toBeUndefined();
  expect(items[2].operationPaths).toEqual([]);
  expect(items[2].outboundFrame).toEqual(unsent);
});

test('journal entries require operation paths exactly on non-checkpoints', async () => {
  const s = await setup();
  const journal = s.make();
  await journal.restore();
  await expect(
    journal.prepare({ ...s.checkpoint(), operationPaths: [] }),
  ).rejects.toThrow('operation paths');
  const { operationPaths: _paths, ...missing } = s.entry(1);
  for (const item of [
    missing,
    s.entry(
      1,
      Array.from({ length: 4097 }, (_, index) => [`${index}`]),
    ),
    s.entry(1, [[long(1025)]]),
  ]) {
    const fresh = s.make(
      new InMemoryDocumentJournalStore(),
      new InMemoryDocumentJournalRollbackAnchor(),
    );
    await fresh.restore();
    await append(fresh, s.checkpoint());
    await expect(fresh.prepare(item)).rejects.toThrow(
      /field authorization|operation paths/,
    );
  }
});

const long = (units: number) => 'x'.repeat(units);

test.each<[string, boolean, Writer | undefined]>([
  ['a missing path list', false, undefined],
  [
    '4,097 paths',
    false,
    pathList(Array.from({ length: 4097 }, (_, i) => [`${i}`])),
  ],
  [
    'a 33-segment path',
    false,
    pathList([Array.from({ length: 33 }, () => 'a')]),
  ],
  ['a 1,025-unit segment', false, pathList([[long(1025)]])],
  [
    'more than 1,048,576 units',
    false,
    pathList(Array.from({ length: 1025 }, (_, i) => [`${i}`, long(1023)])),
  ],
  [
    'an invalid UTF-8 segment',
    false,
    (writer) => {
      writer
        .integer(1, 2)
        .integer(1, 1)
        .bytes(new Uint8Array([0xff]), 4096);
    },
  ],
  [
    'trailing bytes after the path list',
    false,
    (writer) => {
      pathList([['a']])(writer);
      writer.integer(0, 1);
    },
  ],
  ['a checkpoint with a path list', true, pathList([['a']])],
])(
  'a sealed journal entry with %s is rejected',
  async (_name, checkpoint, tail) => {
    const s = await setup();
    const journal = s.make();
    await journal.restore();
    if (!checkpoint) {
      await append(journal, s.checkpoint());
      await appendRaw(
        journal,
        s.store,
        s.storageKey,
        0,
        encodeEntry(s.f, false, pathList([['a']])),
      );
      expect((await s.make().restore())[1].operationPaths).toEqual([['a']]);
      await append(journal, s.checkpoint());
    }
    await appendRaw(
      journal,
      s.store,
      s.storageKey,
      checkpoint ? 1 : 0,
      encodeEntry(s.f, checkpoint, tail),
    );
    await expect(s.make().restore()).rejects.toThrow();
  },
);

const segment = fc.constantFrom('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h');
const fieldPath = fc.array(segment, { maxLength: 5 });

test('recorded operation paths are exact: grants cover the record exactly when they cover every path', () => {
  fc.assert(
    fc.property(
      fc.array(fieldPath, { maxLength: 400 }),
      fc.array(fieldPath, { maxLength: 6 }),
      (paths, grants) => {
        const record = recordDocumentOperationPaths(paths);
        const inputs = paths.map((path) => JSON.stringify(path));
        for (const path of record)
          expect(inputs).toContain(JSON.stringify(path));
        for (const [index, path] of record.entries())
          for (const [other, prefix] of record.entries())
            if (index !== other)
              expect(isFieldPathPrefix(prefix, path)).toBe(false);
        for (const path of paths)
          expect(record.some((prefix) => isFieldPathPrefix(prefix, path))).toBe(
            true,
          );
        expect(firstUnauthorizedFieldPath(grants, record) === -1).toBe(
          firstUnauthorizedFieldPath(grants, paths) === -1,
        );
      },
    ),
    { seed: 6920301, numRuns: 300 },
  );
  const bulk = [
    ['a'],
    ...Array.from({ length: 70 }, (_, index) => ['a', `x${index}`]),
    ['b', 'c'],
  ];
  expect(recordDocumentOperationPaths(bulk.slice(1))).toHaveLength(71);
  expect(recordDocumentOperationPaths(bulk)).toEqual([['a'], ['b', 'c']]);
  expect(
    recordDocumentOperationPaths(
      Array.from({ length: MAX_RECORDED_OPERATION_PATHS }, (_, index) => [
        'root',
        `${index}`,
      ]),
    ),
  ).toHaveLength(MAX_RECORDED_OPERATION_PATHS);
});

test.each(['memory', 'indexeddb'] as const)(
  'a diverged %s journal is deleted only once its unsent frames are drained or discarded, and a rebuild reuses the store with a new anchor',
  async (kind) => {
    const s = await setup(kind);
    try {
      const journal = s.make();
      await journal.restore();
      await append(journal, s.checkpoint());
      await expect(journal.deleteDiverged()).rejects.toThrow('diverged');
      await append(journal, s.entry(1, [['a']], new Uint8Array([5])));
      await journal.markDiverged();
      const stale = s.make();
      await stale.restore();
      await expect(stale.deleteDiverged()).rejects.toThrow('unsent');
      expect((await s.store.load(s.storageKey)).entries).toHaveLength(3);
      if (kind === 'memory') {
        await stale.publicationSent(new Uint8Array([5]));
        await stale.deleteDiverged();
      } else await stale.deleteDiverged({ discardUnsent: true });
      expect((await s.store.load(s.storageKey)).entries).toEqual([]);
      await expect(s.make().restore()).rejects.toThrow('rollback');
      const rebuilt = s.make(
        s.store,
        new InMemoryDocumentJournalRollbackAnchor(),
      );
      expect(await rebuilt.restore()).toEqual([]);
      expect(rebuilt.diverged).toBe(false);
      expect(await rebuilt.pendingPublications()).toEqual([]);
      await append(rebuilt, s.checkpoint());
    } finally {
      await s.close();
    }
  },
);
