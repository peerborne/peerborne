import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import {
  CHANGE_TREE_COMPACTION_DEPTH,
  CHANGE_TREE_COMPACTION_KEEP,
  MAX_CHANGE_TREE_DEPTH,
  changeTreeDepth,
} from './change-tree-walk.js';
import { mergeCompactionConfig } from './compaction-config.js';
import type { CompactionConfig } from './compaction-config.js';
import {
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import { JSONSerializer } from './json-serializer.js';
import { PeerborneDocument } from './peerborne-document.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock(
  'multiformats',
  () => ({
    CID: class {
      static parse(value: string) {
        return { toString: () => value };
      }
    },
  }),
  { virtual: true },
);
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Reject: 'reject' } }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

const cidFor = (index: number): string => `change-cid-${index}`;

function writerDocument(
  compaction: Partial<CompactionConfig> = {},
  isWriter = true,
) {
  const serializer = new JSONSerializer<unknown>();
  const published: Uint8Array[] = [];
  let blocks = 0;
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/change-depth',
    _userPublicKey: 'writer',
    _userKey: 'writer-key',
    _encoder: new TextEncoder(),
    _bootstrapLoadApplicationState: 'pristine',
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _writers: { check: jest.fn(async () => isWriter) },
    _hashes: new Set<string>(),
    _referencedAncestors: new Set<string>(),
    _recentTips: [],
    _putBlock: jest.fn(async () => cidFor(++blocks)),
    _signAsWriter: jest.fn(async () => 'AQ=='),
    _localHandlers: {},
    _keychain: {
      current: jest.fn(async () => [new Uint8Array(32).fill(1), { key: 1 }]),
    },
    _changesSerializer: serializer,
    _syncMessageSerializer: serializer,
    _authProvider: {
      encrypt: jest.fn(async (plaintext: Uint8Array) => ({
        nonce: new Uint8Array(12),
        data: plaintext,
      })),
      sign: jest.fn(async () => new Uint8Array([1])),
    },
    _topic: '/topic',
    swarm: {
      config: {},
      heliaNode: {
        libp2p: {
          services: {
            pubsub: {
              publish: jest.fn(async (_topic: string, bytes: Uint8Array) => {
                published.push(bytes);
              }),
            },
          },
        },
      },
    },
    _crdtProvider: { getSnapshot: jest.fn(() => ({ compacted: true })) },
    _document: {},
    _compactionConfig: mergeCompactionConfig(compaction),
    _snapshotUnsupported: false,
    _compactionInProgress: false,
    _documentChangeCount: 0,
    _changesSinceSnapshot: 0,
    _gcLifecycle: {},
  }) as any;
  return { document, published };
}

const retainedDepth = (document: any): number =>
  changeTreeDepth(document._lastSyncMessage.changes);

function danglingCrossLinks(root: CRDTChangeNode<unknown>): string[] {
  const inline = new Set<string>();
  const deferred: string[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop()!;
    for (const [id, child] of Object.entries(node.children ?? {})) {
      if (child.change === undefined) deferred.push(id);
      else inline.add(id);
      pending.push(child);
    }
  }
  return deferred.filter((id) => !inline.has(id));
}

function inlineChanges(root: CRDTChangeNode<unknown>): number {
  let count = 0;
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop()!;
    if (node.change !== undefined) count++;
    if (node.children) pending.push(...Object.values(node.children));
  }
  return count;
}

function deepRemoteTree(depth: number) {
  let changeId = cidFor(-1);
  let changes: CRDTChangeNode<unknown> = {
    kind: crdtDocumentChangeNode,
    change: { remote: 0 },
  };
  for (let level = 1; level < depth; level++) {
    const parent = changeId;
    changeId = cidFor(-1 - level);
    changes = {
      kind: crdtDocumentChangeNode,
      change: { remote: level },
      children: { [parent]: changes },
    };
  }
  return { changeId, changes };
}

describe('change tree depth bound', () => {
  let log: ReturnType<typeof jest.spyOn>;
  beforeEach(() => {
    log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  });
  afterEach(() => log.mockRestore());

  test.each([
    ['compaction disabled', {}],
    ['pruning disabled', { pruneAfterSnapshot: false }],
    ['retention above the bound', { keepRecentNodes: 10_000 }],
    ['zero retention', { keepRecentNodes: 0 }],
    [
      'periodic compaction past the bound',
      { enabled: true, minChangesBeforeSnapshot: 0, snapshotInterval: 500 },
    ],
  ])(
    'keeps publishing local changes past the depth limit with %s',
    async (_name, compaction) => {
      const { document, published } = writerDocument(compaction);
      const changes = MAX_CHANGE_TREE_DEPTH + 100;
      for (let index = 0; index < changes; index++) {
        await document._makeChange({ index }, crdtDocumentChangeNode);
        expect(retainedDepth(document)).toBeLessThanOrEqual(
          CHANGE_TREE_COMPACTION_DEPTH,
        );
      }
      expect(published).toHaveLength(changes);
      expect(document._latestSnapshot).toEqual(
        expect.objectContaining({ lastChangeNodeCID: expect.any(String) }),
      );
      expect(document._documentChangeCount).toBe(changes);
    },
  );

  test('keeps the most recent inline changes after a depth-bound prune', async () => {
    const { document } = writerDocument();
    let changes = 0;
    while (document._latestSnapshot === undefined) {
      await document._makeChange({ index: changes++ }, crdtDocumentChangeNode);
      expect(changes).toBeLessThanOrEqual(CHANGE_TREE_COMPACTION_DEPTH);
    }
    expect(inlineChanges(document._lastSyncMessage.changes)).toBe(
      CHANGE_TREE_COMPACTION_KEEP,
    );
    expect(retainedDepth(document)).toBe(CHANGE_TREE_COMPACTION_KEEP);
    expect(danglingCrossLinks(document._lastSyncMessage.changes)).toEqual([]);
  });

  test('a writer compacts an adopted deep remote tree before its next change', async () => {
    const { document } = writerDocument();
    const remote = deepRemoteTree(MAX_CHANGE_TREE_DEPTH - 1);
    document._refreshLastSyncMessageFromSync(remote.changeId, remote.changes);
    await document._maybeCompact();

    expect(document._latestSnapshot.lastChangeNodeCID).toBe(remote.changeId);
    expect(retainedDepth(document)).toBeLessThanOrEqual(
      CHANGE_TREE_COMPACTION_KEEP + 1,
    );
    await expect(
      document._makeChange({ local: true }, crdtDocumentChangeNode),
    ).resolves.toBeUndefined();
  });

  test('bounds a long run of membership changes', async () => {
    const { document, published } = writerDocument();
    for (let index = 0; index < 200; index++)
      await document._makeChange({ index }, crdtDocumentChangeNode);
    for (let index = 0; index < MAX_CHANGE_TREE_DEPTH; index++) {
      await document._makeChange(
        { add: `reader-${index}` },
        crdtReaderChangeNode,
      );
      expect(retainedDepth(document)).toBeLessThanOrEqual(
        CHANGE_TREE_COMPACTION_DEPTH,
      );
    }
    expect(published).toHaveLength(200 + MAX_CHANGE_TREE_DEPTH);
    await expect(
      document._makeChange({ after: true }, crdtDocumentChangeNode),
    ).resolves.toBeUndefined();
  });

  test.each([
    ['disabled', false, 0],
    ['enabled', true, 1],
  ])(
    'collects pruned blocks only when pruning is %s',
    async (_name, pruneAfterSnapshot, collections) => {
      const { document } = writerDocument({
        pruneAfterSnapshot,
        gcAfterPrune: true,
      });
      document._gcPrunedBlocks = jest.fn(async () => undefined);
      for (let index = 0; index < CHANGE_TREE_COMPACTION_DEPTH; index++)
        await document._makeChange({ index }, crdtDocumentChangeNode);
      expect(document._latestSnapshot).toBeDefined();
      expect(document._gcPrunedBlocks).toHaveBeenCalledTimes(collections);
    },
  );

  test('a failed depth-bound snapshot keeps the published change and retries', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const { document, published } = writerDocument();
      document._crdtProvider.getSnapshot.mockImplementationOnce(() => {
        throw new Error('snapshot unavailable');
      });
      for (let index = 0; index < CHANGE_TREE_COMPACTION_DEPTH; index++)
        await document._makeChange({ index }, crdtDocumentChangeNode);
      const head = document._lastSyncMessage.changeId;
      expect(document._hashes.has(head)).toBe(true);
      expect(document._latestSnapshot).toBeUndefined();
      expect(warn).toHaveBeenCalledWith(
        'Depth-bound compaction failed for /change-depth',
      );

      await document._makeChange({ next: true }, crdtDocumentChangeNode);
      expect(published).toHaveLength(CHANGE_TREE_COMPACTION_DEPTH + 1);
      expect(document._latestSnapshot).toBeDefined();
      expect(retainedDepth(document)).toBeLessThanOrEqual(
        CHANGE_TREE_COMPACTION_KEEP + 1,
      );
    } finally {
      warn.mockRestore();
    }
  });

  test('a reader leaves an adopted deep remote tree unsnapshotted', async () => {
    const { document } = writerDocument({}, false);
    const remote = deepRemoteTree(CHANGE_TREE_COMPACTION_DEPTH + 10);
    document._refreshLastSyncMessageFromSync(remote.changeId, remote.changes);
    await document._maybeCompact();

    expect(document._latestSnapshot).toBeUndefined();
    expect(retainedDepth(document)).toBe(CHANGE_TREE_COMPACTION_DEPTH + 10);
  });
});
