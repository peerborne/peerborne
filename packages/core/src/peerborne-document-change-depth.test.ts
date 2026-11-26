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
import { KNOWN_CHANGE_GENERATION } from './known-changes.js';
import { loadAdvertisementHash } from './load-advertisement-hash.js';
import { PeerborneDocument } from './peerborne-document.js';
import { tipsHashToHex } from './tips-hash.js';
import { fixtureLoadCommitments } from './__testutils__/load-session.js';

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

describe('known-change sets', () => {
  let log: ReturnType<typeof jest.spyOn>;
  beforeEach(() => {
    log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  });
  afterEach(() => log.mockRestore());

  const serializer = new JSONSerializer<unknown>();
  const decode = (frame: Uint8Array) =>
    serializer.deserializeSyncMessage(frame.slice(32 + 12)) as any;

  // One generation of known, already-referenced remote CIDs, as a long remote
  // history leaves behind.
  const generationSize = KNOWN_CHANGE_GENERATION + 1;
  function learnRemoteHistory(document: any, generation: number): void {
    for (let index = 0; index < generationSize; index++) {
      const cid = `remote-${generation}-${index}`;
      document._hashes.add(cid);
      document._referencedAncestors.add(cid);
    }
  }

  const sorted = (cids: string[]) => [...cids].sort();

  async function servedDigest(document: any): Promise<string> {
    const message = document._lastSyncMessage;
    const manifest = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(
          JSON.stringify([
            message?.changeId,
            message?.changes,
            document._latestSnapshot?.lastChangeNodeCID,
          ]),
        ),
      ),
    );
    return tipsHashToHex(
      await loadAdvertisementHash(
        document.documentPath,
        sorted(document._servedFrontier()),
        fixtureLoadCommitments(),
        manifest,
      ),
    );
  }

  function receiver(document: any) {
    const remoteChange = jest.fn((current: unknown) => current);
    const notify = jest.fn(async () => undefined);
    document._crdtProvider.remoteChange = remoteChange;
    document._fireOrDeferRemoteUpdateHandlers = notify;
    document._getBlock = jest.fn(async () => {
      throw new Error('unexpected block fetch');
    });
    return { remoteChange, notify };
  }

  // A generation of remote history arrives and one more remote change syncs.
  async function syncRemoteGeneration(document: any, generation: number) {
    learnRemoteHistory(document, generation);
    await document._syncDocumentChanges(`remote-head-${generation}`, {
      kind: crdtDocumentChangeNode,
      change: { generation },
      ...(generation === 0
        ? {}
        : {
            children: {
              [`remote-head-${generation - 1}`]: {
                kind: crdtDocumentChangeNode,
              },
            },
          }),
    });
  }

  test('stay bounded through a long history and keep the frontier and served digest', async () => {
    const { document } = writerDocument();
    receiver(document);
    for (let index = 0; index < 5; index++)
      await document._makeChange({ index }, crdtDocumentChangeNode);
    await syncRemoteGeneration(document, 0);
    expect(document._hashes.has('remote-0-0')).toBe(true);
    learnRemoteHistory(document, 1);

    const frontier = sorted(document._currentFrontier());
    const served = sorted(document._servedFrontier());
    const digest = await servedDigest(document);
    const message = document._lastSyncMessage;
    document._trimKnownChanges();

    expect(document._hashes.has('remote-0-0')).toBe(false);
    expect(document._referencedAncestors.has('remote-0-0')).toBe(false);
    expect(document._hashes.has('remote-1-0')).toBe(true);
    expect(document._hashes.has(message.changeId)).toBe(true);
    expect(sorted(document._currentFrontier())).toEqual(frontier);
    expect(sorted(document._servedFrontier())).toEqual(served);
    expect(await servedDigest(document)).toBe(digest);
    expect(document._lastSyncMessage).toBe(message);

    for (let generation = 2; generation < 8; generation++) {
      await syncRemoteGeneration(document, generation);
      await document._makeChange({ generation }, crdtDocumentChangeNode);
      expect(document._hashes.size).toBeLessThanOrEqual(
        2 * KNOWN_CHANGE_GENERATION + 32,
      );
      expect(document._referencedAncestors.size).toBeLessThanOrEqual(
        2 * KNOWN_CHANGE_GENERATION + 32,
      );
    }
    expect(document._hashes.has('remote-5-0')).toBe(false);
    expect(document._hashes.has('remote-7-0')).toBe(true);
  });

  test('a replay within the window or beneath a retained CID is not applied again', async () => {
    const { document, published } = writerDocument();
    for (let index = 0; index < CHANGE_TREE_COMPACTION_DEPTH + 40; index++)
      await document._makeChange({ index }, crdtDocumentChangeNode);
    expect(document._latestSnapshot).toBeDefined();
    const messages = published.map(decode);
    learnRemoteHistory(document, 0);
    document._trimKnownChanges();
    learnRemoteHistory(document, 1);
    document._trimKnownChanges();

    const forgotten = messages[10].changeId;
    expect(document._hashes.has(forgotten)).toBe(false);
    const retained = messages.at(-1).changeId;
    expect(document._hashes.has(retained)).toBe(true);
    const deepRetained = messages.find(
      (message: any) =>
        document._hashes.has(message.changeId) &&
        Object.keys(message.changes.children ?? {}).some(
          (cid) => !document._hashes.has(cid),
        ),
    );
    expect(deepRetained).toBeDefined();

    const { remoteChange, notify } = receiver(document);
    const hashes = [...document._hashes];
    const count = document._documentChangeCount;
    const frontier = sorted(document._currentFrontier());
    for (const message of [messages.at(-1), deepRetained]) {
      await document._syncDocumentChanges(message.changeId, message.changes);
    }
    expect(remoteChange).not.toHaveBeenCalled();
    expect(notify).not.toHaveBeenCalled();
    expect([...document._hashes]).toEqual(hashes);
    expect(document._documentChangeCount).toBe(count);
    expect(sorted(document._currentFrontier())).toEqual(frontier);

    await document._syncDocumentChanges('remote-head', {
      kind: crdtDocumentChangeNode,
      change: { remote: true },
      children: { [deepRetained.changeId]: deepRetained.changes },
    });
    expect(remoteChange).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(['remote-head']);
    expect(document._documentChangeCount).toBe(count + 1);
    expect(document._hashes.has(forgotten)).toBe(false);
  });

  test('a message older than the window is applied again without changing what is served', async () => {
    const { document, published } = writerDocument();
    for (let index = 0; index < CHANGE_TREE_COMPACTION_DEPTH + 40; index++)
      await document._makeChange({ index }, crdtDocumentChangeNode);
    const old = decode(published[10]);
    learnRemoteHistory(document, 0);
    document._trimKnownChanges();
    learnRemoteHistory(document, 1);
    document._trimKnownChanges();
    expect(document._hashes.has(old.changeId)).toBe(false);

    const { remoteChange } = receiver(document);
    const served = sorted(document._servedFrontier());
    const digest = await servedDigest(document);
    const message = document._lastSyncMessage;
    await document._syncDocumentChanges(old.changeId, old.changes);

    expect(remoteChange).toHaveBeenCalledTimes(11);
    expect(document._lastSyncMessage).toBe(message);
    expect(sorted(document._servedFrontier())).toEqual(served);
    expect(await servedDigest(document)).toBe(digest);
  });

  test('a reader trims as remote changes arrive without taking a snapshot', async () => {
    const { document } = writerDocument({}, false);
    receiver(document);
    await syncRemoteGeneration(document, 0);
    await syncRemoteGeneration(document, 1);

    expect(document._latestSnapshot).toBeUndefined();
    expect(document._hashes.has('remote-0-0')).toBe(false);
    expect(document._hashes.has('remote-1-0')).toBe(true);
    expect(document._hashes.size).toBeLessThanOrEqual(generationSize + 2);
  });

  test('a writer that only edits locally trims at its depth-bound snapshots', async () => {
    const { document } = writerDocument();
    learnRemoteHistory(document, 0);
    let changes = 0;
    while (document._latestSnapshot === undefined)
      await document._makeChange({ index: changes++ }, crdtDocumentChangeNode);
    const first = document._latestSnapshot;
    expect(document._hashes.has('remote-0-0')).toBe(true);
    learnRemoteHistory(document, 1);
    while (document._latestSnapshot === first)
      await document._makeChange({ index: changes++ }, crdtDocumentChangeNode);

    expect(document._hashes.has('remote-0-0')).toBe(false);
    expect(document._hashes.has('remote-1-0')).toBe(true);
    expect(document._hashes.has(cidFor(1))).toBe(false);
    expect(document._hashes.has(document._lastSyncMessage.changeId)).toBe(true);
  });

  test('does not trim while bootstrap state application is pending', () => {
    const { document } = writerDocument();
    learnRemoteHistory(document, 0);
    document._trimKnownChanges();
    learnRemoteHistory(document, 1);
    document._bootstrapLoadApplicationState = 'pending';
    document._trimKnownChanges();
    expect(document._hashes.size).toBe(2 * generationSize);
    document._bootstrapLoadApplicationState = 'complete';
    document._trimKnownChanges();
    expect(document._hashes.size).toBe(generationSize);
  });
});
