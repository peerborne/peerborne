import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import { mergeCompactionConfig } from './compaction-config.js';
import {
  CHANGE_TREE_COMPACTION_DEPTH,
  changeTreeDepth,
} from './change-tree-walk.js';
import {
  crdtDocumentChangeNode,
  crdtWriterChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import {
  GossipFrameLimitError,
  MAX_CHANGE_FRAME_BYTES,
  MAX_GOSSIP_SYNC_MESSAGE_BYTES,
} from './gossip-frame.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
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

type Node = CRDTChangeNode<unknown>;
const KEY_AND_NONCE = 44;
const serializer = new JSONSerializer<unknown>();

/**
 * A writer whose provider returns a new document per change, like Automerge,
 * or edits in place, like Yjs.
 */
function writerDocument(name: string, inPlace = false) {
  const published: Uint8Array[] = [];
  let blocks = 0;
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/gossip-frame',
    _userPublicKey: 'writer',
    _userKey: 'writer-key',
    _encoder: new TextEncoder(),
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
    _mutationQueue: new InvitationMembershipQueue(),
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _writers: { check: jest.fn(async () => true) },
    _verifySyncRequest: jest.fn(async () => true),
    _syncRequestsSeen: new Map(),
    _syncRequestClock: 0,
    _lastSyncResponseAt: 0,
    _subscribed: true,
    _hashes: new Set<string>(),
    _referencedAncestors: new Set<string>(),
    _recentTips: [],
    _putBlock: jest.fn(async () => `${name}-cid-${++blocks}`),
    _signAsWriter: jest.fn(async () => 'AQ=='),
    _localHandlers: {},
    _remoteHandlers: {},
    _deliveryFailureHandlers: {},
    _deliveryStateHandlers: {},
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
    _crdtProvider: {
      getSnapshot: jest.fn(() => ({ compacted: true })),
      localChange: jest.fn(
        (current: Record<string, unknown>, _message: string, changeFn) => {
          const draft: Record<string, unknown> = {};
          const change =
            (changeFn as (draft: object) => unknown)(draft) ?? draft;
          if (inPlace) {
            current.last = change;
            return [current, change];
          }
          return [{ ...current, last: change }, change];
        },
      ),
    },
    _document: { last: undefined },
    _compactionConfig: mergeCompactionConfig({}),
    _snapshotUnsupported: false,
    _compactionInProgress: false,
    _documentChangeCount: 0,
    _changesSinceSnapshot: 0,
    _gcLifecycle: {},
    _closeDocument: jest.fn(async () => undefined),
  }) as any;
  return { document, published };
}

const decode = (frame: Uint8Array) =>
  serializer.deserializeSyncMessage(frame.slice(KEY_AND_NONCE));

/** Nodes that name a change by CID while still carrying its ancestry. */
function payloadsSentByCid(root: Node): number {
  let count = 0;
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop()!;
    if (node.change === undefined && node.children !== undefined) count++;
    if (node.children) pending.push(...Object.values(node.children));
  }
  return count;
}

let warn: ReturnType<typeof jest.spyOn>;
let log: ReturnType<typeof jest.spyOn>;
beforeEach(() => {
  warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
});
afterEach(() => {
  warn.mockRestore();
  log.mockRestore();
});

test('frames stay within GossipSub with every change inline while history grows', async () => {
  const { document, published } = writerDocument('a');
  for (let index = 0; index < 30; index++)
    await document.change(() => ({ index, text: 'x'.repeat(200_000) }));
  expect(published).toHaveLength(30);
  expect(document._latestSnapshot).toBeDefined();
  for (const frame of published) {
    expect(frame.byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
      MAX_GOSSIP_SYNC_MESSAGE_BYTES,
    );
    expect(payloadsSentByCid(decode(frame).changes!)).toBe(0);
  }
});

test('a writer that adopts each published tree prunes it to the same tree as its author', async () => {
  const author = writerDocument('author');
  const receiver = writerDocument('receiver');
  for (let index = 0; index < 20; index++) {
    await author.document.change(() => ({ index, text: 'y'.repeat(300_000) }));
    const bytes = author.published.at(-1)!;
    const frame = decode(bytes);
    receiver.document._refreshLastSyncMessageFromSync(
      frame.changeId,
      frame.changes,
    );
    await receiver.document._maybeCompact(
      undefined,
      bytes.byteLength - KEY_AND_NONCE,
    );
  }
  expect(author.document._latestSnapshot).toBeDefined();
  expect(receiver.document._latestSnapshot).toBeDefined();
  // Load digests can still differ: each writer signs its own snapshot.
  expect(receiver.document._lastSyncMessage.changeId).toBe(
    author.document._lastSyncMessage.changeId,
  );
  expect(receiver.document._lastSyncMessage.changes).toEqual(
    author.document._lastSyncMessage.changes,
  );
});

test('a depth-bound prune of a large tree also keeps it within the size bound', async () => {
  const { document, published } = writerDocument('a');
  let changeId = 'remote-0';
  let changes: Node = { kind: crdtDocumentChangeNode, change: { remote: 0 } };
  for (let level = 1; level < CHANGE_TREE_COMPACTION_DEPTH + 4; level++) {
    const parent = changeId;
    changeId = `remote-${level}`;
    changes = {
      kind: crdtDocumentChangeNode,
      change: { level, text: 'd'.repeat(20_000) },
      children: { [parent]: changes },
    };
  }
  document._refreshLastSyncMessageFromSync(changeId, changes);
  const frameBytes = serializer.serializeSyncMessage({
    documentId: '/gossip-frame',
    signatureContext: 'ordinary-sync-v1',
    changeId,
    changes,
  }).byteLength;
  expect(frameBytes).toBeGreaterThan(MAX_GOSSIP_SYNC_MESSAGE_BYTES);
  await document._maybeCompact(undefined, frameBytes);
  // The next change at the per-change limit still fits one frame.
  await expect(
    document.change(() => ({
      text: 'n'.repeat(MAX_CHANGE_FRAME_BYTES - 4096),
    })),
  ).resolves.toBeUndefined();
  expect(published.at(-1)!.byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
    MAX_GOSSIP_SYNC_MESSAGE_BYTES,
  );
});

test.each([
  ['a provider that returns a new document', false],
  ['an in-place provider', true],
])(
  'with %s, a change too large for one frame never reaches history and retires the instance',
  async (_name, inPlace) => {
    const { document, published } = writerDocument('a', inPlace);
    await document.change(() => ({ small: 1 }));
    const hashes = [...document._hashes];
    const tree = document._lastSyncMessage;
    const tips = [...document._recentTips];
    const blocks = document._putBlock.mock.calls.length;
    const error = await document
      .change(() => ({ text: 'z'.repeat(MAX_CHANGE_FRAME_BYTES) }))
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GossipFrameLimitError);
    expect((error as GossipFrameLimitError).limit).toBe(MAX_CHANGE_FRAME_BYTES);
    expect((error as GossipFrameLimitError).retired).toBe(true);
    expect((error as Error).message).toContain('instance was retired');
    expect(document._putBlock.mock.calls.length).toBe(blocks);
    expect(document._signAsWriter.mock.calls.length).toBe(1);
    expect([...document._hashes]).toEqual(hashes);
    expect(document._lastSyncMessage).toBe(tree);
    expect(document._recentTips).toEqual(tips);
    expect(published).toHaveLength(1);
    // No later change can depend on the unpublished edit.
    await expect(document.change(() => ({ small: 2 }))).rejects.toThrow(
      'retired after an oversized edit',
    );
    expect(document._closeDocument).toHaveBeenCalledTimes(1);
  },
);

test.each([
  ['large changes', 30, 200_000],
  ['small changes', CHANGE_TREE_COMPACTION_DEPTH + 8, 1],
])(
  'a writer whose %s keep failing to publish still bounds its retained tree',
  async (_name, count, size) => {
    const { document, published } = writerDocument('a');
    const undelivered: unknown[] = [];
    document.subscribeDeliveryFailures('probe', (failure: unknown) =>
      undelivered.push(failure),
    );
    const { publish } = document.swarm.heliaNode.libp2p.services.pubsub;
    publish.mockRejectedValue(
      new Error('PublishError.NoPeersSubscribedToTopic'),
    );
    for (let index = 0; index < count; index++)
      await document.change(() => ({ index, text: 'x'.repeat(size) }));
    expect(undelivered).toHaveLength(count);
    expect(document._latestSnapshot).toBeDefined();
    expect(
      changeTreeDepth(
        document._lastSyncMessage.changes,
        CHANGE_TREE_COMPACTION_DEPTH,
      ),
    ).toBeLessThan(CHANGE_TREE_COMPACTION_DEPTH);
    expect(document._closeDocument).not.toHaveBeenCalled();

    publish.mockImplementation(async (_topic: string, bytes: Uint8Array) => {
      published.push(bytes);
    });
    await document.change(() => ({ online: true }));
    expect(published).toHaveLength(1);
    expect(published[0].byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
      MAX_GOSSIP_SYNC_MESSAGE_BYTES,
    );
  },
);

test('a writer whose local handler throws on every change still bounds its retained tree', async () => {
  const { document, published } = writerDocument('a');
  Object.assign(document, {
    getReaders: async () => [],
    getWriters: async () => [],
    _localHandlers: {
      broken: () => {
        throw new Error('handler bug');
      },
    },
  });
  for (let index = 0; index < 30; index++)
    await expect(
      document.change(() => ({ index, text: 'x'.repeat(200_000) })),
    ).rejects.toThrow('handler bug');
  expect(published).toHaveLength(30);
  for (const frame of published)
    expect(frame.byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
      MAX_GOSSIP_SYNC_MESSAGE_BYTES,
    );
  expect(document._latestSnapshot).toBeDefined();
  expect(document._closeDocument).not.toHaveBeenCalled();
});

test('a frame that outgrows GossipSub because compaction is unavailable is rolled back, not wedged', async () => {
  const { document, published } = writerDocument('a');
  document._snapshotUnsupported = true;
  await document.change(() => ({ text: 'p'.repeat(1_500_000) }));
  await document.change(() => ({ text: 'q'.repeat(1_500_000) }));
  const hashes = [...document._hashes];
  const tree = document._lastSyncMessage;
  await expect(
    document.change(() => ({ text: 'r'.repeat(1_000_000) })),
  ).rejects.toBeInstanceOf(GossipFrameLimitError);
  expect([...document._hashes]).toEqual(hashes);
  expect(document._lastSyncMessage).toBe(tree);
  expect(published).toHaveLength(2);
  await expect(document.change(() => ({ small: 1 }))).rejects.toThrow(
    'retired after an oversized edit',
  );
});

test('a transaction too large for one frame never reaches history', async () => {
  const { document, published } = writerDocument('a');
  document._inTransaction = false;
  document._committing = false;
  document._pendingChangeFns = [];
  document.startChange();
  document.addChange((draft: Record<string, unknown>) => {
    draft.text = 'z'.repeat(MAX_CHANGE_FRAME_BYTES);
  });
  await expect(document.endChange()).rejects.toBeInstanceOf(
    GossipFrameLimitError,
  );
  expect(document._hashes.size).toBe(0);
  expect(document._lastSyncMessage).toBeUndefined();
  expect(published).toHaveLength(0);
  expect(document._closeDocument).toHaveBeenCalledTimes(1);
});

test('a membership change after a large edit compacts first and is published', async () => {
  const { document, published } = writerDocument('a');
  // An adopted tree that exceeds the frame budget, as from a peer that has
  // not yet compacted.
  document._compactionInProgress = true;
  await document.change(() => ({ text: 'p'.repeat(1_500_000) }));
  await document.change(() => ({ text: 'q'.repeat(1_500_000) }));
  document._compactionInProgress = false;
  const commit = jest.fn();
  await document._makeChange({ writers: ['next'] }, crdtWriterChangeNode, {
    operation: 'removeWriter',
    commit,
  });
  expect(commit).toHaveBeenCalledTimes(1);
  const frame = published.at(-1)!;
  expect(frame.byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
    MAX_GOSSIP_SYNC_MESSAGE_BYTES,
  );
  expect(decode(frame).changes!.kind).toBe(crdtWriterChangeNode);
  expect(document._latestSnapshot).toBeDefined();
});

test('a sync reply too large for GossipSub is reported instead of published', async () => {
  const { document, published } = writerDocument('a');
  document._lastSyncMessage = {
    documentId: '/gossip-frame',
    signatureContext: 'ordinary-sync-v1',
    changeId: 'cid-1',
    changes: { kind: crdtDocumentChangeNode, change: { small: true } },
  };
  document._latestSnapshot = {
    state: 's'.repeat(MAX_GOSSIP_SYNC_MESSAGE_BYTES),
    lastChangeNodeCID: 'cid-0',
    compactedCount: 1,
    signature: new Uint8Array([7]),
    timestamp: 1,
  };
  await document._handleSyncRequest(
    {
      documentId: '/gossip-frame',
      requester: 'reader',
      requesterPeer: '12D3KooWReader',
      requestId: '00'.repeat(16),
      issuedAtMs: Date.now(),
      knownSnapshots: [],
      knownTips: [],
      signature: 'AQ==',
    },
    () => true,
    '12D3KooWReader',
  );
  expect(published).toHaveLength(0);
  expect(warn).toHaveBeenCalledWith(
    'Sync response for /gossip-frame exceeds the GossipSub frame limit; the requester must load the document',
  );
  expect(document._syncRequestsSeen.size).toBe(0);
  expect(document._lastSyncResponseAt).toBe(0);
  expect(document._signAsWriter).not.toHaveBeenCalled();
});
