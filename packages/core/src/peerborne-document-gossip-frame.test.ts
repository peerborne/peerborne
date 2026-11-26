import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import { mergeCompactionConfig } from './compaction-config.js';
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
import { loadResponseManifestHash } from './load-response-manifest.js';
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

const manifest = (changeId: string, changes: Node) =>
  loadResponseManifestHash({
    changeId,
    changes,
    serializeChange: (change: unknown) => serializer.serializeChanges(change),
  });

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

test('a writer that adopts each published tree prunes it exactly like its author', async () => {
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
  expect(receiver.document._lastSyncMessage.changeId).toBe(
    author.document._lastSyncMessage.changeId,
  );
  await expect(
    manifest(
      receiver.document._lastSyncMessage.changeId,
      receiver.document._lastSyncMessage.changes,
    ),
  ).resolves.toEqual(
    await manifest(
      author.document._lastSyncMessage.changeId,
      author.document._lastSyncMessage.changes,
    ),
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
    const error = await document
      .change(() => ({ text: 'z'.repeat(MAX_CHANGE_FRAME_BYTES) }))
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GossipFrameLimitError);
    expect((error as GossipFrameLimitError).limit).toBe(MAX_CHANGE_FRAME_BYTES);
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
      requestId: '00'.repeat(16),
      issuedAtMs: Date.now(),
      knownSnapshots: [],
      knownTips: [],
      signature: 'AQ==',
    },
    () => true,
  );
  expect(published).toHaveLength(0);
  expect(warn).toHaveBeenCalledWith(
    'Sync response for /gossip-frame exceeds the GossipSub frame limit; the requester must load the document',
  );
});
