import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import { mergeCompactionConfig } from './compaction-config.js';
import {
  crdtDocumentChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import {
  GOSSIP_RETAINED_TREE_HIGH_BYTES,
  GossipFrameLimitError,
  MAX_DIRECT_SYNC_MESSAGE_BYTES,
  MAX_GOSSIP_SYNC_MESSAGE_BYTES,
} from './gossip-frame.js';
import { JSONSerializer } from './json-serializer.js';
import { loadResponseManifestHash } from './load-response-manifest.js';
import { PeerborneDocument } from './peerborne-document.js';
import { syncFrameV1 } from './wire-protocols.js';

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
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));
const peer = (id: string) => ({ toString: () => id });

interface DirectSend {
  peer: string;
  protocols: string[];
  payload: Uint8Array;
}

function writerDocument(
  options: { ack?: boolean; dial?: () => Promise<never> } = {},
) {
  const published: Uint8Array[] = [];
  const direct: DirectSend[] = [];
  const subscribers = [peer('member'), peer('relay')];
  let blocks = 0;
  const dialProtocol = jest.fn(
    async (target: { toString(): string }, protocols: string[]) => {
      if (options.dial) return options.dial();
      let payload: Uint8Array | undefined;
      return {
        send: (bytes: Uint8Array) => {
          payload = bytes;
          return true;
        },
        onDrain: async () => undefined,
        close: async () => {
          direct.push({
            peer: target.toString(),
            protocols,
            payload: payload!,
          });
        },
        abort: jest.fn(),
        async *[Symbol.asyncIterator]() {
          if (options.ack !== false) yield Uint8Array.of(1);
        },
      };
    },
  );
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/gossip-frame',
    _userPublicKey: 'writer',
    _userKey: 'writer-key',
    _encoder: new TextEncoder(),
    _bootstrapLoadApplicationState: 'pristine',
    _mutationQueue: new InvitationMembershipQueue(),
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _writers: { check: jest.fn(async () => true) },
    _verifySyncRequest: jest.fn(async () => true),
    _syncRequestsSeen: new Map(),
    _syncRequestClock: 0,
    _lastSyncResponseAt: 0,
    _lastPublishedBytes: 0,
    _subscribed: true,
    _hashes: new Set<string>(),
    _referencedAncestors: new Set<string>(),
    _recentTips: [],
    _putBlock: jest.fn(async () => `cid-${++blocks}`),
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
          dialProtocol,
          peerStore: {
            get: async (target: { toString(): string }) => ({
              protocols: target.toString() === 'relay' ? [] : [syncFrameV1],
            }),
          },
          services: {
            pubsub: {
              getSubscribers: () => subscribers,
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
    _compactionConfig: mergeCompactionConfig({}),
    _snapshotUnsupported: false,
    _compactionInProgress: false,
    _documentChangeCount: 0,
    _changesSinceSnapshot: 0,
    _gcLifecycle: {},
  }) as any;
  return { document, published, direct, dialProtocol };
}

const decode = (frame: Uint8Array) =>
  serializer.deserializeSyncMessage(frame.slice(KEY_AND_NONCE));

function decodeDirect(payload: Uint8Array) {
  const pathLength = new DataView(payload.buffer, payload.byteOffset).getUint32(
    0,
  );
  return {
    path: new TextDecoder().decode(payload.slice(4, 4 + pathLength)),
    message: decode(payload.slice(4 + pathLength)),
  };
}

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

const manifest = (changeId: string, changes: Node) =>
  loadResponseManifestHash({
    changeId,
    changes,
    serializeChange: (change: unknown) => serializer.serializeChanges(change),
  });

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

test('frames fit GossipSub with every payload inline, and receivers keep the author tree', async () => {
  const { document, published, direct } = writerDocument();
  for (let index = 0; index < 30; index++) {
    await document._makeChange(
      { index, text: 'x'.repeat(200_000) },
      crdtDocumentChangeNode,
    );
  }
  for (let index = 0; index < 2; index++)
    await document._makeChange({ small: index }, crdtDocumentChangeNode);
  expect(published).toHaveLength(32);
  expect(direct).toHaveLength(0);
  expect(document._latestSnapshot).toBeDefined();
  for (const frame of published) {
    expect(frame.byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
      GOSSIP_RETAINED_TREE_HIGH_BYTES + 300_000,
    );
    expect(payloadsSentByCid(decode(frame).changes!)).toBe(0);
  }
  // A receiver adopts the last frame's tree; it must hash like the author's.
  const received = decode(published.at(-1)!);
  expect(received.changeId).toBe(document._lastSyncMessage.changeId);
  await expect(
    manifest(received.changeId!, received.changes!),
  ).resolves.toEqual(
    await manifest(
      document._lastSyncMessage.changeId,
      document._lastSyncMessage.changes,
    ),
  );
});

test('a change too large for GossipSub goes inline, directly, to subscribers that accept sync frames', async () => {
  const { document, published, direct } = writerDocument();
  await document._makeChange({ small: true }, crdtDocumentChangeNode);
  const big = { text: 'y'.repeat(MAX_GOSSIP_SYNC_MESSAGE_BYTES) };
  await expect(
    document._makeChange(big, crdtDocumentChangeNode),
  ).resolves.toBeUndefined();
  await turn();
  expect(published).toHaveLength(1);
  expect(direct.map(({ peer }) => peer)).toEqual(['member']);
  expect(direct[0].protocols).toEqual([syncFrameV1]);
  const sent = decodeDirect(direct[0].payload);
  expect(sent.path).toBe('/gossip-frame');
  expect(sent.message.changeId).toBe('cid-2');
  expect(sent.message.changes!.change).toEqual(big);
  expect(payloadsSentByCid(sent.message.changes!)).toBe(0);
  expect(document._lastSyncMessage.changes.change).toEqual(big);

  // The next frame still carries the big change, then compaction drops it.
  await document._makeChange({ after: 1 }, crdtDocumentChangeNode);
  await document._makeChange({ after: 2 }, crdtDocumentChangeNode);
  await turn();
  expect(direct).toHaveLength(2);
  expect(published).toHaveLength(2);
  expect(decode(published[1]).changeId).toBe('cid-4');
});

test('a change too large for a direct frame is rejected', async () => {
  const { document, published, direct } = writerDocument();
  await expect(
    document._makeChange(
      { text: 'z'.repeat(MAX_DIRECT_SYNC_MESSAGE_BYTES) },
      crdtDocumentChangeNode,
    ),
  ).rejects.toBeInstanceOf(GossipFrameLimitError);
  await turn();
  expect(published).toHaveLength(0);
  expect(direct).toHaveLength(0);
});

function syncRequest(fields: Record<string, unknown> = {}) {
  return {
    documentId: '/gossip-frame',
    requester: 'reader',
    requestId: '00'.repeat(16),
    issuedAtMs: Date.now(),
    knownSnapshots: [],
    knownTips: [],
    peer: 'reader-peer',
    signature: 'AQ==',
    ...fields,
  };
}

function withSnapshot(document: any, stateBytes: number) {
  document._lastSyncMessage = {
    documentId: '/gossip-frame',
    signatureContext: 'ordinary-sync-v1',
    changeId: 'cid-1',
    changes: { kind: crdtDocumentChangeNode, change: { small: true } },
  };
  document._latestSnapshot = {
    state: 's'.repeat(stateBytes),
    lastChangeNodeCID: 'cid-0',
    compactedCount: 1,
    signature: new Uint8Array([7]),
    timestamp: 1,
  };
}

test('a catch-up response too large for GossipSub goes, acknowledged, to the peer that signed the request', async () => {
  const { document, published, direct } = writerDocument();
  withSnapshot(document, MAX_GOSSIP_SYNC_MESSAGE_BYTES);
  await document._handleSyncRequest(
    syncRequest(),
    () => true,
    peer('reader-peer'),
  );
  await turn();
  expect(published).toHaveLength(0);
  expect(direct.map(({ peer }) => peer)).toEqual(['reader-peer']);
  const response = decodeDirect(direct[0].payload).message;
  expect(response.changeId).toBe('cid-1');
  expect(response.snapshot?.lastChangeNodeCID).toBe('cid-0');
  expect(warn).not.toHaveBeenCalled();
});

test('a republished request is ignored without hiding the original, and direct replies are rate limited per peer', async () => {
  const { document, direct } = writerDocument();
  withSnapshot(document, MAX_GOSSIP_SYNC_MESSAGE_BYTES);
  await document._handleSyncRequest(
    syncRequest(),
    () => true,
    peer('someone-else'),
  );
  expect(document._syncRequestsSeen.size).toBe(0);
  await document._handleSyncRequest(
    syncRequest(),
    () => true,
    peer('reader-peer'),
  );
  document._lastSyncResponseAt = 0;
  await document._handleSyncRequest(
    syncRequest({ requestId: '01'.repeat(16) }),
    () => true,
    peer('reader-peer'),
  );
  await turn();
  expect(direct.map(({ peer }) => peer)).toEqual(['reader-peer']);
});

test('a catch-up response that cannot be delivered is reported', async () => {
  for (const [stateBytes, source] of [
    [MAX_GOSSIP_SYNC_MESSAGE_BYTES, undefined],
    [MAX_DIRECT_SYNC_MESSAGE_BYTES, peer('reader-peer')],
  ] as const) {
    const { document, published, direct } = writerDocument();
    withSnapshot(document, stateBytes);
    warn.mockClear();
    await document._handleSyncRequest(syncRequest(), () => true, source);
    await turn();
    expect(published).toHaveLength(0);
    expect(direct).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('the requester must load the document'),
    );
  }

  const unacknowledged = writerDocument({ ack: false });
  withSnapshot(unacknowledged.document, MAX_GOSSIP_SYNC_MESSAGE_BYTES);
  warn.mockClear();
  await unacknowledged.document._handleSyncRequest(
    syncRequest(),
    () => true,
    peer('reader-peer'),
  );
  for (let index = 0; index < 5; index++) await turn();
  expect(warn).toHaveBeenCalledWith(
    'Sync response for /gossip-frame was not acknowledged by a peer',
  );
});

test('direct frames in flight are bounded per document', async () => {
  const { document } = writerDocument({ dial: () => new Promise(() => {}) });
  const peers = Array.from({ length: 9 }, (_, index) => peer(`p${index}`));
  document._sendDirectSyncFrames(peers, new Uint8Array(10), 'Test frame');
  expect(warn).toHaveBeenCalledTimes(1);
  expect(warn).toHaveBeenCalledWith(
    'Test frame for /gossip-frame was not sent: too many direct frames in flight',
  );
  expect(document._directSendBudget.usage.operations).toBe(8);
});

test('a small catch-up response stays on GossipSub', async () => {
  const { document, published, direct } = writerDocument();
  withSnapshot(document, 1000);
  await document._handleSyncRequest(
    syncRequest(),
    () => true,
    peer('reader-peer'),
  );
  expect(published).toHaveLength(1);
  expect(direct).toHaveLength(0);
});

test('an unreachable block costs one bounded wait outside the state queue and is then backed off', async () => {
  const { document } = writerDocument();
  const reads: string[] = [];
  document._readBlock = jest.fn(
    (cid: { toString(): string }, options: { signal: AbortSignal }) => {
      reads.push(cid.toString());
      return new Promise((_, reject) => {
        if (options.signal.aborted) reject(options.signal.reason);
        options.signal.addEventListener(
          'abort',
          () => reject(options.signal.reason),
          { once: true },
        );
      });
    },
  );
  const children: Record<string, Node> = {};
  for (let index = 0; index < 40; index++)
    children[`missing-${index}`] = { kind: crdtDocumentChangeNode };
  const message = {
    documentId: '/gossip-frame',
    signatureContext: 'ordinary-sync-v1',
    changeId: 'root',
    changes: { kind: crdtDocumentChangeNode, change: { root: 1 }, children },
  };
  const started = Date.now();
  const prefetch = document._prefetchMissingBlocks(message);
  await expect(
    document._mutationQueue.run(async () => 'state queue is free'),
  ).resolves.toBe('state queue is free');
  const fetched = await prefetch;
  const elapsed = Date.now() - started;
  expect(fetched.size).toBe(0);
  expect(reads).toHaveLength(16);
  expect(elapsed).toBeGreaterThanOrEqual(9_000);
  expect(elapsed).toBeLessThan(15_000);

  const first = new Set(reads);
  reads.length = 0;
  document._readBlock = jest.fn(async (cid: { toString(): string }) => {
    reads.push(cid.toString());
    throw new Error('unreachable');
  });
  await document._prefetchMissingBlocks(message);
  expect(reads).toHaveLength(16);
  expect(reads.some((cid) => first.has(cid))).toBe(false);
}, 30_000);
