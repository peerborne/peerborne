import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import {
  changeTreeDepth,
  CHANGE_TREE_COMPACTION_KEEP,
  MAX_CHANGE_TREE_DEPTH,
} from './change-tree-walk.js';
import { mergeCompactionConfig } from './compaction-config.js';
import {
  crdtDocumentChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import {
  MAX_DIRECT_SYNC_MESSAGE_BYTES,
  MAX_GOSSIP_SYNC_MESSAGE_BYTES,
} from './gossip-frame.js';
import { JSONSerializer } from './json-serializer.js';
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

function writerDocument() {
  const published: Uint8Array[] = [];
  const direct: { peer: unknown; protocols: string[]; payload: Uint8Array }[] =
    [];
  let blocks = 0;
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
          dialProtocol: jest.fn(async (peer: unknown, protocols: string[]) => ({
            send: (payload: Uint8Array) => {
              direct.push({ peer, protocols, payload });
              return true;
            },
            onDrain: async () => undefined,
            close: async () => undefined,
            abort: () => undefined,
          })),
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
    _compactionConfig: mergeCompactionConfig({}),
    _snapshotUnsupported: false,
    _compactionInProgress: false,
    _documentChangeCount: 0,
    _changesSinceSnapshot: 0,
    _gcLifecycle: {},
  }) as any;
  return { document, published, direct };
}

const decode = (frame: Uint8Array) =>
  serializer.deserializeSyncMessage(frame.slice(KEY_AND_NONCE));

function inlineIds(root: Node, rootId: string): Set<string> {
  const ids = new Set<string>();
  const pending: [string, Node][] = [[rootId, root]];
  while (pending.length > 0) {
    const [id, node] = pending.pop()!;
    if (node.change !== undefined) ids.add(id);
    if (node.children) pending.push(...Object.entries(node.children));
  }
  return ids;
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

test('every published frame fits GossipSub while the retained history keeps its payloads', async () => {
  const { document, published } = writerDocument();
  const edits = 30;
  for (let index = 0; index < edits; index++) {
    await document._makeChange(
      { index, text: 'x'.repeat(200_000) },
      crdtDocumentChangeNode,
    );
  }
  expect(published).toHaveLength(edits);
  for (const frame of published) {
    expect(frame.byteLength - KEY_AND_NONCE).toBeLessThanOrEqual(
      MAX_GOSSIP_SYNC_MESSAGE_BYTES,
    );
  }
  const last = decode(published.at(-1)!);
  expect(last.changeId).toBe(`cid-${edits}`);
  const sent = inlineIds(last.changes!, last.changeId!);
  expect(sent.has(`cid-${edits}`)).toBe(true);
  expect(sent.has('cid-1')).toBe(false);
  expect(sent.size).toBeGreaterThan(10);
  expect(
    inlineIds(document._lastSyncMessage.changes, `cid-${edits}`).size,
  ).toBe(edits);
});

test('a change larger than a GossipSub frame is published by CID and still committed', async () => {
  const { document, published } = writerDocument();
  await document._makeChange({ small: true }, crdtDocumentChangeNode);
  await expect(
    document._makeChange(
      { text: 'y'.repeat(MAX_GOSSIP_SYNC_MESSAGE_BYTES) },
      crdtDocumentChangeNode,
    ),
  ).resolves.toBeUndefined();
  const frame = decode(published.at(-1)!);
  expect(frame.changeId).toBe('cid-2');
  expect(frame.changes!.change).toBeUndefined();
  expect(Object.keys(frame.changes!.children as object)).toEqual(['cid-1']);
  expect(published.at(-1)!.byteLength).toBeLessThan(1024);
  expect(document._lastSyncMessage.changes.change).toEqual({
    text: 'y'.repeat(MAX_GOSSIP_SYNC_MESSAGE_BYTES),
  });
});

test('a writer bounds the depth of an adopted tree whose payloads were sent by CID', async () => {
  const { document } = writerDocument();
  let changeId = 'remote-0';
  let changes: Node = { kind: crdtDocumentChangeNode, change: { remote: 0 } };
  for (let level = 1; level < MAX_CHANGE_TREE_DEPTH - 1; level++) {
    const parent = changeId;
    changeId = `remote-${level}`;
    changes = {
      kind: crdtDocumentChangeNode,
      ...(level > MAX_CHANGE_TREE_DEPTH - 10
        ? { change: { remote: level } }
        : {}),
      children: { [parent]: changes },
    };
  }
  document._refreshLastSyncMessageFromSync(changeId, changes);
  await document._maybeCompact();
  expect(
    changeTreeDepth(document._lastSyncMessage.changes),
  ).toBeLessThanOrEqual(CHANGE_TREE_COMPACTION_KEEP + 1);
});

function syncRequest() {
  return {
    documentId: '/gossip-frame',
    requester: 'reader',
    requestId: '00'.repeat(16),
    issuedAtMs: Date.now(),
    knownSnapshots: [],
    knownTips: [],
    signature: 'AQ==',
  };
}

function withLargeSnapshot(document: any, stateBytes: number) {
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

test('a catch-up response too large for GossipSub is sent to the requesting peer', async () => {
  const { document, published, direct } = writerDocument();
  withLargeSnapshot(document, MAX_GOSSIP_SYNC_MESSAGE_BYTES);
  const peer = { toString: () => 'requester-peer' };
  await document._handleSyncRequest(syncRequest(), () => true, peer);
  expect(published).toHaveLength(0);
  expect(direct).toHaveLength(1);
  expect(direct[0].peer).toBe(peer);
  expect(direct[0].protocols).toEqual([syncFrameV1]);
  const payload = direct[0].payload;
  const pathLength = new DataView(payload.buffer, payload.byteOffset).getUint32(
    0,
  );
  expect(new TextDecoder().decode(payload.slice(4, 4 + pathLength))).toBe(
    '/gossip-frame',
  );
  const response = decode(payload.slice(4 + pathLength));
  expect(response.changeId).toBe('cid-1');
  expect(response.snapshot?.lastChangeNodeCID).toBe('cid-0');
});

test('a catch-up response is reported, not sent, when it cannot reach the requester', async () => {
  for (const [stateBytes, peer] of [
    [MAX_GOSSIP_SYNC_MESSAGE_BYTES, undefined],
    [MAX_DIRECT_SYNC_MESSAGE_BYTES, { toString: () => 'requester-peer' }],
  ] as const) {
    const { document, published, direct } = writerDocument();
    withLargeSnapshot(document, stateBytes);
    warn.mockClear();
    await document._handleSyncRequest(syncRequest(), () => true, peer);
    expect(published).toHaveLength(0);
    expect(direct).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('the requester must load the document'),
    );
  }
});

test('a small catch-up response stays on GossipSub', async () => {
  const { document, published, direct } = writerDocument();
  withLargeSnapshot(document, 1000);
  await document._handleSyncRequest(syncRequest(), () => true, {
    toString: () => 'requester-peer',
  });
  expect(published).toHaveLength(1);
  expect(direct).toHaveLength(0);
});

test('a block request with no answer is retried a bounded number of times', async () => {
  const { document } = writerDocument();
  const calls: AbortSignal[] = [];
  const stalled = (signal: AbortSignal) =>
    new Promise<never>((_, reject) => {
      if (signal.aborted) reject(signal.reason);
      signal.addEventListener('abort', () => reject(signal.reason), {
        once: true,
      });
    });
  const bound = { timeoutMs: 20, attempts: 3 };
  const attempt = (options: object = {}) =>
    document._getBlockWithAttempts('cid', options, undefined, bound);

  document._getBlock = jest.fn(async (_cid: unknown, options: any) => {
    calls.push(options.signal);
    if (calls.length < 3) return stalled(options.signal);
    return { fetched: true };
  });
  await expect(attempt()).resolves.toEqual({ fetched: true });
  expect(calls).toHaveLength(3);

  calls.length = 0;
  document._getBlock = jest.fn(async (_cid: unknown, options: any) => {
    calls.push(options.signal);
    return stalled(options.signal);
  });
  await expect(attempt()).rejects.toBeDefined();
  expect(calls).toHaveLength(3);

  calls.length = 0;
  const caller = new AbortController();
  caller.abort(new Error('caller cancelled'));
  await expect(attempt({ signal: caller.signal })).rejects.toThrow(
    'caller cancelled',
  );
  expect(calls).toHaveLength(1);

  calls.length = 0;
  document._getBlock = jest.fn(async (_cid: unknown, options: any) => {
    calls.push(options.signal);
    throw new Error('corrupt block');
  });
  await expect(attempt()).rejects.toThrow('corrupt block');
  expect(calls).toHaveLength(1);
});
