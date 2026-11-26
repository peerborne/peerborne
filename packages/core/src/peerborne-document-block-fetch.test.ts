import { afterEach, describe, expect, jest, test } from '@jest/globals';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { PeerborneDocument } from './peerborne-document.js';
import { RemoteBlockFetches } from './remote-block-fetch.js';

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

const block = new Uint8Array([7]);

// Bitswap's wantBlock settles only when the block arrives or the read aborts.
function wantBlock(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason), {
      once: true,
    });
  });
}

// An inline change that cross-links one block it does not carry.
function tree(change: string, deferred: string) {
  return {
    kind: crdtDocumentChangeNode,
    change: [change],
    children: {
      KNOWN: { kind: crdtDocumentChangeNode },
      [deferred]: { kind: crdtDocumentChangeNode },
    },
  };
}

function fakeDocument(fields: Record<string, unknown> = {}): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/block-fetch',
    swarm: { config: {}, unregisterDocument: jest.fn() },
    _mutationQueue: new InvitationMembershipQueue(),
    _hashes: new Set<string>(['KNOWN']),
    _referencedAncestors: new Set<string>(),
    _recentTips: [],
    _documentChangeCount: 0,
    _changesSinceSnapshot: 0,
    _document: [] as string[],
    _crdtProvider: {
      remoteChange: (document: string[], changes: string[]) => [
        ...document,
        ...changes,
      ],
    },
    _fireOrDeferRemoteUpdateHandlers: jest.fn(async () => undefined),
    _refreshLastSyncMessageFromSync: jest.fn(),
    _maybeCompact: jest.fn(async () => undefined),
    _remoteBlockFetches: new RemoteBlockFetches({ deadlineMs: 20 }),
    ...fields,
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200 && !predicate(); attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  expect(predicate()).toBe(true);
}

afterEach(() => {
  jest.restoreAllMocks();
});

async function boundedSync(document: any, root: string, changes: unknown) {
  const remoteFetches = document._blockFetches().begin();
  try {
    await document._syncDocumentChanges(root, changes, { remoteFetches });
  } finally {
    remoteFetches.end();
  }
}

describe('an ordinary sync citing a block that no reachable peer holds', () => {
  test('applies its inline changes once the fetch deadline passes and skips the block while it backs off', async () => {
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    const document = fakeDocument({
      _getBlock: jest.fn((_cid: unknown, options: any) =>
        wantBlock(options.signal),
      ),
    });

    await boundedSync(document, 'ROOT', tree('inline', 'MISSING'));
    expect(document._document).toEqual(['inline']);
    expect(document._hashes.has('ROOT')).toBe(true);
    expect(document._hashes.has('MISSING')).toBe(false);
    expect(document._getBlock).toHaveBeenCalledTimes(1);
    expect(error).toHaveBeenCalledWith(
      'Failed to fetch missing change from blockstore:',
      'MISSING',
    );

    await boundedSync(document, 'NEXT', tree('next', 'MISSING'));
    expect(document._getBlock).toHaveBeenCalledTimes(1);
    expect(document._document).toEqual(['inline', 'next']);
    expect(document._hashes.has('NEXT')).toBe(true);
  });

  test('reports a block that fails or waits out its retry delay to catch-up', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const missingChange = jest.fn();
    const document = fakeDocument({
      _antiEntropy: { missingChange, remoteStateApplied: jest.fn() },
      _getBlock: jest.fn((_cid: unknown, options: any) =>
        wantBlock(options.signal),
      ),
    });
    await boundedSync(document, 'ROOT', tree('inline', 'MISSING'));
    expect(missingChange).toHaveBeenCalledWith('MISSING');
    await boundedSync(document, 'NEXT', tree('next', 'MISSING'));
    expect(document._getBlock).toHaveBeenCalledTimes(1);
    expect(missingChange).toHaveBeenCalledTimes(2);
  });

  test('close() aborts the fetch promptly without backing the block off', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    let started!: () => void;
    const fetching = new Promise<void>((resolve) => {
      started = resolve;
    });
    const fetches = new RemoteBlockFetches();
    const document = fakeDocument({
      _remoteBlockFetches: fetches,
      _getBlock: jest.fn((_cid: unknown, options: any) => {
        started();
        return wantBlock(options.signal);
      }),
    });

    const syncing = boundedSync(document, 'ROOT', tree('inline', 'MISSING'));
    await fetching;
    await document.close();
    await expect(syncing).resolves.toBeUndefined();
    expect(document._hashes.has('ROOT')).toBe(true);
    expect(fetches.isBackedOff('MISSING')).toBe(false);
  });
});

describe('a load or invitation sync citing blocks', () => {
  test('fetches every block, under its own deadline rather than the ordinary bounds', async () => {
    const deferred = Array.from({ length: 10 }, (_value, index) => `D${index}`);
    const document = fakeDocument({
      _getBlock: jest.fn(async (cid: { toString(): string }) => [
        cid.toString(),
      ]),
    });

    await document._syncDocumentChanges(
      'ROOT',
      {
        kind: crdtDocumentChangeNode,
        change: ['inline'],
        children: Object.fromEntries(
          deferred.map((cid) => [cid, { kind: crdtDocumentChangeNode }]),
        ),
      },
      { signal: new AbortController().signal },
    );
    expect(document._getBlock).toHaveBeenCalledTimes(10);
    expect([...document._document].sort()).toEqual(
      ['inline', ...deferred].sort(),
    );
    for (const cid of deferred) expect(document._hashes.has(cid)).toBe(true);
  });
});

describe('a GossipSub frame citing a block this replica lacks', () => {
  const message = {
    documentId: '/block-fetch',
    signatureContext: 'ordinary-sync-v1',
    changeId: 'ROOT',
    changes: tree('inline', 'MISSING'),
    signature: 'AQ==',
  };

  test('fetches nothing when its writer signature does not verify', async () => {
    const document = fakeDocument({
      _verifyOrdinarySyncSignature: jest.fn(async () => false),
      _readBlock: jest.fn(async () => block),
      _syncUnlocked: jest.fn(async () => true),
    });

    await document._syncGossipMessage(message, () => true);
    expect(document._verifyOrdinarySyncSignature).toHaveBeenCalledTimes(1);
    expect(document._readBlock).not.toHaveBeenCalled();
    expect(document._syncUnlocked).not.toHaveBeenCalled();
  });

  test('fetches the block outside the state queue once the signature verifies', async () => {
    let deliver!: (value: Uint8Array) => void;
    const document = fakeDocument({
      _remoteBlockFetches: new RemoteBlockFetches(),
      _verifyOrdinarySyncSignature: jest.fn(async () => true),
      _readBlock: jest.fn(
        () =>
          new Promise<Uint8Array>((resolve) => {
            deliver = resolve;
          }),
      ),
      _syncUnlocked: jest.fn(async () => true),
    });

    const receiving = document._syncGossipMessage(message, () => true);
    await waitFor(() => document._readBlock.mock.calls.length === 1);
    expect(document._readBlock.mock.calls[0][0].toString()).toBe('MISSING');
    await expect(
      document._runStateMutation(async () => 'unblocked'),
    ).resolves.toBe('unblocked');
    expect(document._syncUnlocked).not.toHaveBeenCalled();

    deliver(block);
    await receiving;
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
    const options = document._syncUnlocked.mock.calls[0][5];
    expect([...options.prefetchedBlocks]).toEqual([['MISSING', block]]);
    expect(options.remoteFetches.signal.aborted).toBe(true);
  });

  test('skips the fetch when every cited block is already known', async () => {
    const document = fakeDocument({
      _verifyOrdinarySyncSignature: jest.fn(async () => true),
      _readBlock: jest.fn(async () => block),
      _syncUnlocked: jest.fn(async () => true),
    });
    document._hashes.add('MISSING');

    await document._syncGossipMessage(message, () => true, 123);
    expect(document._verifyOrdinarySyncSignature).not.toHaveBeenCalled();
    expect(document._readBlock).not.toHaveBeenCalled();
    const options = document._syncUnlocked.mock.calls[0][5];
    expect(options.prefetchedBlocks).toBe(undefined);
    expect(options.frameBytes).toBe(123);
  });
});
