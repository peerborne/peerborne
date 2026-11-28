import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import { PeerborneDocument } from './peerborne-document.js';
import { buildSnapshotSignaturePayload } from './snapshot-signature-payload.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: {
      Accept: 'accept',
      Ignore: 'ignore',
      Reject: 'reject',
    },
  }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

const auth = new SubtleCrypto();
let writer: CryptoKeyPair;

beforeAll(async () => {
  writer = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
});

let consoleSpies: Array<{ mockRestore(): void }>;
beforeEach(() => {
  consoleSpies = [
    jest.spyOn(console, 'warn').mockImplementation(() => undefined),
    jest.spyOn(console, 'error').mockImplementation(() => undefined),
    jest.spyOn(console, 'log').mockImplementation(() => undefined),
  ];
});
afterEach(() => {
  for (const spy of consoleSpies) spy.mockRestore();
});

const state = new Uint8Array([1, 2, 3]);
const snapshotFields = {
  lastChangeNodeCID: 'boundary-cid',
  compactedCount: 10,
  timestamp: 1,
};

async function signSnapshotFor(documentPath: string) {
  return {
    ...snapshotFields,
    state,
    signature: await auth.sign(
      buildSnapshotSignaturePayload(
        documentPath,
        state,
        snapshotFields.lastChangeNodeCID,
        snapshotFields.timestamp,
        snapshotFields.compactedCount,
      ),
      writer.privateKey,
    ),
  };
}

function receivingDocument(documentPath: string): any {
  const hashes = new Set<string>();
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    _hashes: hashes,
    _latestSnapshot: undefined,
    _documentChangeCount: 0,
    _fireOrDeferRemoteUpdateHandlers: jest.fn(async () => undefined),
    _isSigningEnabled: () => true,
    _getWriterKeys: async () => [writer.publicKey],
    _authProvider: auth,
    _changesSerializer: { serializeChanges: (value: Uint8Array) => value },
    _crdtProvider: { remoteChange: (_doc: unknown, next: unknown) => next },
    _collectACLFromTree: () => ({ aclEntries: [], changes: [] }),
    _applyCollectedACL: () => undefined,
    _syncDocumentChanges: async () => {
      hashes.add('head-cid');
    },
  });
}

async function deliver(documentPath: string, signedFor: string) {
  const document = receivingDocument(documentPath);
  const message = {
    documentId: documentPath,
    signatureContext: 'load-response-v4',
    signature: 'AQ==',
    changeId: 'head-cid',
    changes: {
      kind: crdtDocumentChangeNode,
      children: { 'boundary-cid': { kind: crdtDocumentChangeNode } },
    },
    snapshot: await signSnapshotFor(signedFor),
  } as any;
  await expect(
    document._syncValidatedProtocolMessage(message, 'load-response-v4'),
  ).resolves.toBe(true);
  return document;
}

describe('snapshot signatures bind the document path', () => {
  test('a writer snapshot applies to the document it was signed for', async () => {
    const document = await deliver('/docs/a', '/docs/a');
    expect(document._latestSnapshot?.lastChangeNodeCID).toBe('boundary-cid');
  });

  test('the same writer snapshot is rejected by another document', async () => {
    const document = await deliver('/docs/b', '/docs/a');
    expect(document._latestSnapshot).toBeUndefined();
    expect(console.warn).toHaveBeenCalledWith(
      'Rejected snapshot for /docs/b: no authorized writer produced a valid signature',
    );
  });

  test('the document payload builder uses its own path', async () => {
    const snapshot = await signSnapshotFor('/docs/a');
    const verify = async (documentPath: string) =>
      auth.verify(
        receivingDocument(documentPath)._buildSnapshotSignPayload(
          state,
          snapshot.lastChangeNodeCID,
          snapshot.timestamp,
          snapshot.compactedCount,
        ),
        writer.publicKey,
        snapshot.signature,
      );
    await expect(verify('/docs/a')).resolves.toBe(true);
    await expect(verify('/docs/b')).resolves.toBe(false);
  });
});
