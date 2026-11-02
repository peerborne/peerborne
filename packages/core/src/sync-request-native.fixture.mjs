import assert from 'node:assert/strict';
import test from 'node:test';
import { Base64 } from 'js-base64';
import { PeerborneDocument } from './peerborne-document.ts';
import { SubtleCrypto } from './auth-subtlecrypto.ts';
import { JSONSerializer } from './json-serializer.ts';
import {
  decodeSyncRequest,
  encodeSyncRequest,
  isSyncRequest,
  isSyncRequestFresh,
  syncRequestSigningPayload,
  syncSnapshotHint,
  MAX_SYNC_REQUEST_BYTES,
} from './sync-request.ts';

const auth = new SubtleCrypto();
const serializer = new JSONSerializer();
const [writer, reader, stranger] = await Promise.all(
  Array.from({ length: 3 }, () =>
    crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
      'sign',
      'verify',
    ]),
  ),
);
const encryptionKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt'],
);
const keyId = new Uint8Array(16).fill(1);
const root = 'bafkreigh2akiscaildc5uxiaeu4we7ubxqnv6tyc3bv7heor3weuztdf5y';
const otherRoot = 'bafkqaaa';

function harness(identity = writer) {
  const published = [];
  const message = {
    documentId: '/resume',
    signatureContext: 'ordinary-sync-v1',
    changeId: root,
    changes: { kind: 'document', change: { body: 'synthetic fixture' } },
  };
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/resume',
    _userKey: identity.privateKey,
    _userPublicKey: identity.publicKey,
    _authProvider: auth,
    _syncMessageSerializer: serializer,
    _runStateMutation: async (operation) => operation(),
    _subscribed: true,
    _lastSyncMessage: message,
    _recentTips: [],
    _topic: 'fixture',
    _lastSyncRequestAt: 0,
    _knownSyncSnapshots: new Set(),
    _lastSyncResponseAt: 0,
    _syncRequestsSeen: new Map(),
    _writers: {
      users: async () => [writer.publicKey],
      check: async (key) => key === writer.publicKey,
    },
    _readers: {
      users: async () => [reader.publicKey],
      check: async (key) => key === reader.publicKey,
    },
    _keychain: { current: async () => [keyId, encryptionKey] },
    swarm: {
      config: { enableSigning: true },
      heliaNode: {
        libp2p: {
          services: {
            pubsub: {
              publish: async (_topic, bytes) => {
                published.push(bytes);
              },
            },
          },
        },
      },
    },
  });
  return { document, published, message };
}

async function plaintext(bytes) {
  return auth.decrypt(
    bytes.subarray(keyId.length + auth.nonceBytes),
    encryptionKey,
    bytes.subarray(keyId.length, keyId.length + auth.nonceBytes),
  );
}

async function request(identity = reader, overrides = {}) {
  const unsigned = {
    documentId: '/resume',
    requester: await auth.serializePublicKey(identity.publicKey),
    requestId: '12'.repeat(16),
    issuedAtMs: Date.now(),
    knownTips: [otherRoot],
    knownSnapshots: [],
    ...overrides,
  };
  return {
    ...unsigned,
    signature: Base64.fromUint8Array(
      await auth.sign(syncRequestSigningPayload(unsigned), identity.privateKey),
    ),
  };
}

test('a current reader requests updates using a signed, encrypted, detached frame', async () => {
  const { document, published } = harness(reader);
  await document.requestSync();
  assert.equal(published.length, 1);
  const decoded = decodeSyncRequest(await plaintext(published[0]));
  assert.equal(
    decoded.requester,
    await auth.serializePublicKey(reader.publicKey),
  );
  assert.deepEqual(decoded.knownTips, [root]);
  assert.equal(Object.isFrozen(decoded), true);
  assert.equal(Object.isFrozen(decoded.knownTips), true);
  assert.equal(
    await auth.verify(
      syncRequestSigningPayload(decoded),
      reader.publicKey,
      Base64.toUint8Array(decoded.signature),
    ),
    true,
  );
  await document.requestSync();
  assert.equal(published.length, 1);
});

test('a writer answers with the existing ordinary signed update without creating a change', async () => {
  const { document, published, message } = harness();
  await document._handleSyncRequest(await request());
  assert.equal(published.length, 1);
  assert.equal(document._lastSyncMessage, message);
  const decoded = serializer.deserializeSyncMessage(
    await plaintext(published[0]),
  );
  assert.equal(decoded.signatureContext, 'ordinary-sync-v1');
  assert.equal(decoded.changeId, root);
  const { signature, ...unsigned } = decoded;
  assert.equal(
    await auth.verify(
      serializer.serializeSyncMessage(unsigned),
      writer.publicKey,
      Base64.toUint8Array(signature),
    ),
    true,
  );
});

test('replays, requests for a known root, and bursts do not amplify responses', async () => {
  const { document, published } = harness();
  const first = await request();
  await document._handleSyncRequest(first);
  document._lastSyncResponseAt = Date.now() - 3000;
  await document._handleSyncRequest(first);
  assert.equal(published.length, 1);
  await document._handleSyncRequest(
    await request(reader, { requestId: '13'.repeat(16), knownTips: [root] }),
  );
  assert.equal(published.length, 1);
  document._lastSyncResponseAt = Date.now();
  await document._handleSyncRequest(
    await request(reader, { requestId: '14'.repeat(16) }),
  );
  assert.equal(published.length, 1);
});

test('a known root does not suppress a missing snapshot, while known snapshots are omitted', async () => {
  const { document, published } = harness();
  document._latestSnapshot = {
    state: new Uint8Array([5]),
    signature: new Uint8Array([6]),
    lastChangeNodeCID: root,
    compactedCount: 1,
    timestamp: 1,
  };
  await document._handleSyncRequest(
    await request(reader, { knownTips: [root] }),
  );
  assert.equal(published.length, 1);
  const first = serializer.deserializeSyncMessage(
    await plaintext(published[0]),
  );
  assert.ok(first.snapshot);
  const hint = await syncSnapshotHint(document._latestSnapshot.signature);
  document._lastSyncResponseAt = 0;
  await document._handleSyncRequest(
    await request(reader, {
      requestId: '31'.repeat(16),
      knownTips: [root],
      knownSnapshots: [hint],
    }),
  );
  assert.equal(published.length, 1);
  await document._handleSyncRequest(
    await request(reader, {
      requestId: '32'.repeat(16),
      knownSnapshots: [hint],
    }),
  );
  assert.equal(published.length, 2);
  assert.equal(
    serializer.deserializeSyncMessage(await plaintext(published[1])).snapshot,
    undefined,
  );
});

test('unknown members, forged signatures, cross-document requests and stale requests are rejected', async () => {
  const { document, published } = harness();
  const valid = await request();
  for (const candidate of [
    await request(stranger),
    { ...valid, knownTips: [root] },
    await request(reader, { documentId: '/other' }),
    await request(reader, { issuedAtMs: Date.now() - 61_000 }),
    await request(reader, { issuedAtMs: Date.now() + 31_000 }),
  ])
    await document._handleSyncRequest(candidate);
  assert.equal(published.length, 0);
  assert.equal(document._syncRequestsSeen.size, 0);
});

test('reader-only replicas never issue writer responses, and closed or unsigned replicas do not request', async () => {
  const readOnly = harness(reader);
  await readOnly.document._handleSyncRequest(await request(writer));
  assert.equal(readOnly.published.length, 0);
  for (const mutate of [
    (document) => {
      document._subscribed = false;
    },
    (document) => {
      document.swarm.config.enableSigning = false;
    },
    (document) => {
      document._readers.check = async () => false;
    },
  ]) {
    const { document, published } = harness(reader);
    mutate(document);
    await assert.rejects(document.requestSync());
    assert.equal(published.length, 0);
  }
});

test('request replay memory remains bounded under authenticated input', async () => {
  const { document, published } = harness();
  for (let i = 0; i < 140; i++) {
    await document._handleSyncRequest(
      await request(reader, {
        requestId: i.toString(16).padStart(32, '0'),
        knownTips: [root],
      }),
    );
  }
  assert.equal(document._syncRequestsSeen.size, 128);
  assert.equal(published.length, 0);
});

test('the codec rejects malformed framing and binds every request field to its own domain', async () => {
  const valid = await request();
  const wire = encodeSyncRequest(valid);
  assert.deepEqual(decodeSyncRequest(wire), valid);
  assert.equal(isSyncRequest(new TextEncoder().encode('{}')), false);
  assert.equal(decodeSyncRequest(wire.subarray(0, wire.length - 1)), undefined);
  const oversized = new Uint8Array(MAX_SYNC_REQUEST_BYTES + 1);
  oversized.set(wire);
  assert.equal(decodeSyncRequest(oversized), undefined);
  for (const change of [
    { knownTips: [root, root] },
    { knownTips: ['invalid'] },
    { requestId: 'bad' },
    { issuedAtMs: NaN },
    { issuedAtMs: -1 },
    { signature: 'not base64!' },
    { knownSnapshots: ['invalid'] },
    { knownSnapshots: ['ab'.repeat(32), 'ab'.repeat(32)] },
  ])
    assert.throws(() => encodeSyncRequest({ ...valid, ...change }));
  for (const change of [
    { documentId: '/other' },
    { requester: 'other' },
    { requestId: 'ab'.repeat(16) },
    { issuedAtMs: valid.issuedAtMs + 1 },
    { knownTips: [root] },
    { knownSnapshots: ['ab'.repeat(32)] },
  ])
    assert.equal(
      await auth.verify(
        syncRequestSigningPayload({ ...valid, ...change }),
        reader.publicKey,
        Base64.toUint8Array(valid.signature),
      ),
      false,
    );
  assert.equal(isSyncRequestFresh(valid, valid.issuedAtMs + 60_000), true);
  assert.equal(isSyncRequestFresh(valid, valid.issuedAtMs + 60_001), false);
  assert.equal(isSyncRequestFresh(valid, valid.issuedAtMs - 30_000), true);
  assert.equal(isSyncRequestFresh(valid, valid.issuedAtMs - 30_001), false);
});
