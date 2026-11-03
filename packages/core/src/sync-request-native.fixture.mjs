import assert from 'node:assert/strict';
import test from 'node:test';
import fc from 'fast-check';
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
  const work = { signatures: 0, verifications: 0, encryptions: 0 };
  const provider = Object.create(auth);
  provider.sign = (...args) => {
    work.signatures++;
    return auth.sign(...args);
  };
  provider.verify = (...args) => {
    work.verifications++;
    return auth.verify(...args);
  };
  provider.encrypt = (...args) => {
    work.encryptions++;
    return auth.encrypt(...args);
  };
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
    _authProvider: provider,
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
    _syncRequestClock: 0,
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
  return { document, published, message, work };
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

async function withClock(operation) {
  let now = 1_700_000_000_000;
  const original = Date.now;
  Date.now = () => now;
  try {
    await operation({
      get now() {
        return now;
      },
      set(value) {
        now = value;
      },
      advance(delta) {
        now += delta;
      },
    });
  } finally {
    Date.now = original;
  }
}

function pauseMethod(target, method) {
  const original = target[method];
  let entered, release;
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  target[method] = async function (...args) {
    entered();
    await gate;
    return original.apply(this, args);
  };
  return {
    started,
    release,
    restore() {
      target[method] = original;
    },
  };
}

test('generated response delays expire at verification, signing and ciphertext dispatch boundaries', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom('verify', 'sign', 'encrypt'),
      fc.integer({ min: 0, max: 60001 }),
      async (stage, delay) => {
        await withClock(async (clock) => {
          const { document, published, work } = harness();
          const signed = await request();
          const paused = pauseMethod(document._authProvider, stage);
          const response = document._handleSyncRequest(signed);
          await Promise.race([
            paused.started,
            response.then(() => {
              throw new Error('Expected cryptographic stage was not reached');
            }),
          ]);
          try {
            clock.advance(delay);
            paused.release();
            await response;
          } finally {
            paused.release();
            paused.restore();
          }
          assert.equal(published.length, delay <= 60000 ? 1 : 0);
          if (stage === 'verify' && delay > 60000)
            assert.equal(work.signatures, 0);
          assert.ok(document._syncRequestsSeen.size <= 128);
        });
      },
    ),
    {
      seed: 2011223,
      numRuns: 24,
      examples: [
        ['verify', 60001],
        ['sign', 60001],
        ['encrypt', 60001],
        ['encrypt', 60000],
      ],
    },
  );
});

test('authenticated no-op floods cannot displace a live replay record or spend response work', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 129, max: 150 }), async (count) => {
      await withClock(async (clock) => {
        const { document, published, work } = harness();
        const first = await request();
        await document._handleSyncRequest(first);
        const firstWork = { ...work };
        clock.advance(2000);
        for (let index = 0; index < count; index++) {
          const noop = await request(reader, {
            requestId: index.toString(16).padStart(32, '0'),
            knownTips: [root],
          });
          await document._handleSyncRequest(noop);
        }
        assert.equal(document._syncRequestsSeen.size, 1);
        assert.deepEqual(work, firstWork);
        clock.advance(2000);
        await document._handleSyncRequest(first);
        assert.equal(published.length, 1);
        assert.deepEqual(work, firstWork);
      });
    }),
    { seed: 2011224, numRuns: 3 },
  );
});

test('replay expiry remains terminal across wall-clock rollback and cache capacity fails closed', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 60001, max: 90000 }),
      fc.constantFrom(NaN, Infinity, -1, 'invalid'),
      async (jump, invalidClock) => {
        await withClock(async (clock) => {
          const { document, published, work } = harness();
          const start = clock.now;
          const first = await request();
          clock.set(invalidClock);
          await document._handleSyncRequest(first);
          assert.equal(published.length, 0);
          assert.equal(work.verifications, 0);
          clock.set(start);
          await document._handleSyncRequest(first);
          clock.advance(jump);
          const probe = await request(reader, {
            requestId: 'ff'.repeat(16),
            knownTips: [root],
          });
          assert.equal(await document._verifySyncRequest(probe), true);
          await document._handleSyncRequest(probe);
          assert.equal(published.length, 1);
          clock.set(start + 2000);
          await document._handleSyncRequest(first);
          assert.equal(published.length, 1);
          assert.equal(document._syncRequestClock, start + jump);
          clock.set(start + jump + 2000);
          const issued = clock.now;
          document._syncRequestsSeen = new Map(
            Array.from({ length: 128 }, (_, index) => [
              `seed-${index}`,
              issued,
            ]),
          );
          const before = [...document._syncRequestsSeen],
            spent = { ...work };
          await document._handleSyncRequest(
            await request(reader, { requestId: 'fe'.repeat(16) }),
          );
          assert.deepEqual([...document._syncRequestsSeen], before);
          assert.deepEqual(work, spent);
          assert.equal(published.length, 1);
        });
      },
    ),
    { seed: 2011225, numRuns: 6 },
  );
});

test('settled response preparation delays and failures reserve the cooldown', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom('success', 'sign', 'encrypt', 'publish'),
      fc.integer({ min: 2001, max: 10000 }),
      async (stage, delay) => {
        await withClock(async (clock) => {
          const { document, published, work } = harness();
          const pubsub = document.swarm.heliaNode.libp2p.services.pubsub;
          const target =
            stage === 'sign' || stage === 'encrypt'
              ? document._authProvider
              : pubsub;
          const method = stage === 'success' ? 'publish' : stage;
          const original = target[method];
          target[method] = async function (...args) {
            clock.advance(delay);
            if (stage !== 'success')
              throw new Error('Injected preparation failure');
            return original.apply(this, args);
          };
          const first = document._handleSyncRequest(await request());
          try {
            if (stage === 'success') await first;
            else await assert.rejects(first, /Injected preparation failure/);
          } finally {
            target[method] = original;
          }
          const settled = clock.now,
            spent = { ...work };
          await document._handleSyncRequest(
            await request(reader, { requestId: 'cc'.repeat(16) }),
          );
          assert.deepEqual(work, spent);
          assert.equal(document._lastSyncResponseAt, settled);
          clock.advance(2000);
          await document._handleSyncRequest(
            await request(reader, { requestId: 'dd'.repeat(16) }),
          );
          assert.equal(published.length, stage === 'success' ? 2 : 1);
        });
      },
    ),
    {
      seed: 2011226,
      numRuns: 12,
      examples: [
        ['sign', 2001],
        ['encrypt', 2001],
        ['publish', 2001],
        ['success', 2001],
      ],
    },
  );
});

test('dense future-dated signed response histories retain at most 46 live attempts', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 46, max: 64 }), async (count) => {
      await withClock(async (clock) => {
        const { document, published, work } = harness();
        for (let index = 0; index < count; index++) {
          const signed = await request(reader, {
            requestId: index.toString(16).padStart(32, '0'),
            issuedAtMs: clock.now + 30000,
          });
          await document._handleSyncRequest(signed);
          assert.equal(
            document._syncRequestsSeen.size,
            Math.min(index + 1, 46),
          );
          clock.advance(2000);
        }
        assert.equal(published.length, count);
        assert.equal(work.signatures, count);
        assert.equal(work.verifications, count);
      });
    }),
    { seed: 2011227, numRuns: 2, examples: [[46], [64]] },
  );
});

test('sync admission rejects nonboolean membership authorization results', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(
        false,
        0,
        undefined,
        'true',
        'false',
        {},
        new Boolean(false),
        new Boolean(true),
      ),
      async (authorization) => {
        await withClock(async () => {
          const { document, published, work } = harness();
          document._writers.check = async () => authorization;
          await document._handleSyncRequest(await request());
          assert.equal(published.length, 0);
          assert.equal(document._syncRequestsSeen.size, 0);
          assert.equal(work.signatures, 0);
          const requester = harness(reader);
          requester.document._writers.check = async () => authorization;
          requester.document._readers.check = async () => authorization;
          await assert.rejects(requester.document.requestSync());
          assert.equal(requester.published.length, 0);
          assert.equal(requester.work.signatures, 0);
        });
      },
    ),
    { seed: 2011228, numRuns: 30 },
  );
});
