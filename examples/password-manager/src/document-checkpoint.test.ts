import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import {
  PeerborneDocument,
  SubtleCrypto,
  generateEciesKeyPair,
  deserializeBeeKEMWelcomeV2FromWire,
} from '@peerborne/core';
import {
  YjsProvider,
  YjsACLProvider,
  YjsKeychainProvider,
  YjsJSONSerializer,
} from '@peerborne/yjs';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});

async function fixture() {
  const signing = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const kem = await generateEciesKeyPair();
  const blocks = new MemoryBlockstore();
  function document(path = '/checkpoint-fixture', identity = signing) {
    const serializer = new YjsJSONSerializer();
    const registry = new Map();
    const swarm = {
      config: { enableSigning: true, enableTopicValidators: false },
      heliaNode: {
        blockstore: blocks,
        libp2p: {
          services: {
            pubsub: {
              addEventListener() {},
              removeEventListener() {},
              subscribe() {},
              unsubscribe() {},
              async publish() {},
            },
          },
          getConnections: () => [],
        },
      },
      registerDocument(path: string, doc: unknown) {
        if (registry.has(path)) throw new Error('Already registered');
        registry.set(path, doc);
      },
      unregisterDocument(path: string, doc: unknown) {
        if (registry.get(path) === doc) registry.delete(path);
      },
    };
    return new PeerborneDocument(
      swarm as never,
      path,
      identity.privateKey,
      identity.publicKey,
      new YjsProvider(),
      new SubtleCrypto(),
      new YjsACLProvider(),
      new YjsKeychainProvider(),
      serializer,
      serializer,
      serializer,
    );
  }
  const created = document();
  await created.setKemKeyPair(kem);
  await created.create();
  await created.change((doc) => {
    doc.getText('fixture').insert(0, 'before restart');
  });
  return { document, created, signing, kem };
}

test('restores authenticated Yjs state, keys, history, and writer access before opening', async () => {
  const { document, created, kem } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(checkpoint);
  assert.equal(
    restored.document.getText('fixture').toString(),
    'before restart',
  );
  assert.equal(restored.historySize(), created.historySize());
  assert.equal((await restored.getWriters()).length, 1);
  await restored.open();
  await restored.change((doc) => {
    doc.getText('fixture').insert(doc.getText('fixture').length, ' and after');
  });
  assert.equal(
    restored.document.getText('fixture').toString(),
    'before restart and after',
  );
  await assert.rejects(
    restored.restoreCheckpoint(checkpoint),
    /fresh document/,
  );
});

test('rejects tampering, another identity, and another document before installing state', async () => {
  const { document, created } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const damaged = {
    payload: new Uint8Array(checkpoint.payload),
    signature: checkpoint.signature,
  };
  damaged.payload[damaged.payload.length - 1] ^= 1;
  const candidate = document();
  await assert.rejects(
    candidate.restoreCheckpoint(damaged),
    /authentication failed/,
  );
  assert.equal(candidate.historySize(), 0);
  const other = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  await assert.rejects(
    document(undefined, other).restoreCheckpoint(checkpoint),
    /authentication failed/,
  );
  await assert.rejects(
    document('/another').restoreCheckpoint(checkpoint),
    /another document/,
  );
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal(candidate.historySize(), created.historySize());
});

test('rejects malformed signed state atomically and permits a subsequent valid restore', async () => {
  const { document, created, signing } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const state = JSON.parse(new TextDecoder().decode(checkpoint.payload));
  state.hashes = [];
  const payload = new TextEncoder().encode(JSON.stringify(state));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signing.privateKey,
      payload,
    ),
  );
  const candidate = document();
  await assert.rejects(
    candidate.restoreCheckpoint({ payload, signature }),
    /no document history/,
  );
  assert.equal(candidate.historySize(), 0);
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal((await candidate.getWriters()).length, 1);
});

test('preserves membership state so a restored founder can remove an existing reader', async () => {
  const { document, created, kem } = await fixture();
  const member = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const memberKem = await generateEciesKeyPair();
  await created.addReader(
    member.publicKey,
    new Uint8Array(await crypto.subtle.exportKey('raw', memberKem.publicKey)),
  );
  const checkpoint = await created.exportCheckpoint();
  const localWelcome = JSON.parse(new TextDecoder().decode(checkpoint.payload))
    .beekem.welcome;
  assert.throws(
    () => deserializeBeeKEMWelcomeV2FromWire(localWelcome),
    /appended rightmost leaf/,
  );
  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(checkpoint);
  await restored.open();
  assert.equal(
    (await restored.getReaders()).length,
    (await created.getReaders()).length,
  );
  await restored.removeReader(member.publicKey);
  assert.equal(
    (await restored.getReaders()).length,
    (await created.getReaders()).length - 1,
  );
  const afterRemoval = document();
  await afterRemoval.setKemKeyPair(kem);
  await afterRemoval.restoreCheckpoint(await restored.exportCheckpoint());
  await afterRemoval.open();
  await afterRemoval.change((doc) => {
    doc.getText('fixture').insert(0, 'current ');
  });
  assert.equal(
    afterRemoval.document.getText('fixture').toString(),
    'current before restart',
  );
});

test('provider decoding failures do not install staged ACLs or document keys', async () => {
  const { document, created, signing } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const state = JSON.parse(new TextDecoder().decode(checkpoint.payload));
  state.document = Buffer.from('invalid Yjs state').toString('base64');
  const payload = new TextEncoder().encode(JSON.stringify(state));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signing.privateKey,
      payload,
    ),
  );
  const candidate = document();
  await assert.rejects(candidate.restoreCheckpoint({ payload, signature }));
  assert.equal(candidate.historySize(), 0);
  assert.equal((await candidate.getWriters()).length, 0);
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal(
    candidate.document.getText('fixture').toString(),
    'before restart',
  );
});
