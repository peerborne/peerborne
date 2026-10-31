import * as A from '@automerge/automerge';
import * as Y from 'yjs';
import { createHeliaLight } from 'helia';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { Peerborne, SubtleCrypto } from '@peerborne/core';
import {
  AutomergeProvider,
  AutomergeACLProvider,
  AutomergeKeychainProvider,
  AutomergeJSONSerializer,
} from '@peerborne/automerge';
import {
  YjsProvider,
  YjsACLProvider,
  YjsKeychainProvider,
  YjsJSONSerializer,
} from '@peerborne/yjs';

export { A, Y };

export function actor(index) {
  return index.toString(16).padStart(32, '0');
}

export function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

export function shuffled(values, seed) {
  const result = [...values];
  const random = seededRandom(seed);
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

export function syntheticText(length, seed) {
  const random = seededRandom(seed);
  const parts = [];
  for (let offset = 0; offset < length; offset += 8192) {
    const bytes = new Uint8Array(Math.min(8192, length - offset));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = 33 + Math.floor(random() * 90);
    }
    parts.push(String.fromCharCode(...bytes));
  }
  return parts.join('');
}

export async function signingIdentity() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
}

export function providerFor(adapter, index = 1, options = {}) {
  const provider =
    adapter === 'automerge' ? new AutomergeProvider() : new YjsProvider();
  provider.newDocument = () => {
    if (adapter === 'automerge') return A.init({ actor: actor(index) });
    const document = new Y.Doc({ gc: options.gc ?? true });
    document.clientID = index;
    return document;
  };
  return provider;
}

// Only the transport is substituted. Document commits, codecs, Web Crypto,
// UnixFS, snapshots, pruning, and the supplied blockstore are production code.
export async function documentFixture({
  adapter = 'yjs',
  index = 1,
  identity,
  path = '/technical-verification',
  compaction = {},
  blockstore = new MemoryBlockstore(),
  datastore = new MemoryDatastore(),
  open = true,
} = {}) {
  identity ??= await signingIdentity();
  const provider = providerFor(adapter, index);
  const serializer =
    adapter === 'automerge'
      ? new AutomergeJSONSerializer()
      : new YjsJSONSerializer();
  const acl =
    adapter === 'automerge' ? new AutomergeACLProvider() : new YjsACLProvider();
  const keychain =
    adapter === 'automerge'
      ? new AutomergeKeychainProvider()
      : new YjsKeychainProvider();
  const auth = new SubtleCrypto();
  const pubsub = new EventTarget();
  const stats = { publishedFrames: 0, publishedBytes: 0, lastFrame: undefined };
  let publish = async () => {};
  Object.assign(pubsub, {
    topicValidators: new Map(),
    subscribe() {},
    unsubscribe() {},
    async publish(topic, bytes) {
      stats.publishedFrames++;
      stats.publishedBytes += bytes.byteLength;
      stats.lastFrame = bytes.slice();
      await publish(topic, bytes);
    },
  });
  const helia = createHeliaLight({ blockstore, datastore, start: false });
  Object.assign(helia, {
    libp2p: { getConnections: () => [], services: { pubsub } },
  });
  const swarm = new Peerborne(
    identity.privateKey,
    identity.publicKey,
    provider,
    serializer,
    serializer,
    serializer,
    auth,
    acl,
    keychain,
  );
  swarm._heliaNode = helia;
  swarm._config = { compaction, loadQuorumEnabled: false };
  const document = swarm.doc(path);
  if (adapter === 'yjs') {
    for (const name of ['root', 'local', 'cursors', 'left', 'right', 'ops']) {
      document.document.getMap(name);
    }
  }
  if (open) await document.create();
  return {
    document,
    provider,
    serializer,
    auth,
    identity,
    helia,
    blockstore,
    stats,
    setPublish(callback) {
      publish = callback;
    },
    async close() {
      await document.close();
      await helia.stop();
    },
  };
}

export async function replicaOf(source, index, options = {}) {
  const target = await documentFixture({
    adapter: options.adapter ?? 'yjs',
    index,
    identity: source.identity,
    path: source.document.documentPath,
    ...options,
    open: false,
  });
  target.document._writers.merge(source.document._writers.current());
  target.document._keychain.merge(source.document._keychain.history());
  await target.document._keychain.keys();
  if (!(await target.document.sync(await publishedMessage(source)))) {
    throw new Error('Fixture replica rejected authenticated bootstrap');
  }
  await target.document.open();
  return target;
}

export async function publishedMessage(fixture) {
  const bytes = fixture.stats.lastFrame;
  const raw = await fixture.document._decryptBlock(
    bytes.slice(0, 32),
    bytes.slice(32, 44),
    bytes.slice(44),
  );
  if (raw === undefined)
    throw new Error('Fixture could not decrypt its published frame');
  return fixture.serializer.deserializeSyncMessage(raw);
}

export async function signedMessage(fixture, fields) {
  const message = {
    documentId: fixture.document.documentPath,
    signatureContext: 'ordinary-sync-v1',
    ...fields,
  };
  message.signature = await fixture.document._signAsWriter(message);
  return message;
}

export function project(fixture) {
  return fixture.document.document instanceof Y.Doc
    ? fixture.document.document.toJSON()
    : JSON.parse(JSON.stringify(fixture.document.document));
}

export async function receiveEncrypted(fixture, bytes) {
  const raw = await fixture.document._decryptBlock(
    bytes.slice(0, 32),
    bytes.slice(32, 44),
    bytes.slice(44),
  );
  if (raw === undefined) return false;
  return fixture.document.sync(fixture.serializer.deserializeSyncMessage(raw));
}
