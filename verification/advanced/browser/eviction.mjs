import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore } from 'datastore-idb';
import { CID } from 'multiformats/cid';
import {
  getOrCreateIdentity,
  identityFingerprint,
} from '../../../examples/peerborne-note/src/identity-store.ts';
import { documentFixture } from '../../fixtures.mjs';
import { assert, until } from './support.mjs';

let fixture,
  stores = [],
  pc,
  channel,
  tail = Promise.resolve(),
  identity;
let applied = 0,
  rejected = 0,
  receivedBlocks = 0,
  lastFrame;
const manifestName = '/advanced-eviction-manifest';
async function manifest(value) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(manifestName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('state');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('eviction manifest open failed'));
  });
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(
        'state',
        value === undefined ? 'readonly' : 'readwrite',
      );
      const request =
        value === undefined
          ? transaction.objectStore('state').get('current')
          : transaction.objectStore('state').put(value, 'current');
      transaction.oncomplete = () => resolve(request.result);
      transaction.onabort = transaction.onerror = () =>
        reject(new Error('eviction manifest transaction failed'));
    });
  } finally {
    db.close();
  }
}
async function storage() {
  const blockstore = new IDBBlockstore('/advanced-eviction-blocks');
  const datastore = new IDBDatastore('/advanced-eviction-data');
  await blockstore.open();
  await datastore.open();
  stores.push(blockstore, datastore);
  return { blockstore, datastore };
}
export async function victimIdentity() {
  identity = await getOrCreateIdentity();
  return {
    publicKey: await crypto.subtle.exportKey('jwk', identity.publicKey),
    fingerprint: await identityFingerprint(identity.publicKey),
    privateKeyExtractable: identity.privateKey.extractable,
  };
}
export async function authorityStart(publicKey, settings) {
  fixture = await documentFixture({
    path: `/advanced/eviction-${settings.seed}`,
    index: 100,
  });
  const key = await crypto.subtle.importKey(
    'jwk',
    publicKey,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['verify'],
  );
  await fixture.document._runWriterMutation(() =>
    fixture.document._writers.add(key),
  );
  const changes = settings.full ? 100 : 8;
  for (let i = 0; i < changes; i++)
    await fixture.document.change((doc) =>
      doc.getMap('root').set('authoritativeCounter', i),
    );
  await fixture.document.snapshot();
  return {
    path: fixture.document.documentPath,
    writers: Array.from(fixture.document._writers.current()),
    keychain: Array.from(fixture.document._keychain.history()),
    changes,
  };
}
export async function enroll(bootstrap) {
  identity ??= await getOrCreateIdentity();
  fixture = await documentFixture({
    identity,
    path: bootstrap.path,
    index: 200,
    open: false,
    ...(await storage()),
  });
  if (bootstrap.writers.length)
    fixture.document._writers.merge(new Uint8Array(bootstrap.writers));
  if (bootstrap.keychain.length)
    fixture.document._keychain.merge(new Uint8Array(bootstrap.keychain));
  await fixture.document._keychain.keys();
}
function bind(value) {
  channel = value;
  channel.binaryType = 'arraybuffer';
  channel.onmessage = ({ data }) => {
    const bytes = new Uint8Array(data);
    tail = tail.then(async () => {
      if (bytes[0] === 1) {
        const length = new DataView(bytes.buffer).getUint16(1);
        await fixture.blockstore.put(
          CID.decode(bytes.slice(3, 3 + length)),
          bytes.slice(3 + length),
        );
        receivedBlocks++;
        return;
      }
      const frame = bytes.slice(1);
      const raw = await fixture.document._decryptBlock(
        frame.slice(0, 32),
        frame.slice(32, 44),
        frame.slice(44),
      );
      if (raw === undefined) {
        rejected++;
        return;
      }
      if (
        await fixture.document.sync(
          fixture.serializer.deserializeSyncMessage(raw),
        )
      ) {
        applied++;
        lastFrame = frame;
      } else rejected++;
    });
    tail.catch(() => {});
  };
}
async function gathered() {
  await until(
    () => pc.iceGatheringState === 'complete',
    15000,
    'eviction ICE gathering timed out',
  );
  return pc.localDescription.toJSON();
}
export async function offer() {
  pc = new RTCPeerConnection({ iceServers: [] });
  bind(pc.createDataChannel('peerborne-eviction', { ordered: true }));
  await pc.setLocalDescription(await pc.createOffer());
  return gathered();
}
export async function answer(description) {
  pc = new RTCPeerConnection({ iceServers: [] });
  pc.ondatachannel = ({ channel }) => bind(channel);
  await pc.setRemoteDescription(description);
  await pc.setLocalDescription(await pc.createAnswer());
  return gathered();
}
export async function accept(description) {
  await pc.setRemoteDescription(description);
}
export async function opened() {
  await until(
    () => channel?.readyState === 'open',
    15000,
    'eviction RTC channel did not open',
  );
}
async function send(bytes) {
  if (channel.bufferedAmount > 1024 * 1024)
    await until(
      () => channel.bufferedAmount < 256 * 1024,
      30000,
      'eviction block transfer did not drain',
    );
  assert(
    bytes.length <= pc.sctp.maxMessageSize,
    'eviction RTC frame must fit the negotiated bound',
  );
  channel.send(bytes);
}
export async function sendSnapshot() {
  for await (const { cid, bytes } of fixture.blockstore.getAll()) {
    const parts = [];
    for await (const part of bytes) parts.push(part);
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const frame = new Uint8Array(3 + cid.bytes.length + length);
    frame[0] = 1;
    new DataView(frame.buffer).setUint16(1, cid.bytes.length);
    frame.set(cid.bytes, 3);
    let offset = 3 + cid.bytes.length;
    for (const part of parts) {
      frame.set(part, offset);
      offset += part.length;
    }
    await send(frame);
  }
  const message = fixture.document._createSyncMessage('ordinary-sync-v1');
  message.snapshot = fixture.document.latestSnapshot;
  assert(message.snapshot, 'authority must supply an actual signed snapshot');
  message.signature = await fixture.document._signAsWriter(message);
  const [epoch, key] = await fixture.document._keychain.current();
  const encrypted = await fixture.auth.encrypt(
    fixture.serializer.serializeSyncMessage(message),
    key,
  );
  const frame = new Uint8Array(
    1 + epoch.length + encrypted.nonce.length + encrypted.data.length,
  );
  frame.set(epoch, 1);
  frame.set(encrypted.nonce, 1 + epoch.length);
  frame.set(encrypted.data, 1 + epoch.length + encrypted.nonce.length);
  await send(frame);
}
export async function status() {
  await tail;
  return {
    applied,
    rejected,
    receivedBlocks,
    counter:
      fixture?.document.document.getMap('root').get('authoritativeCounter') ??
      null,
  };
}
export async function persist(bootstrap) {
  await tail;
  assert(
    applied > 0 && lastFrame,
    'pre-eviction snapshot must authenticate before persisting',
  );
  await manifest({ bootstrap, frame: Array.from(lastFrame) });
  return status();
}
export async function restore(path) {
  const info = await victimIdentity();
  const saved = await manifest();
  await enroll(saved?.bootstrap ?? { path, writers: [], keychain: [] });
  let restored = false;
  if (saved) {
    const frame = new Uint8Array(saved.frame);
    const raw = await fixture.document._decryptBlock(
      frame.slice(0, 32),
      frame.slice(32, 44),
      frame.slice(44),
    );
    assert(
      raw !== undefined,
      'persisted snapshot must decrypt before eviction',
    );
    restored = await fixture.document.sync(
      fixture.serializer.deserializeSyncMessage(raw),
    );
    assert(restored, 'persisted snapshot must authenticate before eviction');
  }
  let emptyOpenRejected = false;
  if (!saved) {
    try {
      await fixture.document.open();
    } catch {
      emptyOpenRejected = true;
    }
    assert(
      emptyOpenRejected,
      'opening empty evicted state must not silently create a document',
    );
  }
  return {
    ...info,
    persistedManifestPresent: !!saved,
    restored,
    emptyOpenRejected,
    counter:
      fixture.document.document.getMap('root').get('authoritativeCounter') ??
      null,
  };
}
export async function disconnect() {
  pc?.close();
  pc = undefined;
  channel = undefined;
  await tail;
}
export async function closeStorage() {
  await fixture?.close();
  fixture = undefined;
  for (const store of stores) await store.close();
  stores = [];
}
export async function close() {
  await disconnect();
  await closeStorage();
}
