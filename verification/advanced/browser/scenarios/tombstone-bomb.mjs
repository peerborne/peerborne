import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore } from 'datastore-idb';
import { CID } from 'multiformats/cid';
import {
  documentFixture,
  replicaOf,
  receiveEncrypted,
} from '../../../fixtures.mjs';
import { assert, pair, deadline, until, measure } from '../support.mjs';

export const id = 'tombstone-bomb';

function trackWrites() {
  const counters = { readwriteTransactions: 0, putCalls: 0, deleteCalls: 0 };
  const transaction = IDBDatabase.prototype.transaction;
  const put = IDBObjectStore.prototype.put;
  const remove = IDBObjectStore.prototype.delete;
  IDBDatabase.prototype.transaction = function (...args) {
    if (args[1] === 'readwrite') counters.readwriteTransactions++;
    return transaction.apply(this, args);
  };
  IDBObjectStore.prototype.put = function (...args) {
    counters.putCalls++;
    return put.apply(this, args);
  };
  IDBObjectStore.prototype.delete = function (...args) {
    counters.deleteCalls++;
    return remove.apply(this, args);
  };
  return {
    counters,
    restore() {
      IDBDatabase.prototype.transaction = transaction;
      IDBObjectStore.prototype.put = put;
      IDBObjectStore.prototype.delete = remove;
    },
  };
}

export async function run({ full }) {
  const operations = full ? 100000 : 400;
  const resources = [];
  const stores = [];
  const tracker = trackWrites();
  const fixtures = [];
  let tail = Promise.resolve();
  let gcTail = Promise.resolve();
  try {
    const store = async (name) => {
      const blockstore = new IDBBlockstore(`/advanced-bomb-${name}-blocks`);
      const datastore = new IDBDatastore(`/advanced-bomb-${name}-data`);
      await blockstore.open();
      await datastore.open();
      stores.push(blockstore, datastore);
      return { blockstore, datastore };
    };
    const compaction = {
      enabled: true,
      snapshotInterval: 64,
      minChangesBeforeSnapshot: 64,
      keepRecentNodes: 4,
      pruneAfterSnapshot: true,
      gcAfterPrune: true,
    };
    const source = await documentFixture({
      ...(await store('source')),
      compaction,
    });
    fixtures.push(source);
    const target = await replicaOf(source, 2, {
      ...(await store('target')),
      compaction,
    });
    fixtures.push(target);
    const connection = await pair(resources);
    let receivedFrames = 0,
      sentFrames = 0,
      transportedBytes = 0,
      transportBlocks = 0,
      maxBufferedBytes = 0,
      failures = 0,
      snapshots = 0,
      gcCandidates = 0,
      actualBlockDeletes = 0;
    const send = async (bytes) => {
      maxBufferedBytes = Math.max(
        maxBufferedBytes,
        connection.left.bufferedAmount,
      );
      if (connection.left.bufferedAmount > 1024 * 1024)
        await until(
          () => connection.left.bufferedAmount < 256 * 1024,
          30000,
          'RTC flood backpressure did not drain',
        );
      assert(
        bytes.byteLength <= connection.a.sctp.maxMessageSize,
        'flood frame exceeds negotiated native RTC bound',
      );
      connection.left.send(bytes);
      transportedBytes += bytes.byteLength;
    };
    connection.right.onmessage = ({ data }) => {
      const bytes = new Uint8Array(data);
      tail = tail
        .then(async () => {
          if (bytes[0] === 1) {
            const length = new DataView(bytes.buffer).getUint16(1);
            await target.blockstore.put(
              CID.decode(bytes.slice(3, 3 + length)),
              bytes.slice(3 + length),
            );
            transportBlocks++;
          } else {
            assert(
              await receiveEncrypted(target, bytes.slice(1)),
              'bomb ciphertext must authenticate and apply',
            );
            receivedFrames++;
          }
        })
        .catch(() => {
          failures++;
        });
    };
    // This native carrier transports the encrypted content-addressed blocks too;
    // it substitutes Bitswap, rather than silently sharing a blockstore.
    const sendBlock = async (cid, data) => {
      const bytes = new Uint8Array(3 + cid.bytes.length + data.length);
      bytes[0] = 1;
      new DataView(bytes.buffer).setUint16(1, cid.bytes.length);
      bytes.set(cid.bytes, 3);
      bytes.set(data, 3 + cid.bytes.length);
      await send(bytes);
    };
    for await (const { cid, bytes } of source.blockstore.getAll()) {
      const parts = [];
      for await (const part of bytes) parts.push(part);
      const data = new Uint8Array(
        parts.reduce((sum, part) => sum + part.length, 0),
      );
      let offset = 0;
      for (const part of parts) {
        data.set(part, offset);
        offset += part.length;
      }
      await sendBlock(cid, data);
    }
    const put = source.blockstore.put.bind(source.blockstore);
    source.blockstore.put = async (cid, bytes, ...rest) => {
      const result = await put(cid, bytes, ...rest);
      await sendBlock(cid, bytes);
      return result;
    };
    const remove = source.helia.blockstore.delete.bind(source.helia.blockstore);
    source.helia.blockstore.delete = async (...args) => {
      const result = await remove(...args);
      actualBlockDeletes++;
      return result;
    };
    const snapshot = source.document._snapshotUnlocked.bind(source.document);
    source.document._snapshotUnlocked = async (...args) => {
      snapshots++;
      return snapshot(...args);
    };
    const gc = source.document._gcPrunedBlocks.bind(source.document);
    source.document._gcPrunedBlocks = (cids) => {
      gcCandidates += cids.size;
      gcTail = gcTail.then(() => gc(cids));
      return gcTail;
    };
    source.setPublish(async (_topic, frame) => {
      const bytes = new Uint8Array(1 + frame.length);
      bytes.set(frame, 1);
      await send(bytes);
      sentFrames++;
    });
    const samples = [];
    const timing = await measure(async () => {
      for (let i = 0; i < operations; i++) {
        await source.document.change((doc) => {
          const list = doc.getArray('hostile');
          if (i % 2 === 0) list.insert(0, [i]);
          else list.delete(0, 1);
        });
        if ((i + 1) % (operations / 5) === 0) {
          await until(
            () => {
              assert(failures === 0, 'RTC flood receiver failed');
              return receivedFrames === sentFrames;
            },
            60000,
            'bomb frames did not drain',
          );
          await tail;
          await gcTail;
          const estimate = await navigator.storage.estimate();
          samples.push({
            operations: i + 1,
            retainedCIDs: source.document.historySize(),
            yjsStructs: [
              ...source.document.document.store.clients.values(),
            ].reduce((sum, structs) => sum + structs.length, 0),
            jsHeapUsedBytes: performance.memory?.usedJSHeapSize ?? null,
            storageUsageBytes: estimate.usage ?? null,
            storageQuotaBytes: estimate.quota ?? null,
            ...tracker.counters,
          });
        }
      }
      await deadline(tail, 60000);
      await gcTail;
    });
    assert(
      failures === 0 &&
        receivedFrames === sentFrames &&
        sentFrames === operations,
      'every signed mutation must arrive exactly once in the controlled carrier',
    );
    assert(
      source.document.document.getArray('hostile').length === 0 &&
        target.document.document.getArray('hostile').length === 0,
      'insert/delete flood must converge to an empty array',
    );
    assert(
      snapshots > 1 && gcCandidates > 0,
      'automatic snapshot/prune must actually execute',
    );
    let blocks = 0,
      bytes = 0;
    for await (const block of source.blockstore.getAll()) {
      blocks++;
      for await (const part of block.bytes) bytes += part.length;
    }
    const { value, ...performanceMetrics } = timing;
    return {
      scope:
        '100,000 total alternating mutations in full mode, real signed document commits, automatic compaction, native ordered RTC and two IndexedDB stores. Encrypted block delivery/backpressure are fixture transport code, not shipped libp2p/Bitswap admission policy.',
      metrics: {
        operations,
        insertions: operations / 2,
        deletions: operations / 2,
        sentFrames,
        receivedFrames,
        transportedBytes,
        transportBlocks,
        maxBufferedBytes,
        snapshots,
        gcCandidates,
        actualBlockDeletes,
        blocks,
        blockBytes: bytes,
        samples,
        ...tracker.counters,
        ...performanceMetrics,
        converged: true,
      },
      gaps: [
        ...(actualBlockDeletes === 0
          ? [
              'GC was scheduled but did not delete blocks. Compaction alone has not established bounded browser storage.',
            ]
          : []),
        ...(source.document.historySize() > 64 * 3
          ? [
              'The deduplication/history CID set continues to grow despite pruning the active tree. There is no verified aggregate memory or disk quota defense for a writer-authenticated tombstone flood.',
            ]
          : []),
        'Five samples report measured heap/storage growth; no exponential-growth or mobile quota guarantee follows from one finite workload. The source and receiver share a renderer, and transport flow control is supplied by the fixture.',
      ],
    };
  } finally {
    for (const pc of resources) pc.close();
    await tail;
    await gcTail;
    tracker.restore();
    for (const fixture of fixtures.reverse()) await fixture.close();
    for (const store of stores) await store.close();
  }
}
