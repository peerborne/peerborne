import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore } from 'datastore-idb';
import { CID } from 'multiformats/cid';
import { code as rawCodec } from 'multiformats/codecs/raw';
import { documentCheckpointCommitment } from '@peerborne/core';
import { createBrowserCheckpointStorage } from '../../examples/shared/browser-checkpoint-store.ts';
import {
  documentFixture,
  replicaOf,
  receiveEncrypted,
  syntheticText,
} from '../fixtures.mjs';

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const turn = () => new Promise((resolve) => setTimeout(resolve, 0));
const paint = () =>
  new Promise((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(resolve)),
  );

function distribution(values) {
  if (!values.length) return { count: 0, p50: null, p99: null, max: null };
  const sorted = [...values].sort((a, b) => a - b);
  return {
    count: values.length,
    p50: sorted[Math.ceil(sorted.length * 0.5) - 1],
    p99: sorted[Math.ceil(sorted.length * 0.99) - 1],
    max: sorted.at(-1),
  };
}

async function measure(operation, { sampleHeap = false } = {}) {
  const gaps = [];
  const tasks = [];
  let peakSampledJSHeapBytes = null;
  const observeHeap = () => {
    const used = performance.memory?.usedJSHeapSize;
    if (sampleHeap && Number.isFinite(used))
      peakSampledJSHeapBytes = Math.max(peakSampledJSHeapBytes ?? 0, used);
  };
  const observer = new PerformanceObserver((list) =>
    tasks.push(...list.getEntries().map(({ duration }) => duration)),
  );
  observer.observe({ entryTypes: ['longtask'] });
  let last = performance.now();
  const timer = setInterval(() => {
    const now = performance.now();
    gaps.push(now - last);
    last = now;
    if (sampleHeap) observeHeap();
  }, 1);
  const start = performance.now();
  try {
    if (sampleHeap) observeHeap();
    const value = await operation();
    await turn();
    if (sampleHeap) observeHeap();
    tasks.push(...observer.takeRecords().map(({ duration }) => duration));
    return {
      value,
      elapsedMs: performance.now() - start,
      timerGapMs: distribution(gaps),
      longTasksMs: distribution(tasks),
      ...(sampleHeap ? { peakSampledJSHeapBytes } : {}),
    };
  } finally {
    clearInterval(timer);
    observer.disconnect();
  }
}

function trackIDB() {
  const counters = {
    readwriteTransactions: 0,
    readonlyTransactions: 0,
    putCalls: 0,
    addCalls: 0,
  };
  const transaction = IDBDatabase.prototype.transaction;
  const put = IDBObjectStore.prototype.put;
  const add = IDBObjectStore.prototype.add;
  IDBDatabase.prototype.transaction = function (names, mode, options) {
    if (mode === 'readwrite') counters.readwriteTransactions++;
    else counters.readonlyTransactions++;
    return transaction.call(this, names, mode, options);
  };
  IDBObjectStore.prototype.put = function (...args) {
    counters.putCalls++;
    return put.apply(this, args);
  };
  IDBObjectStore.prototype.add = function (...args) {
    counters.addCalls++;
    return add.apply(this, args);
  };
  return {
    snapshot: () => ({ ...counters }),
    reset() {
      for (const key of Object.keys(counters)) counters[key] = 0;
    },
    restore() {
      IDBDatabase.prototype.transaction = transaction;
      IDBObjectStore.prototype.put = put;
      IDBObjectStore.prototype.add = add;
    },
  };
}

async function storageFixture(name, options = {}) {
  const blockstore = new IDBBlockstore(`/technical-${name}-blocks`);
  const datastore = new IDBDatastore(`/technical-${name}-data`);
  await blockstore.open();
  await datastore.open();
  const fixture = await documentFixture({
    ...options,
    blockstore,
    datastore,
    compaction: {
      enabled: true,
      snapshotInterval: 16,
      minChangesBeforeSnapshot: 16,
      keepRecentNodes: 4,
      pruneAfterSnapshot: true,
      gcAfterPrune: false,
    },
  });
  return {
    ...fixture,
    async close() {
      await fixture.close();
      await blockstore.close();
      await datastore.close();
    },
  };
}

async function batching({ full }) {
  const fixture = await storageFixture('batching');
  const tracker = trackIDB();
  try {
    const wordCount = full ? 20_000 : 1000;
    const burst = full ? 2000 : 32;
    const text = Array.from({ length: wordCount }, (_, i) => `word${i}`).join(
      ' ',
    );
    const paste = await measure(() =>
      fixture.document.change((doc) => doc.getText('paste').insert(0, text)),
    );
    assert(
      fixture.document.document.getText('paste').toString() === text,
      'paste lost text',
    );
    const pasteIO = tracker.snapshot();
    tracker.reset();
    const unbatched = await measure(async () => {
      for (let i = 0; i < burst; i++)
        await fixture.document.change((doc) =>
          doc.getMap('burst').set(String(i), i),
        );
    });
    const unbatchedIO = tracker.snapshot();
    tracker.reset();
    const publishesBeforeBatch = fixture.stats.publishedFrames;
    const batched = await measure(async () => {
      fixture.document.startChange();
      for (let i = 0; i < burst; i++)
        fixture.document.addChange((doc) =>
          doc.getMap('batch').set(String(i), i),
        );
      await fixture.document.endChange();
    });
    const batchedIO = tracker.snapshot();
    assert(
      fixture.document.document.getMap('batch').size === burst,
      'transaction lost mutations',
    );
    assert(
      fixture.stats.publishedFrames - publishesBeforeBatch === 1,
      'explicit batch must create one document commit',
    );
    assert(
      batchedIO.putCalls < unbatchedIO.putCalls,
      'explicit batching must reduce actual IndexedDB puts',
    );
    const clean = ({ value: _value, ...metrics }) => metrics;
    return {
      scope:
        'Real Peerborne commits, UnixFS and browser IndexedDB; substituted transport. Explicit transaction compared with sequential change() calls.',
      metrics: {
        wordCount,
        burst,
        paste: { ...clean(paste), ...pasteIO },
        unbatched: { ...clean(unbatched), ...unbatchedIO },
        batched: { ...clean(batched), ...batchedIO },
        explicitBatchConverged: true,
      },
      gaps: [
        'Callers can use startChange/addChange/endChange to batch, but sequential change() calls generate individual block writes. No automatic WAL/coalescing guarantee is established.',
      ],
    };
  } finally {
    tracker.restore();
    await fixture.close();
  }
}

const coldPath = '/technical-cold-recovery';
const coldHistoryChunkSize = 64 * 1024;
const coldCheckpoints = createBrowserCheckpointStorage(
  '/technical-cold-checkpoints',
  'peerborne/technical-cold-checkpoint/1',
);

async function coldStorageFixture(create) {
  const identity = await coldCheckpoints.getIdentity();
  const fixture = await storageFixture('cold', {
    identity: identity.signing,
    index: create ? 100 : 101,
    path: coldPath,
    open: create,
  });
  try {
    const owner = await fixture.auth.serializePublicKey(
      identity.signing.publicKey,
    );
    return {
      ...fixture,
      checkpoints: new coldCheckpoints.Store(identity, owner),
    };
  } catch (error) {
    await fixture.close();
    throw error;
  }
}

async function coldManifest(mode, value) {
  const database = await new Promise((resolve, reject) => {
    const request = indexedDB.open('/technical-cold-metadata', 1);
    request.onupgradeneeded = () =>
      request.result.createObjectStore('manifest');
    request.onerror = () => reject(new Error('cold manifest open failed'));
    request.onsuccess = () => resolve(request.result);
  });
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction('manifest', mode);
      const request =
        mode === 'readwrite'
          ? transaction.objectStore('manifest').put(value, 'state')
          : transaction.objectStore('manifest').get('state');
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () =>
        reject(new Error('cold manifest transaction failed'));
      transaction.onabort = () =>
        reject(new Error('cold manifest transaction aborted'));
    });
  } finally {
    database.close();
  }
}

async function seedCold({ seed }) {
  const targetBytes = 50 * 1024 * 1024;
  const historyMutations = Math.ceil(targetBytes / coldHistoryChunkSize);
  const fixture = await coldStorageFixture(true);
  const doc = fixture.document;
  try {
    // The reference checkpoint store encrypts the small base checkpoint. The
    // large update is stored only as a production UnixFS change block.
    const checkpoint = await doc.exportPlaintextCheckpoint();
    const checkpointPin = await documentCheckpointCommitment(checkpoint);
    try {
      await fixture.checkpoints.save(coldPath, false, checkpoint, 0);
    } finally {
      checkpoint.payload.fill(0);
      checkpoint.signature.fill(0);
    }

    let cid;
    doc.subscribe(
      'cold-change-cid',
      (_state, _readers, _writers, [hash]) => {
        cid = hash;
      },
      'local',
    );
    doc.document.gc = false;
    await doc.change((state) => {
      const root = state.getMap('root');
      const edits = state.getArray('edits');
      state.transact(() => {
        for (let i = 0; i < historyMutations; i++) {
          root.set(
            'historicalText',
            syntheticText(coldHistoryChunkSize, seed + i),
          );
          edits.push([i]);
          if (i > 0) edits.delete(0, 1);
        }
      });
    });
    doc.unsubscribe('cold-change-cid');
    assert(
      cid && CID.parse(cid).code !== rawCodec,
      'expected a chunked UnixFS change',
    );
    const encodedHistoryBytes = fixture.provider.getHistory(
      doc.document,
    ).byteLength;
    assert(
      encodedHistoryBytes >= targetBytes,
      'fixture must contain at least the requested encoded history bytes',
    );

    // Normal sync supports signed deferred change nodes. The fixture supplies
    // one such node after restart to replay the accepted local change by CID.
    const deferred = {
      documentId: coldPath,
      signatureContext: 'ordinary-sync-v1',
      changeId: cid,
      changes: { kind: 'document' },
    };
    const signature = await fixture.auth.sign(
      fixture.serializer.serializeSyncMessage(deferred),
      fixture.identity.privateKey,
    );
    await coldManifest('readwrite', {
      checkpointPin,
      message: {
        ...deferred,
        signature: btoa(String.fromCharCode(...signature)),
      },
      encodedHistoryBytes,
      historyMutations,
      seed,
    });
    return {
      encodedHistoryBytes,
      historyMutations,
      targetBytes,
      encryption: 'AES-GCM',
      sourceGC: false,
      chunkedUnixFS: true,
    };
  } finally {
    await fixture.close();
  }
}

async function loadCold() {
  const timeline = {};
  const io = trackIDB();
  const button = document.querySelector('#input');
  let fixture;
  try {
    await paint();
    timeline.shellPaintMs = performance.now();
    const timing = await measure(
      async () => {
        timeline.startedMs = performance.now();
        const manifest = await coldManifest('readonly');
        assert(manifest, 'cold fixture not seeded');
        fixture = await coldStorageFixture(false);
        const doc = fixture.document;
        const saved = await fixture.checkpoints.load(coldPath);
        assert(saved, 'base checkpoint missing');
        try {
          await doc.restorePlaintextCheckpoint(
            saved.checkpoint,
            manifest.checkpointPin,
          );
        } finally {
          saved.checkpoint.payload.fill(0);
          saved.checkpoint.signature.fill(0);
        }
        await doc.open();
        timeline.baseOpenedMs = performance.now();
        assert(
          doc.document.getArray('edits').length === 0,
          'base already contains the tail',
        );
        assert(
          !doc.hasChange(manifest.message.changeId),
          'base already knows the tail',
        );

        timeline.replayStartedMs = performance.now();
        assert(
          await doc.sync(manifest.message),
          'signed deferred sync was rejected',
        );
        timeline.historyFinishedMs = performance.now();
        assert(
          doc.hasChange(manifest.message.changeId),
          'SDK did not apply the stored change',
        );
        const edits = doc.document.getArray('edits');
        const lastEdit = edits.get(0);
        assert(
          edits.length === 1 && lastEdit === manifest.historyMutations - 1,
          'cold history reconstruction lost edits',
        );
        assert(
          doc.document.getMap('root').get('historicalText') ===
            syntheticText(coldHistoryChunkSize, manifest.seed + lastEdit),
          'cold initial document state is wrong',
        );
        document.querySelector('#document').textContent =
          `Loaded ${lastEdit + 1} historical edits`;
        await paint();
        timeline.firstDocumentPaintMs = performance.now();
        await new Promise((resolve, reject) => {
          button.onclick = async () => {
            button.disabled = true;
            timeline.firstEditStartedMs = performance.now();
            try {
              await doc.change((state) =>
                state.getMap('root').set('restartEdit', 1),
              );
              assert(
                doc.document.getMap('root').get('restartEdit') === 1,
                'first recovered-document edit did not commit',
              );
              timeline.firstEditCompletedMs = performance.now();
              document.querySelector('#probe').textContent = 'Committed edit 1';
              resolve();
            } catch (error) {
              reject(error);
            }
          };
          button.disabled = false;
        });
        return {
          encodedHistoryBytes: manifest.encodedHistoryBytes,
          historyMutations: manifest.historyMutations,
        };
      },
      { sampleHeap: true },
    );
    const { value, ...metrics } = timing;
    return {
      scope:
        'Fresh Chromium process with the same profile. Public SDK checkpoint restore, open, authenticated deferred sync from IndexedDB, and edit. Transport is substituted.',
      metrics: {
        ...value,
        ...metrics,
        io: io.snapshot(),
        timeline,
        deferredReplayMs: timeline.historyFinishedMs - timeline.replayStartedMs,
        documentTTIms: timeline.firstEditCompletedMs - timeline.startedMs,
        navigationToFirstEditMs: timeline.firstEditCompletedMs,
        firstEditCommitMs:
          timeline.firstEditCompletedMs - timeline.firstEditStartedMs,
        initialDocumentPaintBeforeHistoryFinished:
          timeline.firstDocumentPaintMs < timeline.historyFinishedMs,
        ttiDefinition:
          'Time from recovery start through reconstructed document paint and a real click that commits an SDK edit. Includes Playwright input scheduling.',
      },
      gaps: [],
      limitations: [
        'The fixture supplies the signed missing frontier. The checkpoint, commitment, browser identity, and Helia storage all survive in the same profile.',
        'The initial document paints after replay. The test measures sampled JavaScript heap and observed long tasks, without imposing device-independent timing budgets.',
      ],
    };
  } finally {
    button.disabled = true;
    button.onclick = null;
    io.restore();
    await fixture?.close();
  }
}

function withDeadline(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function dataChannelPair(leftIndex, rightIndex, pcs) {
  const left = new RTCPeerConnection({ iceServers: [] });
  pcs.push(left);
  window.technicalProgress.peerConnectionsCreated = pcs.length;
  const right = new RTCPeerConnection({ iceServers: [] });
  pcs.push(right);
  window.technicalProgress.peerConnectionsCreated = pcs.length;
  const candidatesLeft = [];
  const candidatesRight = [];
  left.onicecandidate = ({ candidate }) => {
    if (candidate) candidatesLeft.push(candidate);
  };
  right.onicecandidate = ({ candidate }) => {
    if (candidate) candidatesRight.push(candidate);
  };
  const fromLeft = left.createDataChannel(`${leftIndex}-${rightIndex}`, {
    ordered: true,
  });
  fromLeft.binaryType = 'arraybuffer';
  const fromRight = new Promise((resolve) => {
    right.ondatachannel = ({ channel }) => {
      channel.binaryType = 'arraybuffer';
      resolve(channel);
    };
  });
  await left.setLocalDescription(await left.createOffer());
  await right.setRemoteDescription(left.localDescription);
  await right.setLocalDescription(await right.createAnswer());
  await left.setRemoteDescription(right.localDescription);
  const gathered = (pc) =>
    pc.iceGatheringState === 'complete'
      ? Promise.resolve()
      : new Promise((resolve) => {
          pc.addEventListener('icegatheringstatechange', () => {
            if (pc.iceGatheringState === 'complete') resolve();
          });
        });
  await withDeadline(
    Promise.all([gathered(left), gathered(right)]),
    10_000,
    'ICE gathering timed out',
  );
  await Promise.all([
    ...candidatesLeft.map((candidate) => right.addIceCandidate(candidate)),
    ...candidatesRight.map((candidate) => left.addIceCandidate(candidate)),
  ]);
  const toLeft = await withDeadline(
    fromRight,
    10_000,
    'data channel negotiation timed out',
  );
  const opened = (channel) =>
    channel.readyState === 'open'
      ? Promise.resolve()
      : new Promise((resolve, reject) => {
          channel.onopen = resolve;
          channel.onerror = () => reject(new Error('data channel failed'));
        });
  await withDeadline(
    Promise.all([opened(fromLeft), opened(toLeft)]),
    10_000,
    'data channel open timed out',
  );
  return [fromLeft, toLeft];
}

async function topology({ full, topology: topologyName }) {
  const peerCount = full ? 50 : 4;
  window.technicalProgress = {
    peerCount,
    topology: topologyName,
    peerConnectionsCreated: 0,
    linksOpened: 0,
  };
  const rounds = full ? 4 : 2;
  const fixtures = [];
  const pcs = [];
  const links = Array.from({ length: peerCount }, () => new Map());
  const errors = [];
  const receiveTails = Array.from({ length: peerCount }, () =>
    Promise.resolve(),
  );
  const seen = Array.from({ length: peerCount }, () => new Set());
  const expectedOperations = peerCount * rounds;
  const latencies = [];
  let sentFrames = 0;
  let receivedFrames = 0;
  let sentBytes = 0;
  let maxBufferedBytes = 0;
  const codecs = {};
  try {
    const founder = await documentFixture({ index: 1 });
    fixtures.push(founder);
    await founder.document.change((doc) =>
      doc.getMap('ops').set('bootstrap', 1),
    );
    for (let i = 1; i < peerCount; i++)
      fixtures.push(await replicaOf(founder, i + 1));
    const pairs = [];
    for (let i = 0; i < peerCount; i++) {
      for (let j = i + 1; j < peerCount; j++) {
        const distance = Math.min(j - i, peerCount - (j - i));
        if (topologyName === 'mesh' || distance <= 2) pairs.push([i, j]);
      }
    }
    // Limit negotiation concurrency; every selected link must open.
    for (let offset = 0; offset < pairs.length; offset += 8) {
      await Promise.all(
        pairs.slice(offset, offset + 8).map(async ([i, j]) => {
          const [left, right] = await dataChannelPair(i, j, pcs);
          links[i].set(j, left);
          links[j].set(i, right);
          window.technicalProgress.linksOpened++;
        }),
      );
    }
    const send = async (channel, bytes) => {
      assert(
        bytes.byteLength < 256 * 1024,
        'fixture frame exceeds negotiated RTC message bound',
      );
      maxBufferedBytes = Math.max(maxBufferedBytes, channel.bufferedAmount);
      if (channel.bufferedAmount > 1024 * 1024) {
        channel.bufferedAmountLowThreshold = 256 * 1024;
        await withDeadline(
          new Promise((resolve) =>
            channel.addEventListener('bufferedamountlow', resolve, {
              once: true,
            }),
          ),
          10_000,
          'RTC backpressure did not drain',
        );
      }
      channel.send(bytes);
      sentFrames++;
      sentBytes += bytes.byteLength;
    };
    const forward = async (index, bytes, except) => {
      for (const [remote, channel] of links[index])
        if (remote !== except) await send(channel, bytes);
    };
    for (let i = 0; i < peerCount; i++) {
      fixtures[i].setPublish(async (_topic, frame) => {
        // Sequence and timestamps belong to the test transport header. The
        // production signed/encrypted envelope is carried unchanged.
        const header = new Uint8Array(12);
        const view = new DataView(header.buffer);
        view.setUint32(0, i);
        view.setUint32(4, fixtures[i].stats.publishedFrames);
        view.setUint32(8, Math.floor(performance.now()));
        const bytes = new Uint8Array(header.length + frame.length);
        bytes.set(header);
        bytes.set(frame, header.length);
        seen[i].add(`${i}:${view.getUint32(4)}`);
        await forward(i, bytes);
      });
      for (const [remote, channel] of links[i]) {
        channel.onmessage = ({ data }) => {
          receivedFrames++;
          const bytes = new Uint8Array(data);
          const view = new DataView(bytes.buffer);
          const id = `${view.getUint32(0)}:${view.getUint32(4)}`;
          if (seen[i].has(id)) return;
          seen[i].add(id);
          receiveTails[i] = receiveTails[i]
            .then(async () => {
              assert(
                await receiveEncrypted(fixtures[i], bytes.slice(12)),
                'authenticated RTC frame was rejected',
              );
              latencies.push(performance.now() - view.getUint32(8));
              await forward(i, bytes, remote);
            })
            .catch(() => {
              errors.push('RTC receive/apply failed');
            });
        };
      }
    }
    for (const fixture of fixtures) {
      for (const method of [
        'serializeSyncMessage',
        'deserializeSyncMessage',
        'serializeChanges',
        'deserializeChanges',
      ]) {
        const original = fixture.serializer[method].bind(fixture.serializer);
        const counter = (codecs[method] ??= { calls: 0, totalMs: 0, maxMs: 0 });
        fixture.serializer[method] = (...args) => {
          const start = performance.now();
          try {
            return original(...args);
          } finally {
            const elapsed = performance.now() - start;
            counter.calls++;
            counter.totalMs += elapsed;
            counter.maxMs = Math.max(counter.maxMs, elapsed);
          }
        };
      }
    }
    const timing = await measure(async () => {
      // Each peer's local commits are ordered; all peers are active together.
      await Promise.all(
        fixtures.map(async (fixture, index) => {
          for (let round = 0; round < rounds; round++) {
            await fixture.document.change((doc) =>
              doc.getMap('ops').set(`${index}:${round}`, true),
            );
          }
        }),
      );
      await withDeadline(
        (async () => {
          while (
            fixtures.some(
              (fixture) =>
                fixture.document.document.getMap('ops').size !==
                expectedOperations + 1,
            )
          ) {
            assert(errors.length === 0, 'RTC receive pipeline failed');
            await turn();
          }
        })(),
        60_000,
        'peers did not converge before the bounded deadline',
      );
      await Promise.all(receiveTails);
      for (const channels of links) {
        for (const channel of channels.values()) {
          await withDeadline(
            (async () => {
              while (channel.bufferedAmount) await turn();
            })(),
            10_000,
            'RTC outbound queue did not drain',
          );
        }
      }
      await withDeadline(
        (async () => {
          while (receivedFrames !== sentFrames) await turn();
          await Promise.all(receiveTails);
        })(),
        10_000,
        'RTC frame counters did not drain',
      );
    });
    for (const fixture of fixtures) {
      const map = fixture.document.document.getMap('ops');
      for (let peer = 0; peer < peerCount; peer++) {
        for (let round = 0; round < rounds; round++)
          assert(
            map.get(`${peer}:${round}`) === true,
            'peer lost an operation',
          );
      }
    }
    assert(errors.length === 0, 'RTC error observed');
    const { value: _value, ...metrics } = timing;
    return {
      scope:
        'Independent Peerborne documents and real native WebRTC data channels in one Chromium renderer. Transport graph, signaling, backpressure and flood deduplication are test fixtures; this is not libp2p/GossipSub mesh evidence.',
      metrics: {
        peerCount,
        rounds,
        topology: topologyName,
        undirectedLinks: pairs.length,
        operations: expectedOperations,
        sentFrames,
        receivedFrames,
        sentBytes,
        maxBufferedBytes,
        latencyMs: distribution(latencies),
        codecs,
        ...metrics,
        converged: true,
      },
      gaps: [
        'Product libp2p topology scaling and automatic relay/fanout fallback are not exercised by the native RTC harness. A single-renderer mesh may also hit browser connection limits before a multi-process deployment does.',
      ],
    };
  } finally {
    for (const pc of pcs) pc.close();
    await Promise.all(receiveTails);
    await Promise.all(fixtures.map((fixture) => fixture.close()));
  }
}

window.technical = { batching, seedCold, loadCold, topology };
