import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { deflateRawSync } from 'node:zlib';
import {
  A,
  Y,
  actor,
  providerFor,
  shuffled,
  syntheticText,
  documentFixture,
  replicaOf,
  signedMessage,
  publishedMessage,
  project,
} from '../fixtures.mjs';
import { memory, measure, measuredOnly, nextTurn } from '../measure.mjs';
import { collectTreeCIDs } from '../../packages/core/dist/esm/src/blockstore-gc.js';
import { mergeRemoteSyncTree } from '../../packages/core/dist/esm/src/merkle-cross-links.js';

export async function schema({ seed }) {
  const metrics = {};
  for (const adapter of ['automerge', 'yjs']) {
    const provider = providerFor(adapter, 1);
    let initial = provider.newDocument();
    [initial] = provider.localChange(initial, '', (doc) => {
      if (adapter === 'automerge') doc.user = { name: 'Ada Lovelace' };
      else {
        const user = new Y.Map();
        user.set('name', 'Ada Lovelace');
        doc.getMap('root').set('user', user);
      }
    });
    const makePeer = (index) => {
      if (adapter === 'automerge')
        return A.clone(initial, { actor: actor(index) });
      return provider.remoteChange(
        providerFor(adapter, index).newDocument(),
        provider.getHistory(initial),
      );
    };
    let left = makePeer(2);
    let right = makePeer(3);
    const [a, aDelta] = provider.localChange(left, '', (doc) => {
      if (adapter === 'automerge')
        doc.user.name = { first: 'Ada', last: 'Lovelace' };
      else {
        const name = new Y.Map();
        name.set('first', 'Ada');
        name.set('last', 'Lovelace');
        doc.getMap('root').get('user').set('name', name);
      }
    });
    const [b, bDelta] = provider.localChange(right, '', (doc) => {
      if (adapter === 'automerge') doc.user.name = 'Grace Hopper';
      else doc.getMap('root').get('user').set('name', 'Grace Hopper');
    });
    left = provider.remoteChange(a, bDelta);
    right = provider.remoteChange(b, aDelta);
    const view = (doc) =>
      adapter === 'automerge'
        ? JSON.parse(JSON.stringify(doc))
        : doc.getMap('root').toJSON();
    assert.deepEqual(
      view(left),
      view(right),
      `${adapter}: opposite deliveries must converge`,
    );
    assert.equal(
      view(left).user.name,
      'Grace Hopper',
      `${adapter}: fixed higher actor/client wins`,
    );
    for (const scheduleSeed of [seed, seed + 1, seed + 2]) {
      let observer = makePeer(10 + (scheduleSeed % 1000));
      for (const delta of shuffled(
        [aDelta, bDelta, aDelta, bDelta],
        scheduleSeed,
      )) {
        observer = provider.remoteChange(observer, delta);
      }
      assert.deepEqual(
        view(observer),
        view(left),
        `${adapter}: reorder/replay must converge`,
      );
      if (adapter === 'yjs') observer.destroy();
    }
    if (adapter === 'automerge') {
      const conflicts = Object.values(A.getConflicts(left.user, 'name') ?? {});
      assert.equal(
        conflicts.length,
        2,
        'Automerge must preserve both concurrent values',
      );
      assert(conflicts.some((value) => typeof value === 'object'));
    }
    // The application must tolerate the union during a rolling migration.
    const readName = (value) =>
      typeof value === 'string' ? value : `${value.first} ${value.last}`;
    assert.equal(readName(view(left).user.name), 'Grace Hopper');
    const [edited, delta] = provider.localChange(left, '', (doc) => {
      if (adapter === 'automerge') doc.afterMigration = true;
      else doc.getMap('root').set('afterMigration', true);
    });
    right = provider.remoteChange(right, delta);
    assert.deepEqual(view(edited), view(right));
    metrics[adapter] = {
      schedules: 5,
      duplicateDeliveries: 6,
      converged: true,
      canMutateAfterMerge: true,
    };
    if (adapter === 'yjs') {
      initial.destroy();
      left.destroy();
      right.destroy();
    }
  }
  return {
    metrics,
    gaps: [],
    scope:
      'Real adapters; offline delivery simulation. Union-aware reader is a fixture, not an automatic schema migrator.',
  };
}

export async function history({ full, progress }) {
  const ephemeralMutations = full ? 50_000 : 250;
  const interval = full ? 64 : 32;
  const fixture = await documentFixture({
    compaction: {
      enabled: true,
      snapshotInterval: interval,
      minChangesBeforeSnapshot: interval,
      keepRecentNodes: 4,
      pruneAfterSnapshot: true,
      gcAfterPrune: true,
    },
  });
  let gcTail = Promise.resolve();
  let snapshots = 0;
  let gcCandidates = 0;
  let deletedBlocks = 0;
  const remove = fixture.helia.blockstore.delete.bind(fixture.helia.blockstore);
  fixture.helia.blockstore.delete = async (...args) => {
    await remove(...args);
    deletedBlocks++;
  };
  const gc = fixture.document._gcPrunedBlocks.bind(fixture.document);
  fixture.document._gcPrunedBlocks = (cids) => {
    gcCandidates += cids.size;
    gcTail = gcTail.then(() => gc(cids));
    return gcTail;
  };
  const snapshot = fixture.document._snapshotUnlocked.bind(fixture.document);
  fixture.document._snapshotUnlocked = async () => {
    snapshots++;
    return snapshot();
  };
  const before = memory();
  const samples = [];
  const started = performance.now();
  let late;
  try {
    const timing = await measure(async () => {
      for (let i = 0; i < ephemeralMutations; i++) {
        await fixture.document.change((doc) =>
          doc.getMap('cursors').set('cursor', { x: i, y: -i }),
        );
        await fixture.document.change((doc) =>
          doc.getMap('cursors').delete('cursor'),
        );
        if ((i + 1) % Math.max(1, Math.floor(ephemeralMutations / 5)) === 0) {
          await gcTail;
          samples.push({
            mutations: (i + 1) * 2,
            historyCIDs: fixture.document.historySize(),
            ...memory(),
          });
          progress(`history ${i + 1}/${ephemeralMutations}`);
        }
      }
    });
    await fixture.document.snapshot();
    await gcTail;
    assert(
      snapshots > 1,
      'automatic compaction must run without a manual snapshot per mutation',
    );
    assert(gcCandidates > 0, 'pruning must schedule blockstore GC');
    assert.deepEqual(project(fixture).cursors, {});
    let blockCount = 0;
    let blockBytes = 0;
    for await (const { bytes } of fixture.blockstore.getAll()) {
      blockCount++;
      for await (const chunk of bytes) blockBytes += chunk.byteLength;
    }
    if (deletedBlocks > 0)
      assert(
        blockCount < interval * 3,
        'small fixture blocks must stay bounded after successful GC',
      );
    const tree = fixture.document._lastSyncMessage;
    const retainedNodes = collectTreeCIDs(tree.changeId, tree.changes).size;
    assert(
      retainedNodes <= 8,
      'pruning must retain only the configured tail and ACL',
    );
    late = await documentFixture({
      identity: fixture.identity,
      index: 900,
      open: false,
    });
    late.document._writers.merge(fixture.document._writers.current());
    const load = await signedMessage(fixture, {
      snapshot: fixture.document.latestSnapshot,
      ...tree,
    });
    assert.equal(
      await late.document.sync(load),
      true,
      'late join must accept the signed snapshot and retained tail',
    );
    assert.deepEqual(
      project(late),
      project(fixture),
      'late join must reconstruct the post-GC state',
    );
    await fixture.document.change((doc) =>
      doc.getMap('cursors').set('afterGC', true),
    );
    assert.equal(
      await late.document.sync(await publishedMessage(fixture)),
      true,
    );
    assert.deepEqual(project(late), project(fixture));
    const retainedCIDs = fixture.document.historySize();
    return {
      scope:
        'Real Peerborne change/snapshot/GC and UnixFS in memory; late join uses sync(), not peer discovery or browser restart.',
      metrics: {
        ephemeralMutations,
        deletionMutations: ephemeralMutations,
        snapshots,
        gcCandidates,
        deletedBlocks,
        blockCount,
        blockBytes,
        retainedNodes,
        retainedCIDs,
        samples,
        before,
        after: memory(),
        elapsedIncludingGCms: performance.now() - started,
        ...measuredOnly(timing),
        lateJoinConverged: true,
        lateJoinAfterSuccessfulGC: deletedBlocks > 0,
      },
      gaps: [
        ...(deletedBlocks === 0
          ? [
              'GC was invoked but deleted no blocks. With Helia 7, pins.rm() for these unpinned blocks throws NotFoundError; the production GC catches it as a failure and skips deletion. Late-join after destructive GC therefore remains unverified.',
            ]
          : []),
        ...(retainedCIDs > interval * 3
          ? [
              'History pruning retains every CID in historySize() / the deduplication set. This is not a total-memory bound or removal of CRDT tombstones.',
            ]
          : []),
      ],
    };
  } finally {
    await gcTail;
    await late?.close();
    await fixture.close();
  }
}

export async function causal({ full, seed }) {
  const count = full ? 2048 : 64;
  const metrics = {};
  for (const adapter of ['automerge', 'yjs']) {
    const provider = providerFor(adapter, 1);
    let source = provider.newDocument();
    let receiver = providerFor(adapter, 9000).newDocument();
    const updates = [];
    for (let i = 0; i <= count; i++) {
      let delta;
      [source, delta] = provider.localChange(source, '', (doc) => {
        if (adapter === 'automerge') {
          if (i === 0) doc.values = [];
          else doc.values.push(i);
        } else if (i === 0) doc.getArray('values').push([0]);
        else doc.getArray('values').push([i]);
      });
      updates.push(delta);
    }
    const before = memory();
    const view = (doc) =>
      adapter === 'automerge'
        ? JSON.parse(JSON.stringify(doc))
        : { values: doc.getArray('values').toArray() };
    for (const delta of shuffled(updates.slice(1), seed))
      receiver = provider.remoteChange(receiver, delta);
    assert.equal(
      view(receiver).values?.length ?? 0,
      0,
      `${adapter}: no missing ancestor may be invented`,
    );
    const missing =
      adapter === 'automerge'
        ? A.getMissingDeps(receiver).length
        : (receiver.store.pendingStructs?.update.byteLength ?? 0);
    assert(
      missing > 0,
      `${adapter}: missing causal context must be observable`,
    );
    receiver = provider.remoteChange(receiver, updates[0]);
    assert.deepEqual(
      view(receiver),
      view(source),
      `${adapter}: missing ancestor must release buffered changes`,
    );
    receiver = provider.remoteChange(receiver, updates[0]);
    assert.deepEqual(
      view(receiver),
      view(source),
      `${adapter}: replay must be idempotent`,
    );
    metrics[adapter] = {
      descendantsBeforeAncestor: count,
      bufferedIndicator: missing,
      before,
      after: memory(),
      recovered: true,
    };
    if (adapter === 'yjs') {
      source.destroy();
      receiver.destroy();
    }
  }

  const fixture = await documentFixture();
  try {
    const before = fixture.document.historySize();
    for (let i = 0; i < count; i++) {
      const message = {
        documentId: fixture.document.documentPath,
        signatureContext: 'ordinary-sync-v1',
        changeId: `untrusted-${i}`,
        changes: { kind: 'document', change: new Uint8Array([i % 256]) },
        signature: 'AA==',
      };
      assert.equal(
        await fixture.document.sync(message),
        false,
        'unauthenticated flood must be rejected before CRDT application',
      );
    }
    assert.equal(fixture.document.historySize(), before);
    // Valid, writer-authenticated descendants from many independent histories
    // expose the separate resource-bound problem after authentication.
    let acceptedOrphans = 0;
    for (let i = 0; i < count; i++) {
      const provider = providerFor('yjs', i + 10000);
      let source = provider.newDocument();
      [source] = provider.localChange(source, '', (doc) =>
        doc.getArray('flood').push(['ancestor']),
      );
      const [, orphan] = provider.localChange(source, '', (doc) =>
        doc.getArray('flood').push(['orphan']),
      );
      const message = await signedMessage(fixture, {
        changeId: await fixture.document._putBlock(orphan),
        changes: { kind: 'document', change: orphan },
      });
      if (await fixture.document.sync(message)) acceptedOrphans++;
      source.destroy();
    }
    assert(acceptedOrphans > 0, 'probe must reach the authorized orphan path');
    metrics.flood = {
      attempted: count,
      unauthenticatedRejected: count,
      acceptedOrphans,
      retainedCIDs: fixture.document.historySize() - before,
      yjsPendingBytes:
        fixture.document.document.store.pendingStructs?.update.byteLength ?? 0,
    };
    return {
      scope:
        'Real CRDT causal buffering and signed Peerborne sync ingress. Flood sizes are bounded by the harness, not a product memory limit.',
      metrics,
      gaps: [
        'No aggregate byte/count/TTL bound or eviction policy was observed for writer-authenticated orphan operations. Rejecting unsigned frames does not bound an authorized memory-bloat flood.',
      ],
    };
  } finally {
    await fixture.close();
  }
}

export async function delta({ full, seed }) {
  const changesPerPartition = full ? 300 : 12;
  const fixtures = [];
  try {
    const founder = await documentFixture({ index: 1 });
    fixtures.push(founder);
    await founder.document.change((doc) =>
      doc
        .getMap('root')
        .set('common', syntheticText(full ? 128 * 1024 : 16 * 1024, seed)),
    );
    const left = await replicaOf(founder, 2);
    const right = await replicaOf(founder, 3);
    const leftFollower = await replicaOf(founder, 4);
    const rightFollower = await replicaOf(founder, 5);
    fixtures.push(left, right, leftFollower, rightFollower);
    const timing = await measure(async () => {
      for (let i = 0; i < changesPerPartition; i++) {
        await left.document.change((doc) =>
          doc.getMap('left').set(String(i), i),
        );
        await right.document.change((doc) =>
          doc.getMap('right').set(String(i), -i),
        );
      }
      assert(await leftFollower.document.sync(await publishedMessage(left)));
      assert(await rightFollower.document.sync(await publishedMessage(right)));
    });
    const leftMessage = await publishedMessage(left);
    const rightMessage = await publishedMessage(right);
    const selected = mergeRemoteSyncTree(
      rightMessage.changeId,
      rightMessage.changes,
      leftMessage.changeId,
      left.document._hashes,
    );
    assert.equal(
      selected.length,
      changesPerPartition,
      'receiver-side CID filter must select exactly the unknown partition',
    );
    const wire = right.serializer.serializeSyncMessage(rightMessage);
    const missingPayloadBytes = selected.reduce(
      (sum, [, , payload]) =>
        sum + right.serializer.serializeChanges(payload).byteLength,
      0,
    );
    const fullStateBytes = right.provider.getSnapshot(
      right.document.document,
    ).byteLength;
    assert(
      wire.byteLength > missingPayloadBytes,
      'probe must include the common history present on the wire',
    );
    assert(await left.document.sync(rightMessage));
    assert(await right.document.sync(leftMessage));
    assert.deepEqual(project(left), project(right), 'partitions must converge');
    assert(await left.document.sync(rightMessage));
    assert.deepEqual(
      project(left),
      project(right),
      'replayed partition sync must be idempotent',
    );
    assert(await leftFollower.document.sync(rightMessage));
    assert(await rightFollower.document.sync(leftMessage));
    assert.deepEqual(project(leftFollower), project(rightFollower));
    return {
      scope:
        'Two partitions of two replicas, real signed sync and receiver CID filtering; in-memory transport, no live GossipSub or compression negotiation.',
      metrics: {
        peers: 4,
        changesPerPartition,
        unknownChangesSelected: selected.length,
        serializedWireBytes: wire.byteLength,
        actualEncryptedFrameBytes: right.stats.lastFrame.byteLength,
        missingPayloadBytes,
        fullStateBytes,
        hypotheticalDeflateBytes: deflateRawSync(wire).byteLength,
        converged: true,
        ...measuredOnly(timing),
      },
      gaps: [
        'The receiver filters common CIDs after receiving the message. The sender still serializes common ancestry in the JSON sync envelope; compressed minimum-common-ancestor delta exchange is not established. The deflate figure is a comparison only, not a shipped codec.',
      ],
    };
  } finally {
    await Promise.all(fixtures.map((fixture) => fixture.close()));
    await nextTurn();
  }
}
