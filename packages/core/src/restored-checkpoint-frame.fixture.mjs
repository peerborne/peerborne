import assert from 'node:assert/strict';
import test from 'node:test';
import { isDeepStrictEqual } from 'node:util';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import {
  MAX_CHANGE_FRAME_BYTES,
  MAX_GOSSIP_SYNC_MESSAGE_BYTES,
} from '@peerborne/core';
import {
  documentFixture,
  project,
  publishedMessage,
  receiveEncrypted,
  replicaOf,
  syntheticText,
} from '../../../verification/fixtures.mjs';

const path = '/restored-checkpoint-frame';

// Each value fits one frame; together their snapshot and the retained tree
// exceed a frame.
const valueLength = { automerge: 1_000_000, yjs: 800_000, loro: 700_000 };

function edit(target, adapter, key, value) {
  return target.document.change(
    adapter === 'automerge'
      ? (doc) => {
          doc.root ??= {};
          doc.root[key] = value;
        }
      : (doc) => doc.getMap('root').set(key, value),
  );
}

function rootOf(target, adapter) {
  return adapter === 'automerge'
    ? (project(target).root ?? {})
    : target.document.document.getMap('root').toJSON();
}

for (const adapter of ['automerge', 'yjs', 'loro']) {
  test(`${adapter}: an edit after restoring a checkpoint with a large snapshot publishes a small frame a replica applies`, async (t) => {
    t.mock.method(console, 'log', () => {});
    const options = {
      adapter,
      path,
      blockstore: new MemoryBlockstore(),
      datastore: new MemoryDatastore(),
    };
    const writer = await documentFixture({ ...options, index: 1 });
    await edit(writer, adapter, 'a', 1);
    const replica = await replicaOf(writer, 2, { adapter });
    for (let index = 0; index < 3; index++) {
      await edit(
        writer,
        adapter,
        `big${index}`,
        syntheticText(valueLength[adapter], 10 + index),
      );
      assert.equal(
        await receiveEncrypted(replica, writer.stats.lastFrame),
        true,
      );
    }
    const snapshot = writer.document.latestSnapshot;
    assert.ok(snapshot);
    assert.ok(
      writer.serializer.serializeSyncMessage({
        ...writer.document._lastSyncMessage,
        snapshot,
      }).byteLength > MAX_GOSSIP_SYNC_MESSAGE_BYTES,
    );
    const checkpoint = await writer.document.exportCheckpoint();
    await writer.close();

    const restored = await documentFixture({
      ...options,
      index: 3,
      identity: writer.identity,
      open: false,
    });
    await restored.document.restoreCheckpoint(checkpoint);
    await restored.document.open();
    assert.equal(
      restored.document.latestSnapshot.lastChangeNodeCID,
      snapshot.lastChangeNodeCID,
    );

    for (const [key, value] of [
      ['small', 1],
      ['next', 2],
    ]) {
      await edit(restored, adapter, key, value);
      assert.ok(restored.stats.lastFrame.byteLength < MAX_CHANGE_FRAME_BYTES);
      assert.ok((await publishedMessage(restored)).snapshot === undefined);
      assert.equal(
        await receiveEncrypted(replica, restored.stats.lastFrame),
        true,
      );
      assert.equal(rootOf(replica, adapter)[key], value);
    }
    assert.ok(
      isDeepStrictEqual(rootOf(replica, adapter), rootOf(restored, adapter)),
    );
    await Promise.all([restored.close(), replica.close()]);
  });
}
