import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import { IDBBlockstore as LegacyBlockstore } from 'blockstore-idb-v3';
import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore as LegacyDatastore } from 'datastore-idb-v4';
import { IDBDatastore } from 'datastore-idb';
import { createHelia as createLegacyHelia } from 'helia-v6';
import { createHeliaLight } from 'helia';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

async function collect(source) {
  const chunks = [];
  let length = 0;
  for await (const chunk of source) {
    chunks.push(chunk);
    length += chunk.length;
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

async function blockCid(bytes) {
  return CID.createV1(0x55, await sha256.digest(bytes));
}

async function drain(source) {
  let count = 0;
  for await (const value of source) {
    assert.ok(value);
    count++;
  }
  return count;
}

test('Helia 7 reads and extends blocks and pins written by Helia 6', async () => {
  const blockLocation = '/collabswarm-blocks-migration-test';
  const dataLocation = '/collabswarm-data-migration-test';
  const legacyBlockstore = new LegacyBlockstore(blockLocation);
  const legacyDatastore = new LegacyDatastore(dataLocation);
  const upgradedBlockstore = new IDBBlockstore(blockLocation);
  const upgradedDatastore = new IDBDatastore(dataLocation);
  const reopenedBlockstore = new IDBBlockstore(blockLocation);
  const reopenedDatastore = new IDBDatastore(dataLocation);
  const first = new TextEncoder().encode('written and pinned by Helia 6');
  const second = new TextEncoder().encode('written and pinned by Helia 7');
  const firstCid = await blockCid(first);
  const secondCid = await blockCid(second);
  let legacyHelia;
  let upgradedHelia;
  let reopenedHelia;

  try {
    await legacyBlockstore.open();
    await legacyDatastore.open();
    legacyHelia = await createLegacyHelia({
      blockstore: legacyBlockstore,
      datastore: legacyDatastore,
      blockBrokers: [],
      routers: [],
      start: false,
    });
    await legacyHelia.blockstore.put(firstCid, first);
    assert.equal(
      await drain(legacyHelia.pins.add(firstCid, {
        depth: 0,
        metadata: { writer: 'helia-6' },
      })),
      1,
    );
    await legacyHelia.stop();
    legacyHelia = undefined;
    await legacyBlockstore.close();
    await legacyDatastore.close();

    await upgradedBlockstore.open();
    await upgradedDatastore.open();
    upgradedHelia = createHeliaLight({
      blockstore: upgradedBlockstore,
      datastore: upgradedDatastore,
    });
    await upgradedHelia.start();
    assert.deepEqual(
      await collect(upgradedHelia.blockstore.get(firstCid)),
      first,
    );
    assert.equal(await upgradedHelia.pins.isPinned(firstCid), true);
    assert.deepEqual(await upgradedHelia.pins.get(firstCid), {
      depth: 0,
      metadata: { writer: 'helia-6' },
    });
    await upgradedHelia.blockstore.put(secondCid, second);
    assert.equal(
      await drain(upgradedHelia.pins.add(secondCid, {
        depth: 0,
        metadata: { writer: 'helia-7' },
      })),
      1,
    );
    await upgradedHelia.stop();
    upgradedHelia = undefined;
    await upgradedBlockstore.close();
    await upgradedDatastore.close();

    await reopenedBlockstore.open();
    await reopenedDatastore.open();
    reopenedHelia = createHeliaLight({
      blockstore: reopenedBlockstore,
      datastore: reopenedDatastore,
    });
    await reopenedHelia.start();
    assert.deepEqual(
      await collect(reopenedHelia.blockstore.get(firstCid)),
      first,
    );
    assert.deepEqual(
      await collect(reopenedHelia.blockstore.get(secondCid)),
      second,
    );
    assert.equal(await reopenedHelia.pins.isPinned(firstCid), true);
    assert.equal(await reopenedHelia.pins.isPinned(secondCid), true);
  } finally {
    await legacyHelia?.stop().catch(() => {});
    await upgradedHelia?.stop().catch(() => {});
    await reopenedHelia?.stop().catch(() => {});
    await legacyBlockstore.close().catch(() => {});
    await legacyDatastore.close().catch(() => {});
    await upgradedBlockstore.close().catch(() => {});
    await upgradedDatastore.close().catch(() => {});
    await reopenedBlockstore.close().catch(() => {});
    await reopenedDatastore.close().catch(() => {});
    await reopenedBlockstore.destroy().catch(() => {});
    await reopenedDatastore.destroy().catch(() => {});
  }
});
