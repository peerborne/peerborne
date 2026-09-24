import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore } from 'datastore-idb';
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

test('Helia preserves and extends blocks and pins across store reopen', async () => {
  const blockLocation = '/peerborne-blocks-reopen-test';
  const dataLocation = '/peerborne-data-reopen-test';
  const firstBlockstore = new IDBBlockstore(blockLocation);
  const firstDatastore = new IDBDatastore(dataLocation);
  const secondBlockstore = new IDBBlockstore(blockLocation);
  const secondDatastore = new IDBDatastore(dataLocation);
  const reopenedBlockstore = new IDBBlockstore(blockLocation);
  const reopenedDatastore = new IDBDatastore(dataLocation);
  const first = new TextEncoder().encode(
    'written and pinned in the first session',
  );
  const second = new TextEncoder().encode(
    'written and pinned in the second session',
  );
  const firstCid = await blockCid(first);
  const secondCid = await blockCid(second);
  let firstHelia;
  let secondHelia;
  let reopenedHelia;

  try {
    await firstBlockstore.open();
    await firstDatastore.open();
    firstHelia = createHeliaLight({
      blockstore: firstBlockstore,
      datastore: firstDatastore,
    });
    await firstHelia.start();
    await firstHelia.blockstore.put(firstCid, first);
    assert.equal(
      await drain(
        firstHelia.pins.add(firstCid, {
          depth: 0,
          metadata: { writer: 'first-session' },
        }),
      ),
      1,
    );
    await firstHelia.stop();
    firstHelia = undefined;
    await firstBlockstore.close();
    await firstDatastore.close();

    await secondBlockstore.open();
    await secondDatastore.open();
    secondHelia = createHeliaLight({
      blockstore: secondBlockstore,
      datastore: secondDatastore,
    });
    await secondHelia.start();
    assert.deepEqual(
      await collect(secondHelia.blockstore.get(firstCid)),
      first,
    );
    assert.equal(await secondHelia.pins.isPinned(firstCid), true);
    assert.deepEqual(await secondHelia.pins.get(firstCid), {
      depth: 0,
      metadata: { writer: 'first-session' },
    });
    await secondHelia.blockstore.put(secondCid, second);
    assert.equal(
      await drain(
        secondHelia.pins.add(secondCid, {
          depth: 0,
          metadata: { writer: 'second-session' },
        }),
      ),
      1,
    );
    await secondHelia.stop();
    secondHelia = undefined;
    await secondBlockstore.close();
    await secondDatastore.close();

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
    await firstHelia?.stop().catch(() => {});
    await secondHelia?.stop().catch(() => {});
    await reopenedHelia?.stop().catch(() => {});
    await firstBlockstore.close().catch(() => {});
    await firstDatastore.close().catch(() => {});
    await secondBlockstore.close().catch(() => {});
    await secondDatastore.close().catch(() => {});
    await reopenedBlockstore.close().catch(() => {});
    await reopenedDatastore.close().catch(() => {});
    await reopenedBlockstore.destroy().catch(() => {});
    await reopenedDatastore.destroy().catch(() => {});
  }
});
