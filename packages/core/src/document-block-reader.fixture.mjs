import assert from 'node:assert/strict';
import test from 'node:test';
import { unixfs } from '@helia/unixfs';
import { MemoryBlockstore } from 'blockstore-core';
import fc from 'fast-check';
import { CID } from 'multiformats/cid';
import * as raw from 'multiformats/codecs/raw';
import { sha256 } from 'multiformats/hashes/sha2';
import { SubtleCrypto } from './auth-subtlecrypto.ts';
import {
  DocumentBlockReadLimitError,
  MAX_DOCUMENT_BLOCK_BYTES,
  readDocumentBlock,
} from './document-block-reader.ts';
import { PeerborneDocument } from './peerborne-document.ts';

function chunkAt(width) {
  return async function* (source) {
    for await (const bytes of source) {
      for (let offset = 0; offset < bytes.length; offset += width) {
        yield bytes.subarray(offset, offset + width);
      }
    }
  };
}

async function unixfsFile(bytes, width) {
  const blockstore = new MemoryBlockstore();
  const hash = await unixfs({ blockstore }).addBytes(bytes, {
    chunker: chunkAt(width),
  });
  assert.notEqual(hash.code, raw.code);
  return { blockstore, hash };
}

function readOnlyStore(blockstore, get) {
  return {
    get,
    has: blockstore.has.bind(blockstore),
    put() {
      assert.fail('Document read tried to persist a block');
    },
  };
}

function rejectionOnlyDocument(blockstore) {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    swarm: { heliaNode: { blockstore } },
    _decodeBlock() {
      assert.fail('Rejected UnixFS input reached decryption');
    },
  });
}

test('the document reader reconstructs native UnixFS ciphertext and authenticates before decoding', async () => {
  const generateKey = () => crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  const [key, otherKey] = await Promise.all([generateKey(), generateKey()]);
  const auth = new SubtleCrypto();
  const keyId = new Uint8Array(32).fill(3);
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 20, maxLength: 4096 }),
      fc.integer({ min: 32, max: 1000 }),
      fc.boolean(),
      async (payload, width, shouldChunk) => {
        const blockstore = new MemoryBlockstore();
        const fs = unixfs({ blockstore });
        const storedLength = keyId.length + auth.nonceBytes + payload.length + 16;
        let decodes = 0;
        let received = 0;
        const readStore = {
          has: blockstore.has.bind(blockstore),
          put: blockstore.put.bind(blockstore),
          async *get(cid, options) {
            for await (const chunk of blockstore.get(cid, options)) {
              received += chunk.byteLength;
              yield chunk;
            }
          },
        };
        const document = Object.assign(Object.create(PeerborneDocument.prototype), {
          documentPath: '/block-reader',
          swarm: { heliaNode: { blockstore: readStore } },
          heliaFs: {
            addBytes: (bytes) => fs.addBytes(bytes, {
              chunker: chunkAt(shouldChunk ? Math.min(width, storedLength - 1) : storedLength),
            }),
          },
          _authProvider: auth,
          _keychain: { current: async () => [keyId, key] },
          _keychainProvider: { keyIDLength: keyId.length },
          _changesSerializer: {
            serializeChanges: (bytes) => bytes,
            deserializeChanges: (bytes) => {
              decodes++;
              return bytes;
            },
          },
        });
        const hash = CID.parse(await document._putBlock(payload));
        assert.equal(hash.code === raw.code, !shouldChunk);
        const lookup = (id) => {
          assert.deepEqual(id, keyId);
          return key;
        };
        let charged = 0;
        const output = await document._getBlock(hash, {
          maxBlockBytes: storedLength,
          consumeBytes: (bytes) => { charged += bytes; },
        }, lookup);
        assert.deepEqual(output, payload);
        assert.equal(charged, received);
        assert.equal(charged > storedLength, shouldChunk);
        assert.equal(decodes, 1);

        await assert.rejects(
          document._getBlock(hash, { maxBlockBytes: storedLength - 1 }, lookup),
          DocumentBlockReadLimitError,
        );
        await assert.rejects(
          document._getBlock(hash, undefined, () => otherKey),
          /Failed to decrypt block/,
        );
        const otherDocument = Object.assign(
          Object.create(PeerborneDocument.prototype),
          document,
          { documentPath: '/other-block-reader' },
        );
        await assert.rejects(
          otherDocument._getBlock(hash, undefined, lookup),
          /Failed to decrypt block/,
        );
        assert.equal(decodes, 1);
        const earlierLoadBytes = 17;
        let aggregate = earlierLoadBytes;
        await assert.rejects(document._getBlock(hash, {
          consumeBytes: (bytes) => {
            if (bytes > earlierLoadBytes + storedLength - 1 - aggregate) {
              throw new DocumentBlockReadLimitError('Shared load budget exhausted');
            }
            aggregate += bytes;
          },
        }, lookup), /Shared load budget exhausted/);
        assert.ok(aggregate < earlierLoadBytes + storedLength);
        assert.equal(decodes, 1);
      },
    ),
    { seed: 832003, numRuns: 40 },
  );
});

test('a cancelled document read stops consuming fragments and never reaches decryption', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 2, max: 40 }),
      fc.integer({ min: 1, max: 20 }),
      async (fragments, requestedCutoff) => {
        const cutoff = Math.min(fragments, requestedCutoff);
        const bytes = new Uint8Array(fragments).fill(8);
        const hash = CID.createV1(raw.code, await sha256.digest(bytes));
        const controller = new AbortController();
        const cancelled = new Error('Stopped loading fixture');
        let charged = 0;
        let returned = 0;
        let observedSignal;
        let closeSource;
        const closed = new Promise((resolve) => { closeSource = resolve; });
        const document = Object.assign(Object.create(PeerborneDocument.prototype), {
          swarm: { heliaNode: { blockstore: {
            async *get(_hash, { signal }) {
              observedSignal = signal;
              try {
                for (let index = 0; index < fragments; index++) {
                  returned++;
                  yield bytes.subarray(index, index + 1);
                }
              } finally {
                closeSource();
              }
            },
          } } },
          _decodeBlock() { assert.fail('Aborted input was decoded'); },
        });
        await assert.rejects(
          document._getBlock(hash, {
            signal: controller.signal,
            consumeBytes: (length) => {
              charged += length;
              if (charged === cutoff) controller.abort(cancelled);
            },
          }),
          { message: cancelled.message },
        );
        await closed;
        assert.equal(returned, cutoff);
        assert.equal(charged, cutoff);
        assert.equal(observedSignal.aborted, true);
      },
    ),
    { seed: 832007, numRuns: 40 },
  );
});

test('empty fragments consume the same chunk budget as nonempty fragments', async () => {
  const bytes = new Uint8Array([5]);
  const hash = CID.createV1(raw.code, await sha256.digest(bytes));
  const source = (emptyCount) => ({
    async *get() {
      const empty = new Uint8Array();
      for (let index = 0; index < emptyCount; index++) yield empty;
      yield bytes;
    },
  });
  assert.deepEqual(await readDocumentBlock(source(65_535), hash), bytes);
  await assert.rejects(
    readDocumentBlock(source(65_536), hash),
    DocumentBlockReadLimitError,
  );
});

test('UnixFS traversal admits the exact physical byte limit before checking logical output', async () => {
  const leafBytes = 8 * 1024 * 1024;
  const bytes = new Uint8Array(leafBytes + 1);
  bytes[leafBytes] = 1;
  const { blockstore, hash } = await unixfsFile(bytes, leafBytes);
  let rootBytes = 0;
  for await (const chunk of blockstore.get(hash)) rootBytes += chunk.length;

  for (const limitReduction of [0, 1]) {
    const seen = [];
    let admitted = 0;
    const document = rejectionOnlyDocument(
      readOnlyStore(blockstore, async function* (cid, options) {
        seen.push(cid);
        yield* blockstore.get(cid, options);
      }),
    );
    const budget = limitReduction === 0 ? 'output' : 'traversal input';
    await assert.rejects(
      document._getBlock(hash, {
        maxBlockBytes: rootBytes - limitReduction,
        consumeBytes: (length) => {
          admitted += length;
        },
      }),
      (error) =>
        error instanceof DocumentBlockReadLimitError &&
        error.message.includes(`${budget} budget exceeded`),
    );
    assert.ok(seen[0].equals(hash));
    if (limitReduction === 0) {
      // The exporter can start the next child before yielding the first.
      assert.ok(seen.length <= 3);
    } else {
      assert.equal(seen.length, 2);
    }
    assert.equal(admitted, rootBytes + (limitReduction === 0 ? leafBytes : 0));
  }
});

test('UnixFS traversal counts physical segments across metadata and child reads', async () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const { blockstore, hash } = await unixfsFile(bytes, 3);
  const segmentBudget = 65_536;
  for (const excess of [0, 1]) {
    let reads = 0;
    let emitted = 0;
    let admitted = 0;
    const store = readOnlyStore(blockstore, async function* (cid, options) {
      reads++;
      if (cid.equals(hash)) {
        const empty = new Uint8Array();
        const emptyCount = segmentBudget - 3 + excess; // Root and two raw children.
        for (let index = 0; index < emptyCount; index++) {
          emitted++;
          yield empty;
        }
      }
      for await (const chunk of blockstore.get(cid, options)) {
        emitted++;
        yield chunk;
      }
    });
    const readOptions = {
      maxBlockBytes: bytes.length,
      consumeBytes: () => {
        admitted++;
      },
    };
    if (excess === 0) {
      assert.deepEqual(await readDocumentBlock(store, hash, readOptions), bytes);
    } else {
      await assert.rejects(
        rejectionOnlyDocument(store)._getBlock(hash, readOptions),
        /UnixFS traversal input budget exceeded/,
      );
    }
    assert.equal(admitted, segmentBudget);
    assert.equal(emitted, segmentBudget + excess);
    assert.equal(reads, 3);
  }
});

test('UnixFS cancellation closes an in-flight child before opening its siblings', async () => {
  const { blockstore, hash } = await unixfsFile(
    new Uint8Array([1, 2, 3, 4, 5]),
    3,
  );
  const seen = [];
  let childSignal;
  let childStarted;
  let childClosed;
  const started = new Promise((resolve) => {
    childStarted = resolve;
  });
  const closed = new Promise((resolve) => {
    childClosed = resolve;
  });
  const document = rejectionOnlyDocument(
    readOnlyStore(blockstore, async function* (cid, { signal }) {
      seen.push(cid);
      if (!cid.equals(hash)) {
        childSignal = signal;
        try {
          await new Promise((_resolve, reject) => {
            signal.throwIfAborted();
            signal.addEventListener('abort', () => reject(signal.reason), {
              once: true,
            });
            childStarted();
          });
        } finally {
          childClosed();
        }
      }
      yield* blockstore.get(cid, { signal });
    }),
  );
  const controller = new AbortController();
  const cancelled = new Error('Stopped reading encrypted history');
  const read = document._getBlock(hash, { signal: controller.signal });
  await Promise.race([
    started,
    read.then(() => assert.fail('The deferred child was not fetched')),
  ]);
  controller.abort(cancelled);
  await assert.rejects(read, { message: cancelled.message });
  await closed;
  assert.equal(seen.length, 2);
  assert.ok(seen[0].equals(hash));
  assert.ok(!seen[1].equals(hash));
  assert.equal(childSignal.reason, cancelled);
});

test('the writer does not persist a ciphertext file larger than the reader can open', async () => {
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/oversized',
    _keychain: { current: async () => [new Uint8Array(32), {}] },
    _changesSerializer: { serializeChanges: (bytes) => bytes },
    _authProvider: {
      encrypt: async () => ({
        data: new Uint8Array(MAX_DOCUMENT_BLOCK_BYTES - 32 - 12 + 1),
        nonce: new Uint8Array(12),
      }),
    },
    heliaFs: { addBytes() { assert.fail('Oversized ciphertext was persisted'); } },
  });
  await assert.rejects(
    document._putBlock(new Uint8Array([2])),
    DocumentBlockReadLimitError,
  );
});
