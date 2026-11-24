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

test('the writer does not persist a ciphertext file larger than the reader can open', async () => {
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
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
