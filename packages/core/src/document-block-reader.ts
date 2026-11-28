import { unixfs } from '@helia/unixfs';
import type { CID } from 'multiformats';
import { assertPositiveSafeByteLimit } from './internal/byte-limits.js';
import { concatenate } from './internal/canonical-encoding.js';
import { canReserveDocumentOperation } from './policy/document-admission.js';
import { readUint8Iterable } from './utils.js';

type DocumentBlockstore = Parameters<typeof unixfs>[0]['blockstore'];

export const MAX_DOCUMENT_BLOCK_BYTES = 64 * 1024 * 1024;
const MAX_BLOCK_CHUNKS = 65_536;
const UNIXFS_METADATA_ALLOWANCE = 8 * 1024 * 1024;
const DAG_PB_CODEC = 0x70;

export class DocumentBlockReadLimitError extends RangeError {}

export interface DocumentBlockReadOptions {
  readonly signal?: AbortSignal;
  readonly maxBlockBytes?: number;
  readonly consumeBytes?: (byteLength: number) => void;
}

function blockBudget(byteLimit: number, description: string) {
  let count = 0;
  let bytes = 0;
  return (length: number): void => {
    if (
      !canReserveDocumentOperation(count, bytes, length, MAX_BLOCK_CHUNKS, byteLimit)
    ) {
      throw new DocumentBlockReadLimitError(`${description} budget exceeded`);
    }
    count++;
    bytes += length;
  };
}

/** @internal Assemble chunks already admitted by the block budget. */
export async function assembleUnixFSOutput(
  chunks: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const chunk of chunks) {
    if (chunk.byteLength > 0) parts.push(new Uint8Array(chunk));
  }
  signal?.throwIfAborted();
  return parts.length === 1 ? parts[0]! : concatenate(parts);
}

/** Read the same logical file that UnixFS addBytes wrote. */
export async function readDocumentBlock(
  blockstore: DocumentBlockstore,
  hash: CID,
  options: DocumentBlockReadOptions = {},
): Promise<Uint8Array> {
  const maxBytes = Math.min(
    MAX_DOCUMENT_BLOCK_BYTES,
    options.maxBlockBytes === undefined
      ? MAX_DOCUMENT_BLOCK_BYTES
      : assertPositiveSafeByteLimit(options.maxBlockBytes, 'Document block byte limit'),
  );
  const controller = new AbortController();
  const signal = controller.signal;
  const cancel = () => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) cancel();
  else options.signal?.addEventListener('abort', cancel, { once: true });

  const acceptOutput = blockBudget(maxBytes, 'Document block output');
  async function* checkOutput(
    source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
    consumeBytes?: DocumentBlockReadOptions['consumeBytes'],
  ) {
    for await (const chunk of source) {
      signal.throwIfAborted();
      acceptOutput(chunk.byteLength);
      consumeBytes?.(chunk.byteLength);
      signal.throwIfAborted();
      yield chunk;
    }
  }

  try {
    signal.throwIfAborted();
    if (hash.code !== DAG_PB_CODEC) {
      return await readUint8Iterable(
        checkOutput(blockstore.get(hash, { signal }), options.consumeBytes),
        maxBytes,
      );
    }

    // Bound input independently from output. The exporter may read metadata
    // and child blocks before yielding the file's ciphertext.
    const reserveBlock = blockBudget(0, 'UnixFS traversal block');
    const acceptInput = blockBudget(
      maxBytes + UNIXFS_METADATA_ALLOWANCE,
      'UnixFS traversal input',
    );
    const get: DocumentBlockstore['get'] = async function* (cid, settings) {
      try {
        signal.throwIfAborted();
        reserveBlock(0);
        for await (const chunk of blockstore.get(cid, { ...settings, signal })) {
          signal.throwIfAborted();
          acceptInput(chunk.byteLength);
          options.consumeBytes?.(chunk.byteLength);
          signal.throwIfAborted();
          yield chunk;
        }
      } catch (error) {
        controller.abort(error);
        throw error;
      }
    };
    const fs = unixfs({
      blockstore: {
        get,
        has: blockstore.has.bind(blockstore),
        put: blockstore.put.bind(blockstore),
      },
    });
    const catOptions = { signal, blockReadConcurrency: 1 };
    return await assembleUnixFSOutput(
      checkOutput(fs.cat(hash, catOptions)),
      signal,
    );
  } finally {
    // Returning the iterator does not necessarily stop the exporter’s work.
    controller.abort();
    options.signal?.removeEventListener('abort', cancel);
  }
}
