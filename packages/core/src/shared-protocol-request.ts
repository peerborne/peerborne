import type { Uint8ArrayList } from 'uint8arraylist';
import {
  type BufferListLike,
  readUint8Iterable,
} from './internal/stream-read.js';

/** Maximum document path length in path-prefixed shared protocol headers. */
export const MAX_DOCUMENT_PATH_LENGTH = 4096;

/** Maximum complete request accepted by shared protocol handlers. */
export const MAX_SHARED_PROTOCOL_REQUEST_BYTES = 10 * 1024 * 1024;

/** Reject an outbound frame that the matching inbound handler cannot read. */
export function assertSharedProtocolRequestSize(
  byteLength: number,
  context = 'Shared protocol request',
): void {
  if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
    throw new RangeError(`${context} has an invalid byte length`);
  }
  if (byteLength > MAX_SHARED_PROTOCOL_REQUEST_BYTES) {
    throw new RangeError(
      `${context} exceeds ${MAX_SHARED_PROTOCOL_REQUEST_BYTES} bytes`,
    );
  }
}

/**
 * Outcome of parsing a path-prefixed protocol header off an inbound
 * stream. The wire format is:
 *
 *   [4-byte BE path length] [UTF-8 document path] [protocol body]
 *
 * Used by every shared protocol handler that routes by document path
 * (BeeKEM Welcome and PathUpdate V2). Centralizing
 * the parse here keeps the validation limits (`maxRequestSize`,
 * `maxPathLength`), the unsigned-32-bit length decode, and the
 * registry-lookup behavior consistent across protocols so the two
 * handlers cannot drift on subtle bounds/encoding rules.
 */
export type PathPrefixedHeader<TDocument> =
  | {
      kind: 'ok';
      /** Decoded UTF-8 document path. */
      documentPath: string;
      /** Registry entry the path resolved to. */
      doc: TDocument;
      /** Remaining bytes after the path header (the protocol body). */
      payload: Uint8Array;
    }
  | { kind: 'drop'; reason: PathPrefixedHeaderDropReason };

export type PathPrefixedHeaderDropReason =
  | 'request-too-large'
  | 'read-failed'
  | 'too-short'
  | 'invalid-path-length'
  | 'no-document-registered';

/**
 * Read and parse the path-prefixed header used by shared protocol
 * handlers (BeeKEM Welcome V2 and PathUpdate V2), then look up
 * the document in the supplied registry.
 *
 * On any malformed input -- oversized request, short read, invalid
 * length header, unknown document path -- this logs a warning prefixed
 * with `protocolName` and returns a `drop` result. Callers should
 * still close their stream/cleanup in their own `finally` block; this
 * helper is intentionally side-effect-free w.r.t. the stream.
 *
 * Centralizing this logic keeps the per-protocol handlers focused on
 * their post-header behavior (e.g. dispatching to the right
 * `PeerborneDocument` method) while ensuring a single source of
 * truth for the validation bounds.
 *
 * @param source     The libp2p stream's async source iterable.
 * @param registry   Map of document path -> document instance.
 * @param protocolName Human-readable label for log messages (e.g.
 *   `'beekem-welcome'`).
 * @param maxRequestSize Maximum total inbound payload bytes.
 * @param maxPathLength Maximum encoded UTF-8 path length in bytes (i.e.
 *   the value of the 4-byte length prefix), not the decoded character
 *   count. The path is byte-sliced out of `assembled` using this value.
 */
export async function readPathPrefixedProtocolHeader<TDocument>(
  source: AsyncIterable<Uint8Array | Uint8ArrayList | BufferListLike>,
  registry: { get(key: string): TDocument | undefined },
  protocolName: string,
  maxRequestSize: number,
  maxPathLength: number,
): Promise<PathPrefixedHeader<TDocument>> {
  let assembled: Uint8Array;
  try {
    assembled = await readUint8Iterable(source, maxRequestSize);
  } catch (err) {
    if (err instanceof RangeError) {
      console.warn(
        `Shared ${protocolName} handler: request too large, dropping`,
      );
      return { kind: 'drop', reason: 'request-too-large' };
    }
    console.warn(
      `Shared ${protocolName} handler: failed to read request, dropping`,
    );
    return { kind: 'drop', reason: 'read-failed' };
  }

  if (assembled.length < 4) {
    console.warn(`Shared ${protocolName} handler: message too short`);
    return { kind: 'drop', reason: 'too-short' };
  }

  // Unsigned right shift (>>> 0) so the path length is interpreted as
  // an unsigned 32-bit integer even when bit 31 is set.
  const pathLength =
    ((assembled[0] << 24) |
      (assembled[1] << 16) |
      (assembled[2] << 8) |
      assembled[3]) >>>
    0;

  if (
    pathLength === 0 ||
    pathLength > maxPathLength ||
    pathLength + 4 > assembled.length
  ) {
    console.warn(
      `Shared ${protocolName} handler: invalid path header (pathLength=` +
        pathLength +
        '), dropping message',
    );
    return { kind: 'drop', reason: 'invalid-path-length' };
  }

  const documentPath = new TextDecoder().decode(
    assembled.slice(4, 4 + pathLength),
  );
  const payload = assembled.slice(4 + pathLength);
  const doc = registry.get(documentPath);
  if (!doc) {
    console.warn(
      `Shared ${protocolName} handler: no document registered, dropping`,
    );
    return { kind: 'drop', reason: 'no-document-registered' };
  }

  return { kind: 'ok', documentPath, doc, payload };
}
