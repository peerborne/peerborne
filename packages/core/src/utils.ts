import BufferList from 'bl';
import type { Uint8ArrayList } from 'uint8arraylist';
import type { AesAlgorithmName } from './auth-provider.js';

/**
 * Outcome of parsing a path-prefixed protocol header off an inbound
 * stream. The wire format is:
 *
 *   [4-byte BE path length] [UTF-8 document path] [protocol body]
 *
 * Used by every shared protocol handler that routes by document path
 * (currently `documentKeyUpdateV2` and `beekemWelcomeV1`). Centralizing
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
 * handlers (BeeKEM Welcome v1, document key-update v2), then look up
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
  source: AsyncIterable<Uint8Array | Uint8ArrayList | BufferList>,
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
      console.warn(`Shared ${protocolName} handler: request too large, dropping`);
      return { kind: 'drop', reason: 'request-too-large' };
    }
    console.warn(`Shared ${protocolName} handler: failed to read request, dropping`);
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
      `Shared ${protocolName} handler: no document registered for "${documentPath}"`,
    );
    return { kind: 'drop', reason: 'no-document-registered' };
  }

  return { kind: 'ok', documentPath, doc, payload };
}

export function shuffleArray<T>(array: T[]) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

export function firstTrue(promises: Promise<boolean>[]) {
  const newPromises = promises.map(
    (p) =>
      new Promise<boolean>((resolve, reject) =>
        p.then((v) => v && resolve(true), reject),
      ),
  );
  newPromises.push(Promise.all(promises).then(() => false));
  return Promise.race(newPromises);
}

export function concatUint8Arrays(...arrs: Uint8Array[]): Uint8Array {
  const length = arrs.reduce((a, b) => a + b.length, 0);
  const newArr = new Uint8Array(length);
  let currentIndex = 0;
  for (const arr of arrs) {
    newArr.set(arr, currentIndex);
    currentIndex += arr.length;
  }
  return newArr;
}

export function isBufferList(input: Uint8Array | Uint8ArrayList | BufferList): input is BufferList {
  return input instanceof BufferList;
}

export async function readUint8Iterable(
  iterable:
    | AsyncIterable<Uint8Array | Uint8ArrayList | BufferList>
    | Iterable<Uint8Array | Uint8ArrayList | BufferList>,
  maxSize?: number,
): Promise<Uint8Array> {
  let length = 0;
  const chunks = [] as (Uint8Array | Uint8ArrayList | BufferList)[];
  for await (const chunk of iterable) {
    if (chunk) {
      chunks.push(chunk);
      length += chunk.length;
      if (maxSize !== undefined && length > maxSize) {
        throw new RangeError(
          `Stream exceeded maximum allowed size of ${maxSize} bytes`,
        );
      }
    }
  }

  let index = 0;
  const assembled = new Uint8Array(length);
  for (const chunk of chunks) {
    if (isBufferList(chunk)) {
      const bufferList = chunk as BufferList;
      for (let i = 0; i < bufferList.length; i++) {
        assembled.set([bufferList.readUInt8(i)], index + i);
      }
    } else if (chunk instanceof Uint8Array) {
      assembled.set(chunk, index);
    } else {
      // Uint8ArrayList -- use subarray() to get a contiguous Uint8Array
      assembled.set((chunk as Uint8ArrayList).subarray(), index);
    }
    index += chunk.length;
  }

  return assembled;
}

/**
 * Read one serialized request without waiting for the remote write side to
 * close. Request/response protocols must be able to reply while the stream is
 * still writable; waiting for EOF can deadlock on relayed Yamux connections
 * where the half-close is delayed until the connection timeout.
 *
 * The deserializer doubles as the message-completeness check. A fragmented
 * request keeps accumulating until it can be decoded, while malformed or
 * oversized input still fails once the source ends or crosses `maxSize`.
 */
export async function readFirstDeserializable<T>(
  iterable: AsyncIterable<Uint8Array | Uint8ArrayList | BufferList>,
  deserialize: (data: Uint8Array) => T,
  maxSize?: number,
): Promise<T> {
  let assembled = new Uint8Array(0);
  let length = 0;
  let lastError: unknown = new Error('Stream ended before a complete message arrived');

  for await (const chunk of iterable) {
    if (!chunk) continue;
    if (maxSize !== undefined && length + chunk.length > maxSize) {
      throw new RangeError(
        `Stream exceeded maximum allowed size of ${maxSize} bytes`,
      );
    }
    const bytes = isBufferList(chunk)
      ? new Uint8Array(chunk.slice())
      : chunk instanceof Uint8Array
        ? chunk
        : chunk.subarray();
    const nextLength = length + bytes.length;

    if (maxSize !== undefined && nextLength > maxSize) {
      throw new RangeError(
        `Stream exceeded maximum allowed size of ${maxSize} bytes`,
      );
    }

    if (nextLength > assembled.length) {
      const grownCapacity = Math.max(
        nextLength,
        Math.max(1, assembled.length * 2),
      );
      const nextCapacity = maxSize === undefined
        ? grownCapacity
        : Math.min(grownCapacity, maxSize);
      const next = new Uint8Array(nextCapacity);
      next.set(assembled.subarray(0, length));
      assembled = next;
    }
    assembled.set(bytes, length);
    length = nextLength;

    try {
      return deserialize(assembled.subarray(0, length));
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError;
}

// CryptoKey utils

export async function generateAndExportHmacKey() {
  const key = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    },
    true,
    ['sign', 'verify'],
  );
  return [
    await crypto.subtle.exportKey('jwk', key.privateKey),
    await crypto.subtle.exportKey('jwk', key.publicKey),
  ];
}

export async function importHmacKey(
  keyData: Uint8Array,
  format: Exclude<KeyFormat, 'jwk'> = 'raw',
  hash = 'SHA-512',
) {
  // Cast needed: Uint8Array<ArrayBufferLike> does not satisfy BufferSource (excludes SharedArrayBuffer)
  const key = await crypto.subtle.importKey(
    format,
    keyData as Uint8Array<ArrayBuffer>,
    {
      name: 'HMAC',
      hash,
    },
    true,
    ['sign', 'verify'],
  );

  return key;
}

export async function importSymmetricKey(
  keyData: Uint8Array,
  format: Exclude<KeyFormat, 'jwk'> = 'raw',
  algorithmName: AesAlgorithmName = 'AES-GCM',
) {
  // Cast needed: Uint8Array<ArrayBufferLike> does not satisfy BufferSource (excludes SharedArrayBuffer)
  const key = await crypto.subtle.importKey(format, keyData as Uint8Array<ArrayBuffer>, algorithmName, true, [
    'encrypt',
    'decrypt',
  ]);

  return key;
}

export async function generateAndExportSymmetricKey(
  algorithmName: AesAlgorithmName = 'AES-GCM',
) {
  const documentKey = await crypto.subtle.generateKey(
    {
      name: algorithmName,
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  );
  return await crypto.subtle.exportKey('jwk', documentKey);
}
