import type { Uint8ArrayList } from 'uint8arraylist';

const BUFFER_LIST_SYMBOL = Symbol.for('BufferList');

export interface BufferListLike {
  readonly length: number;
  slice(start?: number, end?: number): Uint8Array;
}

export function isBufferList(input: unknown): input is BufferListLike {
  const candidate = input as Record<PropertyKey, unknown>;
  return (
    typeof input === 'object' &&
    input !== null &&
    candidate[BUFFER_LIST_SYMBOL] === true &&
    typeof candidate.length === 'number' &&
    Number.isSafeInteger(candidate.length) &&
    candidate.length >= 0 &&
    typeof candidate.slice === 'function'
  );
}

function asBufferList(input: unknown): BufferListLike | undefined {
  return isBufferList(input) ? input : undefined;
}

const MAX_BOUNDED_STREAM_CHUNKS = 65_536;

function growStreamBuffer(
  assembled: Uint8Array,
  usedLength: number,
  requiredLength: number,
  maximumLength?: number,
): Uint8Array {
  if (requiredLength <= assembled.length) return assembled;
  const grownCapacity = Math.max(
    requiredLength,
    Math.max(1, assembled.length * 2),
  );
  const nextCapacity =
    maximumLength === undefined
      ? grownCapacity
      : Math.min(grownCapacity, maximumLength);
  const next = new Uint8Array(nextCapacity);
  next.set(assembled.subarray(0, usedLength));
  return next;
}

function appendStreamChunk(
  assembled: Uint8Array,
  offset: number,
  chunk: Uint8Array | Uint8ArrayList | BufferListLike,
): void {
  const bufferList = asBufferList(chunk);
  if (bufferList) {
    assembled.set(bufferList.slice(), offset);
  } else if (chunk instanceof Uint8Array) {
    assembled.set(chunk, offset);
  } else {
    assembled.set((chunk as Uint8ArrayList).subarray(), offset);
  }
}

export async function readUint8Iterable(
  iterable:
    | AsyncIterable<Uint8Array | Uint8ArrayList | BufferListLike>
    | Iterable<Uint8Array | Uint8ArrayList | BufferListLike>,
  maxSize?: number,
): Promise<Uint8Array> {
  let assembled: Uint8Array = new Uint8Array(0);
  let length = 0;
  let chunkCount = 0;
  for await (const chunk of iterable) {
    if (!chunk) continue;
    chunkCount++;
    if (maxSize !== undefined && chunkCount > MAX_BOUNDED_STREAM_CHUNKS) {
      throw new RangeError(
        `Stream exceeded maximum allowed chunk count of ${MAX_BOUNDED_STREAM_CHUNKS}`,
      );
    }
    if (chunk.length === 0) continue;
    const nextLength = length + chunk.length;
    if (maxSize !== undefined && nextLength > maxSize) {
      throw new RangeError(
        `Stream exceeded maximum allowed size of ${maxSize} bytes`,
      );
    }
    assembled = growStreamBuffer(assembled, length, nextLength, maxSize);
    appendStreamChunk(assembled, length, chunk);
    length = nextLength;
  }

  return length === assembled.byteLength
    ? assembled
    : assembled.slice(0, length);
}

/**
 * Read one serialized request without waiting for the remote write side to
 * close. Request/response protocols must be able to reply while the stream is
 * still writable; waiting for EOF can deadlock on relayed Yamux connections
 * where the half-close is delayed until the connection timeout.
 *
 * A serializer-provided completion detector permits fragmented requests to
 * finish on a half-open stream without repeatedly deserializing the growing
 * prefix. Without one, only the first chunk and the final EOF buffer are
 * decoded, which preserves bounded work for custom serializers.
 */
export async function readFirstDeserializable<T>(
  iterable: AsyncIterable<Uint8Array | Uint8ArrayList | BufferListLike>,
  deserialize: (data: Uint8Array) => T,
  maxSize?: number,
  completionDetector?: (chunk: Uint8Array) => boolean,
): Promise<T> {
  let assembled: Uint8Array = new Uint8Array(0);
  let length = 0;
  let chunkCount = 0;
  let lastAttemptLength = -1;
  let lastError: unknown = new Error(
    'Stream ended before a complete message arrived',
  );

  for await (const chunk of iterable) {
    if (!chunk) continue;
    chunkCount++;
    if (maxSize !== undefined && chunkCount > MAX_BOUNDED_STREAM_CHUNKS) {
      throw new RangeError(
        `Stream exceeded maximum allowed chunk count of ${MAX_BOUNDED_STREAM_CHUNKS}`,
      );
    }
    if (chunk.length === 0) continue;
    if (maxSize !== undefined && length + chunk.length > maxSize) {
      throw new RangeError(
        `Stream exceeded maximum allowed size of ${maxSize} bytes`,
      );
    }
    const bufferList = asBufferList(chunk);
    const bytes = bufferList
      ? new Uint8Array(bufferList.slice())
      : chunk instanceof Uint8Array
        ? chunk
        : (chunk as Uint8ArrayList).subarray();
    const nextLength = length + bytes.length;

    if (maxSize !== undefined && nextLength > maxSize) {
      throw new RangeError(
        `Stream exceeded maximum allowed size of ${maxSize} bytes`,
      );
    }

    assembled = growStreamBuffer(assembled, length, nextLength, maxSize);
    assembled.set(bytes, length);
    length = nextLength;

    if (completionDetector !== undefined) {
      if (completionDetector(bytes)) {
        return deserialize(assembled.subarray(0, length));
      }
    } else if (lastAttemptLength < 0) {
      // Preserve the common single-chunk/half-open path. Once the first
      // attempt proves incomplete, wait for EOF instead of reparsing every
      // attacker-controlled fragment.
      lastAttemptLength = length;
      try {
        return deserialize(assembled.subarray(0, length));
      } catch (error) {
        lastError = error;
      }
    }
  }

  if (length === 0 || lastAttemptLength === length) {
    throw lastError;
  }
  return deserialize(assembled.subarray(0, length));
}
