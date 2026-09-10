import type { Uint8ArrayList } from 'uint8arraylist';
import type { AesAlgorithmName } from './auth-provider.js';

const BUFFER_LIST_SYMBOL = Symbol.for('BufferList');

export interface BufferListLike {
  readonly length: number;
  slice(start?: number, end?: number): Uint8Array;
}

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

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)?.get;
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const typedArrayTagGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const uint8ArraySet = Uint8Array.prototype.set;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const intrinsicStructuredClone = globalThis.structuredClone;
const cryptoKeyTypeGetter =
  typeof CryptoKey === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(CryptoKey.prototype, 'type')?.get;
const sharedArrayBufferByteLengthGetter =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'byteLength')
        ?.get;

if (
  typedArrayByteLengthGetter === undefined ||
  typedArrayBufferGetter === undefined ||
  typedArrayTagGetter === undefined
) {
  throw new Error('Uint8Array intrinsic accessors are unavailable');
}
const intrinsicTypedArrayByteLengthGetter = typedArrayByteLengthGetter;
const intrinsicTypedArrayBufferGetter = typedArrayBufferGetter;
const intrinsicTypedArrayTagGetter = typedArrayTagGetter;

/**
 * Outcome of parsing a path-prefixed protocol header off an inbound
 * stream. The wire format is:
 *
 *   [4-byte BE path length] [UTF-8 document path] [protocol body]
 *
 * Used by every shared protocol handler that routes by document path
 * (currently `documentKeyUpdateV2` and BeeKEM Welcome v1/v2). Centralizing
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
        p.then((v) => v === true && resolve(true), reject),
      ),
  );
  newPromises.push(Promise.all(promises).then(() => false));
  return Promise.race(newPromises);
}

/**
 * Detach a serializer/provider-produced record without invoking accessors or
 * reading any property more than once. Routing checks, signature verification,
 * and state mutation must all use the returned snapshot.
 */
export function snapshotEnumerableOwnDataObject<T extends object>(
  value: unknown,
  field = 'value',
): T {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${field} must be a plain object`);
  }
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Reflect.apply(objectGetPrototypeOf, Object, [value]) as
      | object
      | null;
    descriptors = Reflect.apply(objectGetOwnPropertyDescriptors, Object, [
      value,
    ]) as PropertyDescriptorMap;
  } catch {
    throw new TypeError(`${field} must expose stable own data properties`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${field} must be a plain object`);
  }

  const snapshot: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== 'string') {
      throw new TypeError(`${field} must not contain symbol properties`);
    }
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(
        `${field} must contain only enumerable data properties`,
      );
    }
    Object.defineProperty(snapshot, key, {
      configurable: true,
      enumerable: true,
      value: descriptor.value,
      writable: true,
    });
  }
  return snapshot as T;
}

export interface DeepDataSnapshotLimits {
  readonly maxDepth: number;
  readonly maxObjects: number;
  readonly maxProperties: number;
  readonly maxArrayLength: number;
  readonly maxValueBytes: number;
}

/**
 * Iteratively detach an untrusted codec/provider value without invoking own
 * accessors or reading an own property more than once. Plain records retain
 * their descriptor order, arrays must be dense own-data arrays, genuine
 * unshared Uint8Arrays are copied through captured intrinsics, and CryptoKeys
 * are cloned as immutable platform values. Cycles, exotic objects, symbols,
 * accessors, sparse arrays, SAB views, and values exceeding the aggregate
 * work/allocation limits are rejected. Repeated aliases are copied
 * independently so a later mutation through one consumer cannot change
 * another authenticated field.
 */
export function snapshotDeepEnumerableData<T>(
  value: T,
  field = 'value',
  limits: DeepDataSnapshotLimits = {
    // The object-count budget already bounds the depth of an acyclic value.
    // Keeping the default depth equal to that aggregate budget admits legacy
    // Merkle histories while explicit security-sensitive callers can still
    // impose a tighter structural limit.
    maxDepth: 32_768,
    maxObjects: 32_768,
    maxProperties: 131_072,
    maxArrayLength: 65_536,
    maxValueBytes: 64 * 1024 * 1024,
  },
): T {
  for (const [name, limit] of Object.entries(limits)) {
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new TypeError(`${name} must be a non-negative safe integer`);
    }
  }

  let objectCount = 0;
  let propertyCount = 0;
  let valueBytes = 0;
  const active = new WeakSet<object>();

  const accountBytes = (amount: number): void => {
    if (!Number.isSafeInteger(amount) || amount < 0) {
      throw new RangeError(`${field} has an invalid detached size`);
    }
    valueBytes += amount;
    if (
      !Number.isSafeInteger(valueBytes) ||
      valueBytes > limits.maxValueBytes
    ) {
      throw new RangeError(
        `${field} exceeds ${limits.maxValueBytes} detached value bytes`,
      );
    }
  };

  const accountProperties = (amount: number): void => {
    propertyCount += amount;
    if (
      !Number.isSafeInteger(propertyCount) ||
      propertyCount > limits.maxProperties
    ) {
      throw new RangeError(
        `${field} exceeds ${limits.maxProperties} detached properties`,
      );
    }
  };

  type AssignmentTarget =
    | { readonly kind: 'root' }
    | {
        readonly kind: 'array';
        readonly parent: unknown[];
        readonly index: number;
      }
    | {
        readonly kind: 'object';
        readonly parent: Record<string, unknown>;
        readonly key: string;
      };
  type SnapshotTask =
    | {
        readonly kind: 'snapshot';
        readonly candidate: unknown;
        readonly depth: number;
        readonly target: AssignmentTarget;
      }
    | { readonly kind: 'leave'; readonly candidate: object };

  let result: unknown;
  const assign = (target: AssignmentTarget, candidate: unknown): void => {
    if (target.kind === 'root') {
      result = candidate;
    } else if (target.kind === 'array') {
      target.parent[target.index] = candidate;
    } else {
      Object.defineProperty(target.parent, target.key, {
        configurable: true,
        enumerable: true,
        value: candidate,
        writable: true,
      });
    }
  };

  const pending: SnapshotTask[] = [
    { kind: 'snapshot', candidate: value, depth: 0, target: { kind: 'root' } },
  ];
  while (pending.length > 0) {
    const task = pending.pop()!;
    if (task.kind === 'leave') {
      active.delete(task.candidate);
      continue;
    }
    const { candidate, depth, target } = task;
    if (depth > limits.maxDepth) {
      throw new RangeError(`${field} exceeds maximum depth ${limits.maxDepth}`);
    }
    if (
      candidate === null ||
      candidate === undefined ||
      typeof candidate === 'boolean' ||
      typeof candidate === 'number' ||
      typeof candidate === 'bigint'
    ) {
      assign(target, candidate);
      continue;
    }
    if (typeof candidate === 'string') {
      accountBytes(candidate.length * 2);
      assign(target, candidate);
      continue;
    }
    if (typeof candidate === 'symbol' || typeof candidate === 'function') {
      throw new TypeError(`${field} contains a non-cloneable value`);
    }

    const objectCandidate = candidate as object;
    if (active.has(objectCandidate)) {
      throw new TypeError(`${field} must not contain cycles`);
    }
    objectCount++;
    if (objectCount > limits.maxObjects) {
      throw new RangeError(
        `${field} exceeds ${limits.maxObjects} detached objects`,
      );
    }

    // Brand-check through captured typed-array intrinsics. A Proxy around a
    // view fails these getters and an SAB-backed genuine view is rejected by
    // `copyUnsharedUint8Array` before allocation.
    let typedArrayTag: unknown;
    let typedArrayByteLength: number | undefined;
    try {
      typedArrayByteLength = Reflect.apply(
        intrinsicTypedArrayByteLengthGetter,
        objectCandidate,
        [],
      ) as number;
      typedArrayTag = Reflect.apply(
        intrinsicTypedArrayTagGetter,
        objectCandidate,
        [],
      );
    } catch {
      // Not a genuine typed-array view; inspect as an array/object below.
    }
    if (typedArrayTag !== undefined) {
      if (typedArrayTag !== 'Uint8Array') {
        throw new TypeError(`${field} contains an unsupported typed array`);
      }
      accountBytes(typedArrayByteLength!);
      assign(
        target,
        copyUnsharedUint8Array(objectCandidate, 0, limits.maxValueBytes, field),
      );
      continue;
    }

    let prototype: object | null;
    let descriptors: PropertyDescriptorMap;
    try {
      prototype = Reflect.apply(objectGetPrototypeOf, Object, [
        objectCandidate,
      ]) as object | null;
      descriptors = Reflect.apply(objectGetOwnPropertyDescriptors, Object, [
        objectCandidate,
      ]) as PropertyDescriptorMap;
    } catch {
      throw new TypeError(`${field} contains an unstable object`);
    }

    if (Array.isArray(objectCandidate)) {
      const lengthDescriptor = descriptors.length;
      if (
        lengthDescriptor === undefined ||
        !('value' in lengthDescriptor) ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0 ||
        lengthDescriptor.value > limits.maxArrayLength
      ) {
        throw new TypeError(`${field} contains an invalid array`);
      }
      const length = lengthDescriptor.value as number;
      const keys = Reflect.ownKeys(descriptors);
      if (keys.length !== length + 1) {
        throw new TypeError(`${field} arrays must be dense data arrays`);
      }
      accountProperties(length);
      const copy = new Array<unknown>(length);
      const children: SnapshotTask[] = [];
      for (let index = 0; index < length; index++) {
        const descriptor = descriptors[String(index)];
        if (
          descriptor === undefined ||
          descriptor.enumerable !== true ||
          !('value' in descriptor)
        ) {
          throw new TypeError(
            `${field} arrays must contain only own data elements`,
          );
        }
        children.push({
          kind: 'snapshot',
          candidate: descriptor.value,
          depth: depth + 1,
          target: { kind: 'array', parent: copy, index },
        });
      }
      assign(target, copy);
      active.add(objectCandidate);
      pending.push({ kind: 'leave', candidate: objectCandidate });
      for (let index = children.length - 1; index >= 0; index--) {
        pending.push(children[index]!);
      }
      continue;
    }

    if (prototype !== Object.prototype && prototype !== null) {
      // CryptoKey is the sole opaque platform value admitted by the sync
      // message type. Invoke the captured native brand getter before cloning;
      // a Proxy or lookalike fails without consulting overridable fields.
      if (
        cryptoKeyTypeGetter !== undefined &&
        intrinsicStructuredClone !== undefined
      ) {
        try {
          Reflect.apply(cryptoKeyTypeGetter, objectCandidate, []);
          const copy = Reflect.apply(intrinsicStructuredClone, undefined, [
            objectCandidate,
          ]);
          if (
            Reflect.apply(cryptoKeyTypeGetter, copy, []) ===
            Reflect.apply(cryptoKeyTypeGetter, objectCandidate, [])
          ) {
            assign(target, copy);
            continue;
          }
        } catch {
          // Fall through to the fail-closed exotic-object error.
        }
      }
      throw new TypeError(`${field} contains a non-plain object`);
    }

    const keys = Reflect.ownKeys(descriptors);
    accountProperties(keys.length);
    const copy: Record<string, unknown> = {};
    const children: SnapshotTask[] = [];
    for (const key of keys) {
      if (typeof key !== 'string') {
        throw new TypeError(`${field} must not contain symbol properties`);
      }
      const descriptor = descriptors[key];
      if (
        descriptor === undefined ||
        descriptor.enumerable !== true ||
        !('value' in descriptor)
      ) {
        throw new TypeError(
          `${field} must contain only enumerable data properties`,
        );
      }
      children.push({
        kind: 'snapshot',
        candidate: descriptor.value,
        depth: depth + 1,
        target: { kind: 'object', parent: copy, key },
      });
    }
    assign(target, copy);
    active.add(objectCandidate);
    pending.push({ kind: 'leave', candidate: objectCandidate });
    for (let index = children.length - 1; index >= 0; index--) {
      pending.push(children[index]!);
    }
  }

  return result as T;
}

/**
 * Validate and detach an untrusted byte view without consulting overridable
 * instance properties. Genuine cross-realm Uint8Arrays are accepted, while
 * SharedArrayBuffer-backed views and typed-array lookalikes are rejected.
 */
export function copyUnsharedUint8Array(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  field = 'bytes',
): Uint8Array {
  let byteLength: number;
  let buffer: ArrayBufferLike;
  let tag: unknown;
  try {
    byteLength = Reflect.apply(
      intrinsicTypedArrayByteLengthGetter,
      value,
      [],
    ) as number;
    buffer = Reflect.apply(
      intrinsicTypedArrayBufferGetter,
      value,
      [],
    ) as ArrayBufferLike;
    tag = Reflect.apply(intrinsicTypedArrayTagGetter, value, []);
  } catch {
    throw new TypeError(`${field} must be a genuine Uint8Array`);
  }

  let shared = false;
  if (sharedArrayBufferByteLengthGetter !== undefined) {
    try {
      Reflect.apply(sharedArrayBufferByteLengthGetter, buffer, []);
      shared = true;
    } catch {
      // Ordinary ArrayBuffer backing.
    }
  }
  if (
    tag !== 'Uint8Array' ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < minimumLength ||
    byteLength > maximumLength ||
    shared
  ) {
    throw new TypeError(`${field} has an invalid length or backing buffer`);
  }

  const copy = new Uint8Array(byteLength);
  try {
    Reflect.apply(uint8ArraySet, copy, [value, 0]);
  } catch {
    throw new TypeError(`${field} could not be copied safely`);
  }
  return copy;
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
  const key = await crypto.subtle.importKey(
    format,
    keyData as Uint8Array<ArrayBuffer>,
    algorithmName,
    true,
    ['encrypt', 'decrypt'],
  );

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
