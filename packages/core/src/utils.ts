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
const arrayConstructor = Array;
const uint8ArrayConstructor = Uint8Array;
const arrayIsArray = Array.isArray;
const numberIsSafeInteger = Number.isSafeInteger;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectHas = Reflect.has;
const reflectOwnKeys = Reflect.ownKeys;
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

function defineEnumerableDataProperty(
  target: object,
  key: PropertyKey,
  value: unknown,
): void {
  reflectApply(objectDefineProperty, Object, [
    target,
    key,
    {
      configurable: true,
      enumerable: true,
      value,
      writable: true,
    },
  ]);
}

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
  limits: Readonly<{
    maxProperties: number;
    maxKeyBytes: number;
  }> = {
    maxProperties: 131_072,
    maxKeyBytes: 64 * 1024 * 1024,
  },
): T {
  for (const [name, limit] of [
    ['maxProperties', limits.maxProperties],
    ['maxKeyBytes', limits.maxKeyBytes],
  ] as const) {
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new TypeError(`${name} must be a non-negative safe integer`);
    }
  }
  if (value === null || typeof value !== 'object') {
    throw new TypeError(`${field} must be a plain object`);
  }
  let isArray: boolean;
  try {
    isArray = reflectApply(arrayIsArray, Array, [value]) as boolean;
  } catch {
    throw new TypeError(`${field} must expose stable own data properties`);
  }
  if (isArray) throw new TypeError(`${field} must be a plain object`);
  let prototype: object | null;
  let keys: (string | symbol)[];
  try {
    prototype = reflectApply(objectGetPrototypeOf, Object, [value]) as
      | object
      | null;
    keys = reflectOwnKeys(value);
  } catch {
    throw new TypeError(`${field} must expose stable own data properties`);
  }
  if (prototype !== objectPrototype && prototype !== null) {
    throw new TypeError(`${field} must be a plain object`);
  }
  if (keys.length > limits.maxProperties) {
    throw new RangeError(
      `${field} exceeds ${limits.maxProperties} own properties`,
    );
  }

  let keyBytes = 0;
  for (const key of keys) {
    if (typeof key !== 'string') {
      throw new TypeError(`${field} must not contain symbol properties`);
    }
    keyBytes += key.length * 2;
    if (
      !Number.isSafeInteger(keyBytes) ||
      keyBytes > limits.maxKeyBytes
    ) {
      throw new RangeError(
        `${field} exceeds ${limits.maxKeyBytes} own-property key bytes`,
      );
    }
  }
  const stringKeys = keys as string[];

  const snapshot: Record<string, unknown> = {};
  for (const key of stringKeys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
        value,
        key,
      ]) as PropertyDescriptor | undefined;
    } catch {
      throw new TypeError(`${field} must expose stable own data properties`);
    }
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(
        `${field} must contain only enumerable data properties`,
      );
    }
    defineEnumerableDataProperty(snapshot, key, descriptor.value);
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

export interface DeepDataSnapshotOptions {
  /**
   * Reject these properties whether they are own or inherited. This is for
   * versioned runtime boundaries that must not erase newer-version markers
   * while converting an input to an own-data snapshot.
   */
  readonly forbiddenFields?: readonly string[];
}

/**
 * Iteratively detach an untrusted codec/provider value without invoking own
 * accessors. Plain records retain their descriptor order and each retained
 * field is read once; arrays retain a stable bounded length and dense own data
 * elements while irrelevant non-index properties are ignored; genuine
 * unshared Uint8Arrays are copied through captured intrinsics, and CryptoKeys
 * are cloned as immutable platform values. Cycles, exotic objects, symbols,
 * accessors in retained fields, sparse arrays, SAB views, and values exceeding
 * the aggregate work/allocation limits are rejected. Repeated aliases are
 * copied independently so a later mutation through one consumer cannot change
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
  options: DeepDataSnapshotOptions = {},
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
      defineEnumerableDataProperty(
        target.parent,
        `${target.index}`,
        candidate,
      );
    } else {
      defineEnumerableDataProperty(target.parent, target.key, candidate);
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
      typedArrayByteLength = reflectApply(
        intrinsicTypedArrayByteLengthGetter,
        objectCandidate,
        [],
      ) as number;
      typedArrayTag = reflectApply(
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

    let isArray: boolean;
    try {
      isArray = reflectApply(arrayIsArray, Array, [objectCandidate]) as boolean;
    } catch {
      throw new TypeError(`${field} contains an unstable object`);
    }

    if (isArray) {
      const readLength = (): number => {
        let descriptor: PropertyDescriptor | undefined;
        try {
          descriptor = reflectApply(
            objectGetOwnPropertyDescriptor,
            Object,
            [objectCandidate, 'length'],
          ) as PropertyDescriptor | undefined;
        } catch {
          throw new TypeError(`${field} contains an unstable object`);
        }
        if (
          descriptor === undefined ||
          !('value' in descriptor) ||
          !Number.isSafeInteger(descriptor.value) ||
          descriptor.value < 0 ||
          descriptor.value > limits.maxArrayLength
        ) {
          throw new TypeError(`${field} contains an invalid array`);
        }
        return descriptor.value as number;
      };

      const length = readLength();
