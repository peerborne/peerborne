import { defineEnumerableDataProperty } from './data-property.js';
import {
  byteLengthOf,
  copyUnsharedUint8Array,
  typedArrayTagOf,
} from './bytes.js';

const arrayIsArray = Array.isArray;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const intrinsicStructuredClone = globalThis.structuredClone;
const cryptoKeyTypeGetter =
  typeof CryptoKey === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(CryptoKey.prototype, 'type')?.get;

// JavaScript string lengths count UTF-16 code units, each occupying two bytes.
const UTF16_BYTES_PER_CODE_UNIT = 2;

/** Bytes charged by snapshot budgets for a detached JavaScript string. */
export function snapshotStringBytes(value: string): number {
  return value.length * UTF16_BYTES_PER_CODE_UNIT;
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
      object | null;
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
    keyBytes += snapshotStringBytes(key);
    if (!Number.isSafeInteger(keyBytes) || keyBytes > limits.maxKeyBytes) {
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

/** @internal Whether `value` carries the native CryptoKey brand. */
export function isNativeCryptoKey(value: unknown): boolean {
  if (
    cryptoKeyTypeGetter === undefined ||
    typeof value !== 'object' ||
    value === null
  ) {
    return false;
  }
  try {
    reflectApply(cryptoKeyTypeGetter, value, []);
    return true;
  } catch {
    return false;
  }
}

/**
 * Iteratively detach an untrusted codec/provider value without invoking own
 * accessors. Plain records retain their descriptor order and each field is
 * read once; arrays must be dense own-data arrays whose bounded length stays
 * stable while their elements are read; genuine unshared Uint8Arrays are
 * copied through captured intrinsics, and CryptoKeys are cloned as immutable
 * platform values. Cycles, exotic objects, symbols, accessors, sparse arrays,
 * SAB views, and values exceeding the aggregate work/allocation limits are
 * rejected. Repeated aliases are copied independently so a later mutation
 * through one consumer cannot change another authenticated field.
 */
export function snapshotDeepEnumerableData<T>(
  value: T,
  field = 'value',
  limits: DeepDataSnapshotLimits = {
    // The object-count budget already bounds the depth of an acyclic value.
    // Keeping the default depth equal to that aggregate budget admits ordinary
    // Merkle histories while explicit security-sensitive callers can still
    // impose a tighter structural limit.
    maxDepth: 32_768,
    maxObjects: 32_768,
    maxProperties: 131_072,
    maxArrayLength: 65_536,
    maxValueBytes: 64 * 1024 * 1024,
  },
  options: { retainCryptoKeys?: boolean } = {},
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
        String(target.index),
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
      accountBytes(snapshotStringBytes(candidate));
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
      typedArrayByteLength = byteLengthOf(objectCandidate as Uint8Array);
      typedArrayTag = typedArrayTagOf(objectCandidate);
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
    let isArray: boolean;
    try {
      prototype = reflectApply(objectGetPrototypeOf, Object, [
        objectCandidate,
      ]) as object | null;
      isArray = reflectApply(arrayIsArray, Array, [objectCandidate]) as boolean;
    } catch {
      throw new TypeError(`${field} contains an unstable object`);
    }

    if (isArray) {
      const readLength = (): number => {
        let lengthDescriptor: PropertyDescriptor | undefined;
        try {
          lengthDescriptor = reflectApply(
            objectGetOwnPropertyDescriptor,
            Object,
            [objectCandidate, 'length'],
          ) as PropertyDescriptor | undefined;
        } catch {
          throw new TypeError(`${field} contains an unstable array`);
        }
        if (
          lengthDescriptor === undefined ||
          !('value' in lengthDescriptor) ||
          !Number.isSafeInteger(lengthDescriptor.value) ||
          lengthDescriptor.value < 0 ||
          lengthDescriptor.value > limits.maxArrayLength
        ) {
          throw new TypeError(`${field} contains an invalid array`);
        }
        return lengthDescriptor.value as number;
      };
      const length = readLength();
      let keys: (string | symbol)[];
      try {
        keys = reflectOwnKeys(objectCandidate);
      } catch {
        throw new TypeError(`${field} contains an unstable array`);
      }
      if (keys.length !== length + 1) {
        throw new TypeError(`${field} arrays must be dense data arrays`);
      }
      // Array index keys never appear in encoded input; accountProperties
      // bounds their descriptor work without charging them as value bytes.
      accountProperties(length);
      for (let index = 0; index < length; index++) {
        if (keys[index] !== String(index)) {
          throw new TypeError(`${field} arrays must be dense data arrays`);
        }
      }
      if (keys[length] !== 'length') {
        throw new TypeError(`${field} arrays must be dense data arrays`);
      }
      const copy = new Array<unknown>(length);
      const children: SnapshotTask[] = [];
      for (let index = 0; index < length; index++) {
        let descriptor: PropertyDescriptor | undefined;
        try {
          descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
            objectCandidate,
            String(index),
          ]) as PropertyDescriptor | undefined;
        } catch {
          throw new TypeError(`${field} contains an unstable array`);
        }
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
      if (readLength() !== length) {
        throw new TypeError(`${field} contains an invalid array`);
      }
      assign(target, copy);
      active.add(objectCandidate);
      pending.push({ kind: 'leave', candidate: objectCandidate });
      for (let index = children.length - 1; index >= 0; index--) {
        pending.push(children[index]!);
      }
      continue;
    }

    if (prototype !== objectPrototype && prototype !== null) {
      // CryptoKey is the sole opaque platform value admitted by the sync
      // message type. Invoke the captured native brand getter before cloning;
      // a Proxy or lookalike fails without consulting overridable fields.
      if (
        cryptoKeyTypeGetter !== undefined &&
        intrinsicStructuredClone !== undefined
      ) {
        try {
          reflectApply(cryptoKeyTypeGetter, objectCandidate, []);
          const copy = reflectApply(intrinsicStructuredClone, undefined, [
            objectCandidate,
          ]);
          if (
            reflectApply(cryptoKeyTypeGetter, copy, []) ===
            reflectApply(cryptoKeyTypeGetter, objectCandidate, [])
          ) {
            assign(target, options.retainCryptoKeys ? objectCandidate : copy);
            continue;
          }
        } catch {
          // Fall through to the fail-closed exotic-object error.
        }
      }
      throw new TypeError(`${field} contains a non-plain object`);
    }

    let keys: (string | symbol)[];
    try {
      keys = reflectOwnKeys(objectCandidate);
    } catch {
      throw new TypeError(`${field} contains an unstable object`);
    }
    // Reject over-budget objects before scanning their keys, regardless of
    // which shape error a smaller object would report.
    accountProperties(keys.length);
    for (const key of keys) {
      if (typeof key !== 'string') {
        throw new TypeError(`${field} must not contain symbol properties`);
      }
      accountBytes(snapshotStringBytes(key));
    }
    const stringKeys = keys as string[];
    const copy: Record<string, unknown> = {};
    const children: SnapshotTask[] = [];
    for (const key of stringKeys) {
      let descriptor: PropertyDescriptor | undefined;
      try {
        descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
          objectCandidate,
          key,
        ]) as PropertyDescriptor | undefined;
      } catch {
        throw new TypeError(`${field} contains an unstable object`);
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
