import { requireIntrinsicGetter } from './data-property.js';

const reflectApply = Reflect.apply;
const numberIsSafeInteger = Number.isSafeInteger;
const uint8ArrayConstructor = Uint8Array;
const uint8ArraySet = Uint8Array.prototype.set;
const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const typedArrayByteLength = requireIntrinsicGetter(
  typedArrayPrototype,
  'byteLength',
  'TypedArray.prototype.byteLength',
);
const typedArrayByteOffset = requireIntrinsicGetter(
  typedArrayPrototype,
  'byteOffset',
  'TypedArray.prototype.byteOffset',
);
const typedArrayBuffer = requireIntrinsicGetter(
  typedArrayPrototype,
  'buffer',
  'TypedArray.prototype.buffer',
);
const typedArrayTag = requireIntrinsicGetter(
  typedArrayPrototype,
  Symbol.toStringTag,
  'TypedArray.prototype[Symbol.toStringTag]',
);
const sharedArrayBufferByteLength =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : requireIntrinsicGetter(
        SharedArrayBuffer.prototype,
        'byteLength',
        'SharedArrayBuffer.prototype.byteLength',
      );

/** @internal Byte length read through the TypedArray intrinsic, ignoring instance overrides. */
export function byteLengthOf(value: Uint8Array): number {
  return reflectApply(typedArrayByteLength, value, []) as number;
}

/** @internal Byte offset read through the TypedArray intrinsic, ignoring instance overrides. */
export function byteOffsetOf(value: Uint8Array): number {
  return reflectApply(typedArrayByteOffset, value, []) as number;
}

/** @internal Backing buffer read through the TypedArray intrinsic, ignoring instance overrides. */
export function bufferOf(value: Uint8Array): ArrayBufferLike {
  return reflectApply(typedArrayBuffer, value, []) as ArrayBufferLike;
}

/** @internal `Symbol.toStringTag` read through the TypedArray intrinsic; throws for non-typed-arrays. */
export function typedArrayTagOf(value: unknown): unknown {
  return reflectApply(typedArrayTag, value, []);
}

/** @internal True for SharedArrayBuffers from any realm. */
export function isSharedArrayBuffer(buffer: unknown): boolean {
  if (sharedArrayBufferByteLength === undefined) return false;
  try {
    reflectApply(sharedArrayBufferByteLength, buffer, []);
    return true;
  } catch {
    return false;
  }
}

/** @internal Copy `source` into `target` through the intrinsic `Uint8Array.prototype.set`. */
export function setBytes(
  target: Uint8Array,
  source: Uint8Array,
  offset = 0,
): void {
  reflectApply(uint8ArraySet, target, [source, offset]);
}

/**
 * @internal Validate an untrusted byte view without consulting overridable
 * instance properties. Genuine cross-realm Uint8Arrays are accepted, while
 * SharedArrayBuffer-backed views and typed-array lookalikes are rejected.
 */
export function unsharedUint8ArrayByteLength(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  field = 'bytes',
): number {
  let byteLength: unknown;
  let buffer: unknown;
  let tag: unknown;
  try {
    byteLength = reflectApply(typedArrayByteLength, value, []);
    buffer = reflectApply(typedArrayBuffer, value, []);
    tag = reflectApply(typedArrayTag, value, []);
  } catch {
    throw new TypeError(`${field} must be a genuine Uint8Array`);
  }
  if (
    tag !== 'Uint8Array' ||
    typeof byteLength !== 'number' ||
    !numberIsSafeInteger(byteLength) ||
    byteLength < minimumLength ||
    byteLength > maximumLength ||
    isSharedArrayBuffer(buffer)
  ) {
    throw new TypeError(`${field} has an invalid length or backing buffer`);
  }
  return byteLength;
}

/** Detach an untrusted byte view into a fresh, unshared Uint8Array. */
export function copyUnsharedUint8Array(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  field = 'bytes',
): Uint8Array {
  const byteLength = unsharedUint8ArrayByteLength(
    value,
    minimumLength,
    maximumLength,
    field,
  );
  const copy = new uint8ArrayConstructor(byteLength);
  try {
    reflectApply(uint8ArraySet, copy, [value, 0]);
  } catch {
    throw new TypeError(`${field} could not be copied safely`);
  }
  return copy;
}

/** @internal Compare byte sequences without content-dependent early exits. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  const length = byteLengthOf(left);
  if (length !== byteLengthOf(right)) return false;
  let difference = 0;
  for (let index = 0; index < length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

/** @internal {@link equalBytes} where two absent values are equal. */
export function optionalEqualBytes(
  left: Uint8Array | undefined,
  right: Uint8Array | undefined,
): boolean {
  return left === undefined || right === undefined
    ? left === right
    : equalBytes(left, right);
}

/** @internal Lexicographic byte order; a proper prefix sorts first. */
export function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const leftLength = byteLengthOf(left);
  const rightLength = byteLengthOf(right);
  const length = Math.min(leftLength, rightLength);
  for (let index = 0; index < length; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return leftLength - rightLength;
}

/** @internal Sum of byte lengths, read through the TypedArray intrinsic. */
export function totalByteLength(parts: ReadonlyArray<Uint8Array>): number {
  let total = 0;
  for (let index = 0; index < parts.length; index++) {
    total += byteLengthOf(parts[index]);
  }
  return total;
}

/** @internal Takes an array rather than rest arguments so large part lists cannot exceed the call-argument limit. */
export function concatBytes(
  parts: ReadonlyArray<Uint8Array>,
): Uint8Array<ArrayBuffer> {
  const output = new uint8ArrayConstructor(totalByteLength(parts));
  let offset = 0;
  for (let index = 0; index < parts.length; index++) {
    const part = parts[index];
    reflectApply(uint8ArraySet, output, [part, offset]);
    offset += byteLengthOf(part);
  }
  return output;
}
