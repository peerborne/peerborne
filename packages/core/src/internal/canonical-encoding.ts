/** @internal */
export function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** @internal Count canonical UTF-8 bytes without allocating an encoded buffer. */
export function boundedUtf8ByteLength(value: string, maximum: number): number {
  //@ verify
  //@ requires value.length <= 4294967295
  //@ requires 0 <= maximum && maximum <= 4294967295
  //@ ensures -2 <= \result && \result <= maximum
  //@ ensures value.length > maximum ==> \result === -1
  //@ ensures \result >= 0 ==> value.length <= \result && \result <= 3 * value.length
  //@ ensures \result >= 0 ==> forall(j: int, 0 <= j && j < value.length ==> isPairedUtf16Unit(value, j))
  //@ ensures \result === -2 ==> exists(j: int, 0 <= j && j < value.length && !isPairedUtf16Unit(value, j))
  if (value.length > maximum) return -1;
  let bytes = 0;
  for (let index = 0; index < value.length; index++) {
    //@ invariant 0 <= index && index <= value.length
    //@ invariant index <= maximum
    //@ invariant 0 <= bytes && bytes <= maximum
    //@ invariant index <= bytes && bytes <= 3 * index
    //@ invariant forall(j: int, 0 <= j && j < index ==> isPairedUtf16Unit(value, j))
    //@ decreases value.length - index
    if (!isPairedUtf16Unit(value, index)) return -2;
    const width = utf8UnitByteLength(value.charCodeAt(index));
    if (width > maximum - bytes) return -1;
    bytes += width;
  }
  return bytes;
}

function utf8UnitByteLength(code: number): number {
  //@ verify
  //@ requires 0 <= code && code <= 65535
  //@ ensures 1 <= \result && \result <= 3
  //@ ensures \result === (code < 128 ? 1 : code < 2048 ? 2 : 55296 <= code && code <= 57343 ? 2 : 3)
  if (code < 0x80) return 1;
  if (code < 0x800) return 2;
  if (code >= 0xd800 && code <= 0xdfff) return 2;
  return 3;
}

/** @internal Validate text before copying payloads or allocating UTF-8 bytes. */
export function assertBoundedUtf8(
  value: unknown,
  maximum: number,
  field: string,
  allowEmpty = false,
): asserts value is string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0))
    throw new TypeError(
      `${field} must be a ${allowEmpty ? '' : 'non-empty '}string`,
    );
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 0xffffffff)
    throw new RangeError('Invalid UTF-8 byte limit');
  const bytes = boundedUtf8ByteLength(value, maximum);
  if (bytes === -2) throw new TypeError(`${field} must be well-formed UTF-16`);
  if (bytes < 0)
    throw new RangeError(`${field} exceeds ${maximum} UTF-8 bytes`);
}

/** @internal Big-endian unsigned 32-bit integer. */
export function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** @internal Takes an array rather than rest arguments so large part lists cannot exceed the call-argument limit. */
export function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** @internal True when `value` has no unpaired surrogate code units. */
export function isWellFormedUtf16(value: string): boolean {
  //@ verify
  //@ requires value.length <= 4294967295
  //@ ensures \result <==> forall(j: int, 0 <= j && j < value.length ==> isPairedUtf16Unit(value, j))
  for (let index = 0; index < value.length; index++) {
    //@ invariant 0 <= index && index <= value.length
    //@ invariant forall(j: int, 0 <= j && j < index ==> isPairedUtf16Unit(value, j))
    //@ decreases value.length - index
    if (!isPairedUtf16Unit(value, index)) return false;
  }
  return true;
}

function isPairedUtf16Unit(value: string, index: number): boolean {
  //@ verify
  //@ requires 0 <= index && index < value.length && value.length <= 4294967295
  //@ ensures \result <==> (!isHighSurrogate(value.charCodeAt(index)) || (index + 1 < value.length && isLowSurrogate(value.charCodeAt(index + 1)))) && (!isLowSurrogate(value.charCodeAt(index)) || (index > 0 && isHighSurrogate(value.charCodeAt(index - 1))))
  const code = value.charCodeAt(index);
  if (isHighSurrogate(code))
    return (
      index + 1 < value.length && isLowSurrogate(value.charCodeAt(index + 1))
    );
  if (isLowSurrogate(code))
    return index > 0 && isHighSurrogate(value.charCodeAt(index - 1));
  return true;
}

function isHighSurrogate(code: number): boolean {
  //@ verify
  //@ ensures \result <==> 55296 <= code && code <= 56319
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
  //@ verify
  //@ ensures \result <==> 56320 <= code && code <= 57343
  return code >= 0xdc00 && code <= 0xdfff;
}
