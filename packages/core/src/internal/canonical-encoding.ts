/** @internal */
export function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
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
