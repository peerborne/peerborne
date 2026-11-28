import { bufferOf, byteLengthOf, concatBytes } from './bytes.js';

const reflectApply = Reflect.apply;
const numberIsInteger = Number.isInteger;
const uint8ArrayConstructor = Uint8Array;
const dataViewConstructor = DataView;
const dataViewSetUint16 = DataView.prototype.setUint16;
const dataViewSetUint32 = DataView.prototype.setUint32;
const dataViewSetBigUint64 = DataView.prototype.setBigUint64;
const stringCharCodeAt = String.prototype.charCodeAt;

/** @internal Largest unsigned 64-bit integer. */
export const MAX_U64 = (1n << 64n) - 1n;

/** @internal Narrow an untrusted value to an unsigned 64-bit bigint. */
export function requireU64(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
  return value;
}

/** @internal One unsigned byte. */
export function encodeU8(value: number): Uint8Array {
  if (!numberIsInteger(value) || value < 0 || value > 0xff) {
    throw new Error('value does not fit in u8');
  }
  const output = new uint8ArrayConstructor(1);
  output[0] = value;
  return output;
}

/** @internal Big-endian unsigned 16-bit integer. */
export function encodeU16(value: number): Uint8Array {
  if (!numberIsInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('value does not fit in u16');
  }
  const output = new uint8ArrayConstructor(2);
  reflectApply(dataViewSetUint16, new dataViewConstructor(bufferOf(output)), [
    0,
    value,
    false,
  ]);
  return output;
}

/** @internal Big-endian unsigned 32-bit integer. */
export function encodeU32(value: number): Uint8Array {
  if (!numberIsInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('value does not fit in u32');
  }
  const output = new uint8ArrayConstructor(4);
  reflectApply(dataViewSetUint32, new dataViewConstructor(bufferOf(output)), [
    0,
    value,
    false,
  ]);
  return output;
}

/** @internal Big-endian unsigned 64-bit integer. */
export function encodeU64(value: bigint, field = 'u64'): Uint8Array {
  requireU64(value, field);
  const output = new uint8ArrayConstructor(8);
  reflectApply(
    dataViewSetBigUint64,
    new dataViewConstructor(bufferOf(output)),
    [0, value, false],
  );
  return output;
}

/** @internal `value` preceded by its big-endian u16 byte length. */
export function lengthPrefixed16(value: Uint8Array): Uint8Array {
  return concatBytes([encodeU16(byteLengthOf(value)), value]);
}

/** @internal `value` preceded by its big-endian u32 byte length. */
export function lengthPrefixed32(value: Uint8Array): Uint8Array {
  return concatBytes([encodeU32(byteLengthOf(value)), value]);
}

/** @internal Encode a fixed ASCII domain separator. */
export function asciiBytes(value: string): Uint8Array {
  const output = new uint8ArrayConstructor(value.length);
  for (let index = 0; index < value.length; index++) {
    const code = reflectApply(stringCharCodeAt, value, [index]) as number;
    if (code > 0x7f) throw new TypeError('domain separators must be ASCII');
    output[index] = code;
  }
  return output;
}
