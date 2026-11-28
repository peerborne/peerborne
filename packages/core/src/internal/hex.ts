import { byteLengthOf } from './bytes.js';

const HEX_BYTES: readonly string[] = Object.freeze(
  Array.from({ length: 256 }, (_, value) =>
    value.toString(16).padStart(2, '0'),
  ),
);
const LOWERCASE_HEX = /^(?:[0-9a-f]{2})*$/;
const reflectApply = Reflect.apply;
const regExpExec = RegExp.prototype.exec;
const numberParseInt = Number.parseInt;
const stringSlice = String.prototype.slice;

/** Lowercase hex encoding of a byte view. */
export function bytesToHex(bytes: Uint8Array): string {
  const length = byteLengthOf(bytes);
  let result = '';
  for (let index = 0; index < length; index++)
    result += HEX_BYTES[bytes[index]];
  return result;
}

/** @internal Decode lowercase hex of exactly `byteLength` bytes, or `undefined` when it is not canonical. */
export function tryDecodeLowercaseHex(
  value: string,
  byteLength: number,
): Uint8Array | undefined {
  if (
    typeof value !== 'string' ||
    value.length !== byteLength * 2 ||
    reflectApply(regExpExec, LOWERCASE_HEX, [value]) === null
  ) {
    return undefined;
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength; index++) {
    bytes[index] = numberParseInt(
      reflectApply(stringSlice, value, [index * 2, index * 2 + 2]) as string,
      16,
    );
  }
  return bytes;
}
