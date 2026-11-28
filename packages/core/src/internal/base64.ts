import { Base64 } from 'js-base64';

const PADDED_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Whether `value` has the shape of padded base64. The check runs in linear
 * time, so it accepts strings of any length; callers that need canonical
 * encoding compare a decode-and-encode round trip.
 */
export function isPaddedBase64(value: string): boolean {
  return value.length % 4 === 0 && PADDED_BASE64.test(value);
}

/**
 * Decode canonical padded base64, or return `undefined` when `value` is not
 * canonical or decodes to more than `maxBytes`. Callers supply their own
 * error message.
 */
export function tryDecodeCanonicalBase64(
  value: string,
  maxBytes?: number,
): Uint8Array | undefined {
  if (maxBytes !== undefined && value.length > Math.ceil(maxBytes / 3) * 4) {
    return undefined;
  }
  if (!isPaddedBase64(value)) {
    return undefined;
  }
  let decoded: Uint8Array;
  try {
    decoded = Base64.toUint8Array(value);
  } catch {
    return undefined;
  }
  if (maxBytes !== undefined && decoded.byteLength > maxBytes) {
    return undefined;
  }
  return Base64.fromUint8Array(decoded) === value ? decoded : undefined;
}
