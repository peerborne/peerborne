/** Length of an epoch ID in bytes (SHA-256 hash). */
export const EPOCH_ID_LENGTH = 32;

/**
 * Convert a Uint8Array to a lowercase hex string.
 */
export function toHex(bytes: Uint8Array): string {
  const hexChars: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hexChars[i] = bytes[i].toString(16).padStart(2, '0');
  }
  return hexChars.join('');
}
