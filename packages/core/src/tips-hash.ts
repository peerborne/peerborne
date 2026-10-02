/** Width of SHA-256 digests used by load messages. */
export const TIPS_HASH_LENGTH = 32;

/**
 * Encode a tips-hash byte array as a lowercase hex string. Used to key the
 * agreement map in `decideLoadQuorum` and to log/diagnose hash mismatches.
 *
 * Mirrors the canonical encoding so two callers comparing serialized hashes
 * over the wire always produce identical strings for identical inputs.
 */
export function tipsHashToHex(hash: Uint8Array): string {
  let out = '';
  for (let i = 0; i < hash.length; i++) {
    out += hash[i].toString(16).padStart(2, '0');
  }
  return out;
}
