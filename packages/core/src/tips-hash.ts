/** Width of SHA-256 digests used by load messages. */
export const TIPS_HASH_LENGTH = 32;

/**
 * Hash a sorted CID set, separated by newlines. This standalone utility does
 * not encode a V4 advertisement; use loadAdvertisementHash for that protocol.
 */
export async function tipsHash(
  hashes: Set<string> | readonly string[],
): Promise<Uint8Array> {
  const sorted = Array.from(hashes).slice().sort();
  // Use `\n` (0x0A) as a CID separator. Real CIDs are base32/base58/base64
  // text and never contain raw `\n`, so this is unambiguous. Encoding the
  // separator (rather than concatenating bytes directly) prevents two
  // different tip sets from colliding via a shared boundary, e.g.
  // `["ab", "c"]` vs `["a", "bc"]`.
  const canonical = sorted.join('\n');
  const encoded = new TextEncoder().encode(canonical);
  // Cast required: `Uint8Array<ArrayBufferLike>` does not strictly satisfy
  // WebCrypto's `BufferSource` (excludes `SharedArrayBuffer`-backed views).
  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoded as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest);
}

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
