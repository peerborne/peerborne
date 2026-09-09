import { tipsHash } from './tips-hash.js';
import {
  LOAD_SECURITY_HASH_LENGTH,
  LoadSecurityCommitments,
  loadSecurityStateHash,
  loadSecurityStateHashToHex,
} from './load-security-state.js';

const SECURITY_LOAD_ADVERTISEMENT_DOMAIN =
  'peerborne/security-load-advertisement/v2\0';

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
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

/**
 * Hash a legacy served frontier, or the complete security-aware load tuple.
 * The legacy branch intentionally delegates to `tipsHash` byte-for-byte.
 * V4 additionally commits to a locally-derived complete load-response
 * manifest. This prevents a responder from retaining the voted frontier while
 * smuggling extra nodes, different node classifications/edges, snapshot state,
 * or keychain changes into the selected full response.
 */
export function loadAdvertisementHash(
  documentId: string,
  frontier: readonly string[],
): Promise<Uint8Array>;
export function loadAdvertisementHash(
  documentId: string,
  frontier: readonly string[],
  commitments: LoadSecurityCommitments,
  responseManifestHash: Uint8Array,
): Promise<Uint8Array>;
export async function loadAdvertisementHash(
  documentId: string,
  frontier: readonly string[],
  commitments?: LoadSecurityCommitments,
  responseManifestHash?: Uint8Array,
): Promise<Uint8Array> {
  if (commitments === undefined) {
    if (responseManifestHash !== undefined) {
      throw new TypeError(
        'legacy load advertisements cannot include a V4 response manifest',
      );
    }
    return tipsHash(frontier);
  }
  if (
    !(responseManifestHash instanceof Uint8Array) ||
    responseManifestHash.length !== LOAD_SECURITY_HASH_LENGTH
  ) {
    throw new TypeError(
      `V4 load advertisements require a ${LOAD_SECURITY_HASH_LENGTH}-byte response manifest hash`,
    );
  }
  const securityStateHash = await loadSecurityStateHash({
    ...commitments,
    documentId,
    frontier,
  });
  const digest = await crypto.subtle.digest(
    'SHA-256',
    concatenate([
      encodeUtf8(SECURITY_LOAD_ADVERTISEMENT_DOMAIN),
      securityStateHash,
      responseManifestHash,
    ]) as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest);
}

export const loadAdvertisementHashToHex = loadSecurityStateHashToHex;
