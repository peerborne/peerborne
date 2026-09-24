import { tipsHash } from './tips-hash.js';
import {
  LOAD_SECURITY_HASH_LENGTH,
  LoadSecurityCommitments,
  cloneLoadSecurityCommitments,
  loadSecurityStateHash,
  loadSecurityStateHashToHex,
} from './load-security-state.js';
import { copyUnsharedUint8Array } from './utils.js';
import { concatenate, encodeUtf8 } from './internal/canonical-encoding.js';

const SECURITY_LOAD_ADVERTISEMENT_DOMAIN =
  'peerborne/security-load-advertisement/v2\0';

/**
 * Hash a legacy served frontier, or the complete security-aware load tuple.
 * The legacy branch intentionally delegates to `tipsHash` byte-for-byte.
 * This is a quorum comparison digest, not a signature payload. V4 responders
 * must sign the response envelope including its fresh `loadChallenge`; putting
 * a per-responder request challenge in this digest would prevent equal
 * document states from agreeing in the same quorum round.
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
  let manifestHashSnapshot: Uint8Array;
  try {
    manifestHashSnapshot = copyUnsharedUint8Array(
      responseManifestHash,
      LOAD_SECURITY_HASH_LENGTH,
      LOAD_SECURITY_HASH_LENGTH,
      'V4 response manifest hash',
    );
  } catch {
    throw new TypeError(
      `V4 load advertisements require a ${LOAD_SECURITY_HASH_LENGTH}-byte response manifest hash`,
    );
  }
  const commitmentSnapshot = cloneLoadSecurityCommitments(commitments);
  const securityStateHash = await loadSecurityStateHash({
    ...commitmentSnapshot,
    documentId,
    frontier,
  });
  const digest = await crypto.subtle.digest(
    'SHA-256',
    concatenate([
      encodeUtf8(SECURITY_LOAD_ADVERTISEMENT_DOMAIN),
      securityStateHash,
      manifestHashSnapshot,
    ]) as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest);
}

export const loadAdvertisementHashToHex = loadSecurityStateHashToHex;
