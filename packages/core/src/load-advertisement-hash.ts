import {
  LOAD_SECURITY_HASH_LENGTH,
  LoadSecurityCommitments,
  cloneLoadSecurityCommitments,
  loadSecurityStateHash,
  loadSecurityStateHashToHex,
} from './load-security-state.js';
import { copyUnsharedUint8Array } from './utils.js';

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
export async function loadAdvertisementHash(
  documentId: string,
  frontier: readonly string[],
  commitments: LoadSecurityCommitments,
  responseManifestHash: Uint8Array,
): Promise<Uint8Array> {
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
