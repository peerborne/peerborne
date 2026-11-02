import { Base64 } from 'js-base64';
import { CID } from 'multiformats';
import { syncRequestTimeAllowed } from './policy/sync-request.js';

const domain = '\u0000peerborne/sync-request/2\u0000';
const prefix = Uint8Array.from(domain, (character) => character.charCodeAt(0));
export const MAX_SYNC_REQUEST_BYTES = 32 * 1024;
export const SYNC_REQUEST_LIFETIME_MS = 60_000;

export interface SyncRequest {
  readonly documentId: string;
  readonly requester: string;
  readonly requestId: string;
  readonly issuedAtMs: number;
  readonly knownTips: readonly string[];
  readonly knownSnapshots: readonly string[];
  readonly signature: string;
}

export function isSyncRequest(bytes: Uint8Array): boolean {
  return (
    bytes.length >= prefix.length &&
    prefix.every((byte, index) => bytes[index] === byte)
  );
}

export function syncRequestSigningPayload(
  request: Omit<SyncRequest, 'signature'>,
): Uint8Array {
  const bytes = new TextEncoder().encode(
    domain +
      JSON.stringify([
        request.documentId,
        request.requester,
        request.requestId,
        request.issuedAtMs,
        request.knownTips,
        request.knownSnapshots,
      ]),
  );
  if (bytes.length > MAX_SYNC_REQUEST_BYTES)
    throw new RangeError('Sync request exceeds its limit');
  return bytes;
}

export function encodeSyncRequest(request: SyncRequest): Uint8Array {
  const bytes = new TextEncoder().encode(
    domain +
      JSON.stringify([
        request.documentId,
        request.requester,
        request.requestId,
        request.issuedAtMs,
        request.knownTips,
        request.knownSnapshots,
        request.signature,
      ]),
  );
  if (!decodeSyncRequest(bytes)) throw new TypeError('Invalid sync request');
  return bytes;
}

export function decodeSyncRequest(bytes: Uint8Array): SyncRequest | undefined {
  if (!isSyncRequest(bytes) || bytes.length > MAX_SYNC_REQUEST_BYTES) return;
  try {
    const fields = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(
        bytes.subarray(prefix.length),
      ),
    );
    if (!Array.isArray(fields) || fields.length !== 7) return;
    const [
      documentId,
      requester,
      requestId,
      issuedAtMs,
      knownTips,
      knownSnapshots,
      signature,
    ] = fields;
    if (
      typeof documentId !== 'string' ||
      documentId.length < 1 ||
      documentId.length > 4096 ||
      typeof requester !== 'string' ||
      requester.length < 1 ||
      requester.length > 4096 ||
      typeof requestId !== 'string' ||
      !/^[0-9a-f]{32}$/u.test(requestId) ||
      !Number.isSafeInteger(issuedAtMs) ||
      issuedAtMs < 0 ||
      !Array.isArray(knownTips) ||
      knownTips.length < 1 ||
      knownTips.length > 32 ||
      new Set(knownTips).size !== knownTips.length ||
      !Array.isArray(knownSnapshots) ||
      knownSnapshots.length > 32 ||
      new Set(knownSnapshots).size !== knownSnapshots.length ||
      knownSnapshots.some(
        (hint: unknown) =>
          typeof hint !== 'string' || !/^[0-9a-f]{64}$/u.test(hint),
      ) ||
      typeof signature !== 'string' ||
      signature.length < 1 ||
      signature.length > 8192
    )
      return;
    for (const tip of knownTips) {
      if (
        typeof tip !== 'string' ||
        tip.length > 256 ||
        CID.parse(tip).toString() !== tip
      )
        return;
    }
    const signatureBytes = Base64.toUint8Array(signature);
    if (
      signatureBytes.length === 0 ||
      Base64.fromUint8Array(signatureBytes) !== signature
    )
      return;
    return Object.freeze({
      documentId,
      requester,
      requestId,
      issuedAtMs,
      knownTips: Object.freeze(knownTips),
      knownSnapshots: Object.freeze(knownSnapshots),
      signature,
    });
  } catch {
    return;
  }
}

export async function syncSnapshotHint(signature: Uint8Array): Promise<string> {
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new Uint8Array(signature)),
  );
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

export function isSyncRequestFresh(
  request: SyncRequest,
  nowMs: number,
): boolean {
  return (
    Number.isSafeInteger(nowMs) &&
    nowMs >= 0 &&
    Number.isSafeInteger(request.issuedAtMs) &&
    request.issuedAtMs >= 0 &&
    syncRequestTimeAllowed(request.issuedAtMs, nowMs)
  );
}
