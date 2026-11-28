import { isWellFormedUtf16 } from './internal/canonical-encoding.js';
import { MAX_DOCUMENT_PATH_LENGTH } from './shared-protocol-request.js';

const SNAPSHOT_SIGNATURE_DOMAIN = Uint8Array.from(
  'peerborne/snapshot-signature/v2\0',
  (value) => value.charCodeAt(0),
);

/**
 * Build the deterministic binary payload that a writer signs for a snapshot
 * of `documentPath`, and that receivers verify.
 *
 * Binary layout (big-endian integers):
 *   bytes   domain `peerborne/snapshot-signature/v2\0`
 *   uint32  pathLen
 *   bytes   UTF-8(documentPath)
 *   uint64  timestamp
 *   uint32  compactedCount
 *   uint32  cidLen
 *   bytes   UTF-8(lastChangeNodeCID)
 *   uint32  stateLen
 *   bytes   stateBytes
 */
export function buildSnapshotSignaturePayload(
  documentPath: string,
  stateBytes: Uint8Array,
  lastChangeNodeCID: string,
  timestamp: number,
  compactedCount: number,
): Uint8Array {
  if (
    typeof documentPath !== 'string' ||
    documentPath.length === 0 ||
    !isWellFormedUtf16(documentPath)
  ) {
    throw new Error('Invalid snapshot document path');
  }
  const encoder = new TextEncoder();
  const pathBytes = encoder.encode(documentPath);
  if (pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
    throw new Error(
      `Snapshot document path too large: ${pathBytes.length} bytes`,
    );
  }
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new Error(`Invalid snapshot timestamp: ${timestamp}`);
  }
  if (
    !Number.isInteger(compactedCount) ||
    compactedCount < 0 ||
    compactedCount > 0xffffffff
  ) {
    throw new Error(`Invalid snapshot compactedCount: ${compactedCount}`);
  }
  if (typeof lastChangeNodeCID !== 'string') {
    throw new Error('Invalid snapshot lastChangeNodeCID');
  }
  if (!(stateBytes instanceof Uint8Array)) {
    throw new Error('Invalid snapshot state');
  }
  const cidBytes = encoder.encode(lastChangeNodeCID);
  if (cidBytes.length > 0xffffffff) {
    throw new Error(`lastChangeNodeCID too large: ${cidBytes.length} bytes`);
  }
  if (stateBytes.length > 0xffffffff) {
    throw new Error(`Snapshot state too large: ${stateBytes.length} bytes`);
  }
  const out = new Uint8Array(
    SNAPSHOT_SIGNATURE_DOMAIN.length +
      4 +
      pathBytes.length +
      8 +
      4 +
      4 +
      cidBytes.length +
      4 +
      stateBytes.length,
  );
  const view = new DataView(out.buffer);
  let offset = 0;
  out.set(SNAPSHOT_SIGNATURE_DOMAIN, offset);
  offset += SNAPSHOT_SIGNATURE_DOMAIN.length;
  view.setUint32(offset, pathBytes.length, false);
  offset += 4;
  out.set(pathBytes, offset);
  offset += pathBytes.length;
  view.setBigUint64(offset, BigInt(timestamp), false);
  offset += 8;
  view.setUint32(offset, compactedCount, false);
  offset += 4;
  view.setUint32(offset, cidBytes.length, false);
  offset += 4;
  out.set(cidBytes, offset);
  offset += cidBytes.length;
  view.setUint32(offset, stateBytes.length, false);
  offset += 4;
  out.set(stateBytes, offset);
  return out;
}
