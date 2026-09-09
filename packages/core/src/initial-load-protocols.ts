import {
  documentLoadV3,
  documentLoadV4,
  securityAdvertiseV1,
  snapshotLoadV3,
  snapshotLoadV4,
  tipAdvertiseV1,
} from './wire-protocols.js';

/** Maximum complete request or ordinary encrypted sync frame (10 MiB). */
export const MAX_SHARED_PROTOCOL_REQUEST_SIZE = 10 * 1024 * 1024;

/**
 * Maximum encrypted legacy V3 tip advertisement buffered before
 * authentication. Legacy document IDs were not globally limited, so this
 * preserves every document ID admitted by the 10 MiB request ceiling plus
 * fixed response fields and authenticated-encryption framing.
 */
export const MAX_TIP_ADVERTISE_RESPONSE_SIZE =
  MAX_SHARED_PROTOCOL_REQUEST_SIZE + 64 * 1024;

/**
 * Maximum encrypted V4 security advertisement buffered before
 * authentication. V4 bounds document IDs to 4096 bytes and group IDs to 1024
 * bytes; JSON control-character escaping can expand each byte to six ASCII
 * bytes. 40 KiB covers that worst-case expansion plus hashes, challenge,
 * signature, JSON framing, key ID, nonce, and authentication tag.
 */
export const MAX_SECURITY_ADVERTISE_RESPONSE_SIZE = 40 * 1024;

/**
 * Maximum encrypted full initial-load response buffered before validation.
 * The V4 manifest independently allows up to 16 MiB each for inline changes,
 * snapshot state, and keychain changes. Yjs base64 expansion makes that valid
 * three-part payload slightly larger than 64 MiB before framing/encryption;
 * 128 MiB admits it while retaining a finite pre-authentication bound.
 */
export const MAX_INITIAL_LOAD_RESPONSE_SIZE = 128 * 1024 * 1024;

export interface InitialLoadProtocolFamily {
  documentLoad: string;
  snapshotLoad: string;
  advertise: string;
  securityAware: boolean;
}

export function initialLoadProtocols(
  requireSecurityStateQuorum: boolean,
): InitialLoadProtocolFamily {
  return requireSecurityStateQuorum
    ? {
        documentLoad: documentLoadV4,
        snapshotLoad: snapshotLoadV4,
        advertise: securityAdvertiseV1,
        securityAware: true,
      }
    : {
        documentLoad: documentLoadV3,
        snapshotLoad: snapshotLoadV3,
        advertise: tipAdvertiseV1,
        securityAware: false,
      };
}

export function shouldServeInitialLoadProtocol(
  requireSecurityStateQuorum: boolean,
  securityAware: boolean,
): boolean {
  return !requireSecurityStateQuorum || securityAware;
}
