import { Base64 } from 'js-base64';
import { copyUnsharedUint8Array } from './utils.js';
import {
  concatenate,
  encodeUtf8,
  isWellFormedUtf16,
  uint32,
} from './internal/canonical-encoding.js';

const INITIAL_LOAD_REQUEST_DOMAIN = 'peerborne/initial-load-request/v4\0';

export const INITIAL_LOAD_CHALLENGE_LENGTH = 32;
export const MAX_INITIAL_LOAD_CHALLENGE_DOCUMENT_ID_BYTES = 4096;
const INITIAL_LOAD_CHALLENGE_BASE64_LENGTH =
  Math.ceil(INITIAL_LOAD_CHALLENGE_LENGTH / 3) * 4;
const INITIAL_LOAD_CHALLENGE_BASE64_PATTERN = /^[A-Za-z0-9+/]{43}=$/;

function snapshotInitialLoadChallenge(challenge: unknown): Uint8Array {
  try {
    return copyUnsharedUint8Array(
      challenge,
      INITIAL_LOAD_CHALLENGE_LENGTH,
      INITIAL_LOAD_CHALLENGE_LENGTH,
      'initial-load challenge',
    );
  } catch {
    throw new TypeError(
      `initial-load challenge must be a ${INITIAL_LOAD_CHALLENGE_LENGTH}-byte unshared Uint8Array`,
    );
  }
}

function validateDocumentId(documentId: string): Uint8Array {
  if (typeof documentId !== 'string' || documentId.length === 0) {
    throw new TypeError('initial-load documentId must be a non-empty string');
  }
  if (!isWellFormedUtf16(documentId)) {
    throw new TypeError('initial-load documentId must be well-formed UTF-16');
  }
  const bytes = encodeUtf8(documentId);
  if (bytes.length > MAX_INITIAL_LOAD_CHALLENGE_DOCUMENT_ID_BYTES) {
    throw new RangeError(
      `initial-load documentId exceeds ${MAX_INITIAL_LOAD_CHALLENGE_DOCUMENT_ID_BYTES} UTF-8 bytes`,
    );
  }
  return bytes;
}

export function validateInitialLoadChallenge(
  challenge: unknown,
): asserts challenge is Uint8Array {
  snapshotInitialLoadChallenge(challenge);
}

export function createInitialLoadChallenge(): Uint8Array {
  return crypto.getRandomValues(
    new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH),
  );
}

export function cloneInitialLoadChallenge(challenge: Uint8Array): Uint8Array {
  return snapshotInitialLoadChallenge(challenge);
}

export function initialLoadChallengeEquals(
  expected: Uint8Array | undefined,
  candidate: Uint8Array | undefined,
): boolean {
  let expectedSnapshot: Uint8Array;
  let candidateSnapshot: Uint8Array;
  try {
    expectedSnapshot = snapshotInitialLoadChallenge(expected);
    candidateSnapshot = snapshotInitialLoadChallenge(candidate);
  } catch {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < INITIAL_LOAD_CHALLENGE_LENGTH; index++) {
    difference |= expectedSnapshot[index] ^ candidateSnapshot[index];
  }
  return difference === 0;
}

/** Canonical bytes signed by a V4 requester (document path + fresh nonce). */
export function initialLoadRequestSignaturePayload(
  documentId: string,
  challenge: Uint8Array,
): Uint8Array {
  const documentIdBytes = validateDocumentId(documentId);
  const challengeSnapshot = snapshotInitialLoadChallenge(challenge);
  return concatenate([
    encodeUtf8(INITIAL_LOAD_REQUEST_DOMAIN),
    uint32(documentIdBytes.length),
    documentIdBytes,
    challengeSnapshot,
  ]);
}

export function serializeInitialLoadChallengeForWire(
  challenge: Uint8Array,
): string {
  return Base64.fromUint8Array(snapshotInitialLoadChallenge(challenge));
}

export function deserializeInitialLoadChallengeFromWire(
  value: unknown,
): Uint8Array {
  if (typeof value !== 'string') {
    throw new TypeError('initial-load challenge wire value must be a string');
  }
  if (
    value.length !== INITIAL_LOAD_CHALLENGE_BASE64_LENGTH ||
    !INITIAL_LOAD_CHALLENGE_BASE64_PATTERN.test(value)
  ) {
    throw new TypeError(
      `initial-load challenge wire value must use canonical fixed-width base64 for a ${INITIAL_LOAD_CHALLENGE_LENGTH}-byte challenge`,
    );
  }
  const decoded = Base64.toUint8Array(value);
  const challenge = snapshotInitialLoadChallenge(decoded);
  if (Base64.fromUint8Array(decoded) !== value) {
    throw new TypeError(
      'initial-load challenge wire value must use canonical base64',
    );
  }
  return challenge;
}
