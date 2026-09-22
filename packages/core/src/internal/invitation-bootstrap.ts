import { assertPositiveSafeByteLimit } from './byte-limits.js';
import type { InvitationBootstrapBundle } from '../peerborne-document.js';
import { MAX_INVITATION_MESSAGE_BYTES } from '../invitation-wire.js';
import {
  copyUnsharedUint8Array,
  snapshotEnumerableOwnDataObject,
} from '../utils.js';

const reflectOwnKeys = Reflect.ownKeys;

/** @internal Validate and detach every caller-owned invitation byte field. */
export function snapshotInvitationBootstrapBundle(
  bundle: InvitationBootstrapBundle,
  keyIDLength: number,
  nonceLength: number,
): Readonly<InvitationBootstrapBundle> {
  assertPositiveSafeByteLimit(keyIDLength, 'Invitation key ID length');
  assertPositiveSafeByteLimit(nonceLength, 'Invitation nonce length');
  const candidate = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    bundle,
    'Invitation bootstrap bundle',
  );
  const invalidFieldsMessage =
    'Invitation bootstrap bundle must contain exactly its three byte fields';
  const keys = reflectOwnKeys(candidate);
  let recognizedKeys = 0;
  for (const key of keys) {
    if (
      key !== 'welcomeEpochId' &&
      key !== 'sealedWelcome' &&
      key !== 'encryptedBootstrap'
    ) {
      throw new TypeError(invalidFieldsMessage);
    }
    recognizedKeys += 1;
  }
  if (recognizedKeys !== 3) {
    throw new TypeError(invalidFieldsMessage);
  }
  const welcomeEpochId = copyUnsharedUint8Array(
    candidate.welcomeEpochId,
    keyIDLength,
    keyIDLength,
    'Invitation welcome epoch',
  );
  const sealedWelcome = copyUnsharedUint8Array(
    candidate.sealedWelcome,
    1,
    MAX_INVITATION_MESSAGE_BYTES,
    'Invitation sealed Welcome',
  );
  const encryptedBootstrap = copyUnsharedUint8Array(
    candidate.encryptedBootstrap,
    keyIDLength + nonceLength + 1,
    MAX_INVITATION_MESSAGE_BYTES,
    'Invitation encrypted bootstrap',
  );
  return Object.freeze({
    welcomeEpochId,
    sealedWelcome,
    encryptedBootstrap,
  });
}
