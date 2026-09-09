/**
 * Pure validation logic for incoming BeeKEM Welcome messages.
 *
 * The full receive path in
 * `PeerborneDocument.handleBeeKEMWelcomeRequestData` mixes validation
 * with stateful mutation (`keychain.merge`, setting `_invitationEpoch`).
 * The validation half is extracted here as a pure async function so its
 * security-critical branches -- document-path mismatch, missing epoch
 * ID, missing recipient binding, wrong recipient, not-in-readers-ACL,
 * missing signature, invalid signature -- can be exercised directly in
 * unit tests against mock providers, without standing up a full
 * libp2p/Helia stack.
 *
 * The production handler in `PeerborneDocument` calls this helper and
 * then applies the keychain merge + `_invitationEpoch` assignment when
 * the result is `accept`. Keep the two in sync: if you add or reorder a
 * gate in the handler, mirror the change here.
 */

import { CRDTSyncMessage } from './crdt-sync-message.js';
import { ECIES_P256_PUBLIC_KEY_LENGTH } from './ecies.js';
import { EPOCH_ID_LENGTH } from './epoch.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import {
  copyUnsharedUint8Array,
  snapshotEnumerableOwnDataObject,
} from './utils.js';

const MAX_BEEKEM_WELCOME_MESSAGE_BYTES = 10 * 1024 * 1024;

/**
 * Outcome of validating an incoming Welcome.
 *
 * `accept`: all gates passed; the caller should merge `keychainChanges`
 *   and record `welcomeEpochId` as the local invitation epoch.
 * `drop-not-for-us`: legitimate Welcome addressed to another reader;
 *   the caller should silently ignore it (this is not an attack).
 * `drop-malformed`: the Welcome is missing required fields (path,
 *   epoch ID, recipient binding, or keychain key material). The
 *   `reason` is a stable string suitable for log messages and tests.
 * `drop-unauthorized`: the Welcome failed an authorization gate
 *   (not in readers ACL, unsigned when signing is enabled, invalid
 *   signature). The `reason` distinguishes the specific failure.
 */
export type WelcomeValidationResult<ChangesType = unknown, PublicKey = unknown> =
  | {
      kind: 'accept';
      message: CRDTSyncMessage<ChangesType, PublicKey>;
    }
  | { kind: 'drop-not-for-us' }
  | { kind: 'drop-malformed'; reason: WelcomeMalformedReason }
  | {
      kind: 'drop-unauthorized';
      reason: WelcomeUnauthorizedReason;
      /** Present only after mandatory writer authentication succeeded. */
      message?: CRDTSyncMessage<ChangesType, PublicKey>;
    };

export type WelcomeMalformedReason =
  | 'wrong-document'
  | 'invalid-welcome-encoding'
  | 'missing-welcome-epoch-id'
  | 'missing-welcome-recipient'
  | 'missing-recipient-kem-public-key'
  | 'invalid-recipient-kem-public-key-length'
  | 'missing-ecies-sealed';

export type WelcomeUnauthorizedReason =
  | 'not-in-readers-acl'
  | 'missing-signature'
  | 'invalid-signature';

export type WelcomeTransitionDecision =
  | { kind: 'accept' }
  | { kind: 'reject'; reason: 'legacy-downgrade' | 'non-increasing-v2' };

/** Enforce monotonic Welcome replacement after writer authentication. */
export function evaluateBeeKEMWelcomeTransition(
  currentGeneration: number | null | undefined,
  protocolVersion: 1 | 2,
  incomingGeneration: number | undefined,
): WelcomeTransitionDecision {
  if (currentGeneration === undefined) return { kind: 'accept' };
  if (protocolVersion === 1 && currentGeneration !== null) {
    return { kind: 'reject', reason: 'legacy-downgrade' };
  }
  if (
    protocolVersion === 2 &&
    currentGeneration !== null &&
    (incomingGeneration === undefined || incomingGeneration <= currentGeneration)
  ) {
    return { kind: 'reject', reason: 'non-increasing-v2' };
  }
  return { kind: 'accept' };
}

/**
 * Minimal dependency surface a Welcome validator needs. Modeled as a
 * record of callables rather than full provider instances so tests can
 * pass small mocks.
 *
 * SECURITY NOTE: writer-auth (`verifyWriterSignature`) is enforced
 * **unconditionally** on Welcomes, independent of the document-key
 * signing toggle (`enableSigning` on `PeerborneConfig`). Welcomes are
 * broadcast in plaintext to every connected peer and carry the document
 * keychain delta + an `_invitationEpoch` binding; without a writer
 * signature any peer could inject arbitrary `keychainChanges` and force
 * a recipient's join boundary, enabling key poisoning / DoS against
 * `since_invited` history filtering. `enableSigning` is a knob for
 * application-layer signing of *document changes*; Welcome authenticity
 * is a separate concern and must always be verified. Wire that up by
 * having `verifyWriterSignature` actually do the verification regardless
 * of any signing-config short-circuit elsewhere in the stack.
 */
export interface WelcomeValidationDeps<ChangesType, PublicKey> {
  /** The document this Welcome should be for. */
  documentPath: string;
  /** Local user's public key, used for the recipient binding check. */
  localUserPublicKey: PublicKey;
  /** Serialize a public key into the wire form the Welcome carries. */
  serializePublicKey: (pk: PublicKey) => Promise<string>;
  /** Check whether `pk` is currently a reader on the document. */
  isReader: (pk: PublicKey) => Promise<boolean>;
  /**
   * Treat an exact recipient-bound, current-writer-signed Welcome as the
   * onboarding grant when the recipient cannot yet decrypt the readers ACL.
   */
  allowWriterAuthorizedBootstrap?: boolean;
  /**
   * Verify a writer signature over the canonical (signature-stripped)
   * serialization of the message. Returns `true` iff the signature is
   * valid and the signer is currently an authorized writer.
   *
   * MUST always perform real verification (do not short-circuit to
   * `true` when application-layer signing is disabled): Welcomes are
   * always writer-authenticated.
   */
  verifyWriterSignature: (
    raw: Uint8Array,
    signature: string,
  ) => Promise<boolean>;
  /**
   * Serializer used to compute the canonical bytes signed by the
   * inviter (i.e. the sync message with the `signature` field stripped).
   */
  syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>;
}

/**
 * Run every validation gate enforced by
 * `PeerborneDocument.handleBeeKEMWelcomeRequestData`, in the same
 * order, and return a discriminated result so the caller can decide
 * what to do next (merge / drop / ignore).
 *
 * This function performs **no** mutations. The caller is responsible
 * for merging `message.keychainChanges` into the local keychain and
 * recording `message.welcomeEpochId` as the local invitation epoch
 * when the result is `accept`.
 */
export async function evaluateBeeKEMWelcome<ChangesType, PublicKey>(
  message: CRDTSyncMessage<ChangesType, PublicKey>,
  deps: WelcomeValidationDeps<ChangesType, PublicKey>,
): Promise<WelcomeValidationResult<ChangesType, PublicKey>> {
  // Canonicalize and detach the complete message before the first async
  // provider call. This prevents a caller-owned view/object from changing
  // between signature verification and the caller's eventual state commit.
  try {
    const encoded = copyUnsharedUint8Array(
      deps.syncMessageSerializer.serializeSyncMessage(message),
      1,
      MAX_BEEKEM_WELCOME_MESSAGE_BYTES,
      'BeeKEM Welcome encoding',
    );
    message = snapshotEnumerableOwnDataObject<
      CRDTSyncMessage<ChangesType, PublicKey>
    >(
      deps.syncMessageSerializer.deserializeSyncMessage(encoded),
      'BeeKEM Welcome message',
    );
  } catch {
    return { kind: 'drop-malformed', reason: 'invalid-welcome-encoding' };
  }

  // Defense in depth: the shared protocol handler routes by document
  // path header, but a misrouted or hand-crafted message could still
  // carry a mismatched `documentId`. Drop these without further work.
  if (message.documentId !== deps.documentPath) {
    return { kind: 'drop-malformed', reason: 'wrong-document' };
  }

  // The Welcome MUST carry an exact epoch ID so the recipient can bind the
  // installed keychain delta to the BeeKEM root and retain a monotonic local
  // invitation anchor. A truthy check is insufficient because it admits empty
  // or malformed IDs.
  let welcomeEpochId: Uint8Array;
  try {
    welcomeEpochId = copyUnsharedUint8Array(
      message.welcomeEpochId,
      EPOCH_ID_LENGTH,
      EPOCH_ID_LENGTH,
      'welcomeEpochId',
    );
  } catch {
    return { kind: 'drop-malformed', reason: 'missing-welcome-epoch-id' };
  }
  message = { ...message, welcomeEpochId };

  // Recipient binding: Welcomes are broadcast to every connected peer
  // (the inviter cannot identify the new reader's libp2p connection
  // directly), so without an explicit recipient binding any
  // well-behaved peer receiving a writer-signed Welcome would install
  // the document key. The binding is covered by the writer signature
  // (verified below), so only an authorized writer can claim a
  // recipient.
  if (!message.welcomeRecipient) {
    return { kind: 'drop-malformed', reason: 'missing-welcome-recipient' };
  }

  // The recipient KEM public key binds the sealed payload to a
  // specific encryption key. Required so the writer can sign over the
  // identity-to-encryption-key mapping; without it, an attacker
  // controlling one of the two keys alone could attempt to substitute
  // the sealed payload.
  if (!message.welcomeRecipientKemPublicKey) {
    return {
      kind: 'drop-malformed',
      reason: 'missing-recipient-kem-public-key',
    };
  }

  // The protocol requires the recipient KEM public key to be a fixed
  // 65-byte SEC1-uncompressed P-256 point (0x04 || X || Y); see
  // `ECIES_P256_PUBLIC_KEY_LENGTH`. Enforce the length here so the
  // validator stays the single structural gate: anything else would
  // otherwise pass this gate and fail later inside the receive path
  // (e.g. `importEciesPublicKey` rejects on length mismatch) with a
  // less specific error. Treating it as malformed lets the bounded
  // pending-Welcome buffer drop it cleanly without retrying.
  let welcomeRecipientKemPublicKey: Uint8Array;
  try {
    welcomeRecipientKemPublicKey = copyUnsharedUint8Array(
      message.welcomeRecipientKemPublicKey,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      'welcomeRecipientKemPublicKey',
    );
  } catch {
    return {
      kind: 'drop-malformed',
      reason: 'invalid-recipient-kem-public-key-length',
    };
  }
  message = { ...message, welcomeRecipientKemPublicKey };

  // A Welcome without an `eciesSealed` payload is useless: the recipient
  // would record an invitation anchor without installing the corresponding
  // document key, leaving it unable to decrypt pubsub traffic. Treat a
  // missing/empty sealed payload as malformed and refuse to record the epoch.
  let eciesSealed: Uint8Array;
  try {
    eciesSealed = copyUnsharedUint8Array(
      message.eciesSealed,
      1,
      MAX_BEEKEM_WELCOME_MESSAGE_BYTES,
      'eciesSealed',
    );
  } catch {
    return { kind: 'drop-malformed', reason: 'missing-ecies-sealed' };
  }
  message = { ...message, eciesSealed };

  const localSerializedKey = await deps.serializePublicKey(
    deps.localUserPublicKey,
  );
  if (message.welcomeRecipient !== localSerializedKey) {
    // Not addressed to us. Not necessarily an attack -- a legitimate
    // Welcome to another peer flows past our connection too. Silently
    // ignore.
    return { kind: 'drop-not-for-us' };
  }

  // Verify the writer signature **unconditionally**. The signing
  // convention matches `_signWelcomeAsWriter` on the inviter side: the
  // signature is computed over the serialized message with the
  // `signature` field stripped. Because the recipient binding is
  // included in the signed payload, only an authorized writer can
  // claim a particular recipient.
  //
  // SECURITY: unlike normal sync-message signing -- which is gated by
  // the swarm-wide `enableSigning` config
  // -- Welcome writer-auth is enforced even when document-key signing
  // is disabled. Welcomes are plaintext broadcasts that carry the
  // keychain delta and bind a recipient's `_invitationEpoch`; without
  // an unconditional writer-signature requirement any connected peer
  // could inject arbitrary `keychainChanges` (key poisoning) or set
  // `_invitationEpoch` for an existing reader (history-filter DoS).
  // The dep contract requires `verifyWriterSignature` to always do
  // real verification here.
  if (!message.signature) {
    return { kind: 'drop-unauthorized', reason: 'missing-signature' };
  }
  const { signature, ...messageWithoutSignature } = message;
  const raw = deps.syncMessageSerializer.serializeSyncMessage(
    messageWithoutSignature,
  );
  if ((await deps.verifyWriterSignature(raw, signature)) !== true) {
    return { kind: 'drop-unauthorized', reason: 'invalid-signature' };
  }

  // A caller may treat the exact identity+KEM-bound, current-writer signature
  // above as an onboarding grant by enabling `allowWriterAuthorizedBootstrap`.
  // Otherwise retain the defense-in-depth readers-ACL prerequisite.
  if (
    deps.allowWriterAuthorizedBootstrap !== true &&
    (await deps.isReader(deps.localUserPublicKey)) !== true
  ) {
    return {
      kind: 'drop-unauthorized',
      reason: 'not-in-readers-acl',
      message,
    };
  }

  return { kind: 'accept', message };
}
