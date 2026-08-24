import { describe, expect, test } from '@jest/globals';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import {
  evaluateBeeKEMWelcome,
  WelcomeValidationDeps,
} from './beekem-welcome-handler.js';

/**
 * Direct unit-test coverage for the security-critical gates of the
 * BeeKEM Welcome receive path.
 *
 * The validation gates have been extracted from
 * `PeerborneDocument.handleBeeKEMWelcomeRequestData` into the pure
 * `evaluateBeeKEMWelcome` helper so each gate can be exercised directly
 * here with small mocks (mock `AuthProvider`, ACL, and `Keychain`),
 * rather than requiring a full libp2p/Helia stack to construct a
 * `PeerborneDocument`. Prior coverage only mirrored the decision
 * logic in a helper; this file is the integration-style coverage of
 * the real receive-side validation.
 *
 * The production handler calls this same helper and applies
 * keychain.merge + `_invitationEpoch` assignment when the result is
 * `accept`; tests that exercise the mutation side-effects live in
 * `beekem-welcome.test.ts` against the in-memory keychain.
 */

type ChangesType = Uint8Array;
type PublicKey = { id: string };

/**
 * Minimal sync-message serializer that survives the round-trip used by
 * `evaluateBeeKEMWelcome` to compute the canonical bytes covered by
 * the writer signature. We only need a stable byte representation that
 * is deterministic for equal messages.
 */
const stubSerializer: SyncMessageSerializer<ChangesType, PublicKey> = {
  serializeSyncMessage(message: CRDTSyncMessage<ChangesType, PublicKey>) {
    return new TextEncoder().encode(JSON.stringify(message));
  },
  deserializeSyncMessage(_data: Uint8Array) {
    throw new Error('not used in evaluation');
  },
} as unknown as SyncMessageSerializer<ChangesType, PublicKey>;

function makeDeps(
  overrides: Partial<WelcomeValidationDeps<ChangesType, PublicKey>> = {},
): WelcomeValidationDeps<ChangesType, PublicKey> {
  return {
    documentPath: '/doc/welcome',
    localUserPublicKey: { id: 'my-pubkey' },
    serializePublicKey: async (pk) => pk.id,
    isReader: async () => true,
    verifyWriterSignature: async () => true,
    syncMessageSerializer: stubSerializer,
    ...overrides,
  };
}

/**
 * A fully-valid Welcome message. SECURITY: Welcomes are
 * **unconditionally** writer-authenticated -- the
 * validator no longer has an `isSigningEnabled` toggle -- so the base
 * acceptable message must carry a `signature` for the happy-path
 * assertions to hold.
 *
 * Note: confidentiality is enforced via the `eciesSealed` field
 * (encrypted to `welcomeRecipientKemPublicKey`); the validator
 * checks both fields are present and non-empty but does not attempt
 * to open the seal (that happens in the production receive path
 * after validation).
 */
function baseAcceptableMessage(): CRDTSyncMessage<ChangesType, PublicKey> {
  return {
    documentId: '/doc/welcome',
    welcomeEpochId: new Uint8Array(32).fill(7),
    welcomeRecipient: 'my-pubkey',
    welcomeRecipientKemPublicKey: new Uint8Array(65).fill(4),
    eciesSealed: new Uint8Array([1, 2, 3]),
    signature: 'good-sig',
  };
}

describe('evaluateBeeKEMWelcome (security-critical gates)', () => {
  test('accepts a fully-valid signed Welcome', async () => {
    const result = await evaluateBeeKEMWelcome(baseAcceptableMessage(), makeDeps());
    expect(result.kind).toBe('accept');
  });

  test('drops Welcomes for a different document path', async () => {
    const msg = { ...baseAcceptableMessage(), documentId: '/doc/other' };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({ kind: 'drop-malformed', reason: 'wrong-document' });
  });

  test('drops Welcomes missing welcomeEpochId', async () => {
    const msg = baseAcceptableMessage();
    delete msg.welcomeEpochId;
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-welcome-epoch-id',
    });
  });

  test('drops Welcomes with a zero-length welcomeEpochId', async () => {
    // A truthy check alone passes empty `Uint8Array` values, but
    // recording an empty epoch ID as `_invitationEpoch` would later
    // make every `historySince` lookup miss and silently fall back to
    // returning the full history -- defeating `since_invited`
    // filtering. The validator must treat empty as malformed.
    const msg = {
      ...baseAcceptableMessage(),
      welcomeEpochId: new Uint8Array(0),
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-welcome-epoch-id',
    });
  });

  test('drops Welcomes missing welcomeRecipient (recipient-binding gate)', async () => {
    const msg = baseAcceptableMessage();
    delete msg.welcomeRecipient;
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-welcome-recipient',
    });
  });

  test('drops Welcomes missing welcomeRecipientKemPublicKey (recipient KEM binding gate)', async () => {
    const msg = baseAcceptableMessage();
    delete msg.welcomeRecipientKemPublicKey;
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-recipient-kem-public-key',
    });
  });

  test('drops Welcomes with an empty welcomeRecipientKemPublicKey', async () => {
    const msg = {
      ...baseAcceptableMessage(),
      welcomeRecipientKemPublicKey: new Uint8Array(0),
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-recipient-kem-public-key',
    });
  });

  test('drops Welcomes whose welcomeRecipientKemPublicKey is shorter than 65 bytes', async () => {
    // The protocol fixes the recipient KEM public key at the
    // SEC1-uncompressed P-256 size (65 bytes: 0x04 || X || Y). A
    // shorter payload could not be a valid P-256 point; the validator
    // is the single structural gate so we must reject it here instead
    // of letting it pass and fail later inside `importEciesPublicKey`.
    const msg = {
      ...baseAcceptableMessage(),
      welcomeRecipientKemPublicKey: new Uint8Array(64).fill(4),
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'invalid-recipient-kem-public-key-length',
    });
  });

  test('drops Welcomes whose welcomeRecipientKemPublicKey is longer than 65 bytes', async () => {
    // Same rationale as the 64-byte case: anything other than the
    // fixed 65-byte uncompressed P-256 encoding is malformed and the
    // validator must fail fast rather than handing a wrong-length
    // buffer downstream.
    const msg = {
      ...baseAcceptableMessage(),
      welcomeRecipientKemPublicKey: new Uint8Array(66).fill(4),
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'invalid-recipient-kem-public-key-length',
    });
  });

  test('drops Welcomes missing eciesSealed (would wedge the recipient)', async () => {
    // Without the sealed keychain delta the recipient would record
    // `welcomeEpochId` as their `_invitationEpoch` but have no
    // corresponding key installed in their keychain, leaving them
    // unable to decrypt traffic and corrupting later `since_invited`
    // filtering. The validator must refuse to accept such a Welcome.
    const msg = baseAcceptableMessage();
    delete msg.eciesSealed;
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-ecies-sealed',
    });
  });

  test('drops Welcomes with empty eciesSealed (zero-length payload)', async () => {
    // An empty sealed payload carries no key material, so it has the
    // same wedge potential as a missing field. The validator must
    // reject it for the same reason.
    const msg = {
      ...baseAcceptableMessage(),
      eciesSealed: new Uint8Array(0),
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-ecies-sealed',
    });
  });

  test('silently drops Welcomes addressed to someone else', async () => {
    const msg = {
      ...baseAcceptableMessage(),
      welcomeRecipient: 'someone-else',
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({ kind: 'drop-not-for-us' });
  });

  test('drops Welcomes addressed to us when we are not in the readers ACL', async () => {
    const result = await evaluateBeeKEMWelcome(
      baseAcceptableMessage(),
      makeDeps({ isReader: async () => false }),
    );
    expect(result).toEqual({
      kind: 'drop-unauthorized',
      reason: 'not-in-readers-acl',
    });
  });

  test('drops unsigned Welcomes unconditionally (writer-auth is mandatory)', async () => {
    // SECURITY: writer-auth on Welcomes is
    // enforced regardless of the document-key signing toggle. An
    // unsigned Welcome must be dropped even when the swarm-wide
    // `enableSigning` is `false` -- otherwise any connected peer could
    // inject arbitrary `keychainChanges` and set `_invitationEpoch`
    // for an existing reader.
    const msg = baseAcceptableMessage();
    delete msg.signature;
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-unauthorized',
      reason: 'missing-signature',
    });
  });

  test('drops Welcomes with an invalid writer signature', async () => {
    const msg = { ...baseAcceptableMessage(), signature: 'sig-bytes' };
    const result = await evaluateBeeKEMWelcome(
      msg,
      makeDeps({
        verifyWriterSignature: async () => false,
      }),
    );
    expect(result).toEqual({
      kind: 'drop-unauthorized',
      reason: 'invalid-signature',
    });
  });

  test('accepts signed Welcomes when the writer signature verifies', async () => {
    let verifiedRawLength = 0;
    let verifiedSig = '';
    const msg = { ...baseAcceptableMessage(), signature: 'good-sig' };

    const result = await evaluateBeeKEMWelcome(
      msg,
      makeDeps({
        verifyWriterSignature: async (raw, sig) => {
          verifiedRawLength = raw.length;
          verifiedSig = sig;
          return true;
        },
      }),
    );

    expect(result.kind).toBe('accept');
    // The signature gate must verify over the message **without** the
    // signature field embedded -- otherwise the inviter's signing
    // convention (`_signWelcomeAsWriter` strips the signature before
    // signing) and the verification convention disagree.
    expect(verifiedSig).toBe('good-sig');
    expect(verifiedRawLength).toBeGreaterThan(0);
    const reSerialized = stubSerializer.serializeSyncMessage(msg);
    expect(verifiedRawLength).toBeLessThan(reSerialized.length);
  });

  test('gate ordering: missing welcomeEpochId takes precedence over missing welcomeRecipient', async () => {
    const msg: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: '/doc/welcome',
      // Both welcomeEpochId and welcomeRecipient are missing. The
      // epoch-id gate runs first so the reported reason is the
      // epoch-id one, matching the production handler's order.
    };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({
      kind: 'drop-malformed',
      reason: 'missing-welcome-epoch-id',
    });
  });

  test('gate ordering: not-for-us check runs before the readers-ACL check', async () => {
    // A Welcome addressed to someone else should never invoke
    // `isReader` -- otherwise a misaddressed Welcome would still leak
    // the ACL-membership probe to whatever provider the test wires in.
    let isReaderCalled = false;
    const msg = {
      ...baseAcceptableMessage(),
      welcomeRecipient: 'someone-else',
    };
    const result = await evaluateBeeKEMWelcome(
      msg,
      makeDeps({
        isReader: async () => {
          isReaderCalled = true;
          return false;
        },
      }),
    );
    expect(result).toEqual({ kind: 'drop-not-for-us' });
    expect(isReaderCalled).toBe(false);
  });

  test('gate ordering: readers-ACL check runs before signature verification', async () => {
    // A non-member should be rejected even if the signature would
    // verify; we should not feed the signature path with unauthorized
    // inputs.
    let verifyCalled = false;
    const msg = { ...baseAcceptableMessage(), signature: 'sig' };
    const result = await evaluateBeeKEMWelcome(
      msg,
      makeDeps({
        isReader: async () => false,
        verifyWriterSignature: async () => {
          verifyCalled = true;
          return true;
        },
      }),
    );
    expect(result).toEqual({
      kind: 'drop-unauthorized',
      reason: 'not-in-readers-acl',
    });
    expect(verifyCalled).toBe(false);
  });
});
