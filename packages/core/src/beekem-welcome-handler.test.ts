import { describe, expect, test } from '@jest/globals';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import {
  evaluateBeeKEMWelcome,
  evaluateBeeKEMWelcomeTransition,
  WelcomeValidationDeps,
} from './beekem-welcome-handler.js';

/**
 * Direct unit-test coverage for BeeKEM Welcome validation gates.
 *
 * The validation gates have been extracted from
 * `PeerborneDocument.handleBeeKEMWelcomeRequestData` into the pure
 * `evaluateBeeKEMWelcome` helper so each gate can be exercised directly
 * here with injected collaborators rather than a full libp2p/Helia stack.
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
    return new TextEncoder().encode(
      JSON.stringify(message, (_key, value) =>
        value instanceof Uint8Array
          ? { __testBytes: Array.from(value) }
          : value,
      ),
    );
  },
  deserializeSyncMessage(data: Uint8Array) {
    return JSON.parse(
      new TextDecoder().decode(data),
      (_key, value) =>
        value &&
        typeof value === 'object' &&
        Array.isArray(value.__testBytes)
          ? new Uint8Array(value.__testBytes)
          : value,
    ) as CRDTSyncMessage<ChangesType, PublicKey>;
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
 * A structurally acceptable Welcome under the injected verifier. The base
 * message carries a signature so the unit fixture reaches the accept path.
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

describe('evaluateBeeKEMWelcome unit gates', () => {
  test('accepts a structurally acceptable Welcome under the injected verifier', async () => {
    const result = await evaluateBeeKEMWelcome(baseAcceptableMessage(), makeDeps());
    expect(result.kind).toBe('accept');
  });

  test('drops Welcomes for a different document path', async () => {
    const msg = { ...baseAcceptableMessage(), documentId: '/doc/other' };
    const result = await evaluateBeeKEMWelcome(msg, makeDeps());
    expect(result).toEqual({ kind: 'drop-malformed', reason: 'wrong-document' });
  });

  test('routes and verifies only the exact detached codec snapshot', async () => {
    const target = {
      ...baseAcceptableMessage(),
      documentId: '/doc/other',
    };
    let documentIdReads = 0;
    const unstable = new Proxy(target, {
      get(object, property, receiver) {
        if (property === 'documentId') {
          documentIdReads++;
          return documentIdReads === 1 ? '/doc/welcome' : '/doc/other';
        }
        return Reflect.get(object, property, receiver);
      },
    });
    let verified = false;
    const serializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => unstable,
    } as unknown as SyncMessageSerializer<ChangesType, PublicKey>;

    const result = await evaluateBeeKEMWelcome(
      baseAcceptableMessage(),
      makeDeps({
        syncMessageSerializer: serializer,
        verifyWriterSignature: async () => {
          verified = true;
          return true;
        },
      }),
    );

    expect(result).toEqual({ kind: 'drop-malformed', reason: 'wrong-document' });
    expect(documentIdReads).toBe(0);
    expect(verified).toBe(false);
  });

  test('rejects accessor-backed codec output without invoking it', async () => {
    let getterCalls = 0;
    const accessorMessage = { ...baseAcceptableMessage() };
    Object.defineProperty(accessorMessage, 'documentId', {
      enumerable: true,
      get() {
        getterCalls++;
        return '/doc/welcome';
      },
    });
    const serializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => accessorMessage,
    } as unknown as SyncMessageSerializer<ChangesType, PublicKey>;

    await expect(
      evaluateBeeKEMWelcome(
        baseAcceptableMessage(),
        makeDeps({ syncMessageSerializer: serializer }),
      ),
    ).resolves.toEqual({
      kind: 'drop-malformed',
      reason: 'invalid-welcome-encoding',
    });
    expect(getterCalls).toBe(0);
  });

  test.each([undefined, ''])(
    'drops Welcomes with a missing or empty document path (%p)',
    async (documentId) => {
      const msg = {
        ...baseAcceptableMessage(),
        documentId,
      } as unknown as CRDTSyncMessage<ChangesType, PublicKey>;
      const result = await evaluateBeeKEMWelcome(msg, makeDeps());
      expect(result).toEqual({
        kind: 'drop-malformed',
        reason: 'wrong-document',
      });
    },
  );

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
    // A truthy check alone passes empty `Uint8Array` values, but an empty ID
    // cannot identify an installed keychain boundary. Reject it before any
    // invitation state is applied.
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

  test.each([31, 33])(
    'drops Welcomes whose epoch ID is not exactly 32 bytes (%i)',
    async (length) => {
      const result = await evaluateBeeKEMWelcome(
        {
          ...baseAcceptableMessage(),
          welcomeEpochId: new Uint8Array(length),
        },
        makeDeps(),
      );
      expect(result).toEqual({
        kind: 'drop-malformed',
        reason: 'missing-welcome-epoch-id',
      });
    },
  );

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
      reason: 'invalid-recipient-kem-public-key-length',
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
    // unable to decrypt traffic and leaving the local anchor unsupported by
    // installed key material. The validator must refuse such a Welcome.
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
    expect(result).toMatchObject({
      kind: 'drop-unauthorized',
      reason: 'not-in-readers-acl',
    });
  });

  test('allows the ACL check to be bypassed when writer-authorized bootstrap is enabled', async () => {
    let readerCheckCalled = false;
    const result = await evaluateBeeKEMWelcome(
      baseAcceptableMessage(),
      makeDeps({
        allowWriterAuthorizedBootstrap: true,
        isReader: async () => {
          readerCheckCalled = true;
          return false;
        },
      }),
    );
    expect(result.kind).toBe('accept');
    expect(readerCheckCalled).toBe(false);
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

  test.each(['false', {}])(
    'rejects truthy non-boolean writer verification result %#',
    async (verificationResult) => {
      const result = await evaluateBeeKEMWelcome(
        baseAcceptableMessage(),
        makeDeps({
          verifyWriterSignature: async () =>
            verificationResult as unknown as boolean,
        }),
      );
      expect(result).toEqual({
        kind: 'drop-unauthorized',
        reason: 'invalid-signature',
      });
    },
  );

  test.each(['false', {}])(
    'rejects truthy non-boolean reader authorization result %#',
    async (readerResult) => {
      const result = await evaluateBeeKEMWelcome(
        baseAcceptableMessage(),
        makeDeps({
          isReader: async () => readerResult as unknown as boolean,
        }),
      );
      expect(result).toMatchObject({
        kind: 'drop-unauthorized',
        reason: 'not-in-readers-acl',
      });
    },
  );

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

  test('gate ordering: signature verification runs before the readers-ACL check', async () => {
    let verifyCalled = false;
    let isReaderCalled = false;
    const msg = { ...baseAcceptableMessage(), signature: 'sig' };
    const result = await evaluateBeeKEMWelcome(
      msg,
      makeDeps({
        isReader: async () => {
          isReaderCalled = true;
          return false;
        },
        verifyWriterSignature: async () => {
          verifyCalled = true;
          return false;
        },
      }),
    );
    expect(result).toEqual({
      kind: 'drop-unauthorized',
      reason: 'invalid-signature',
    });
    expect(verifyCalled).toBe(true);
    expect(isReaderCalled).toBe(false);
  });
});

describe('evaluateBeeKEMWelcomeTransition', () => {
  test('rejects v1 replacement of generation-bearing state', () => {
    expect(evaluateBeeKEMWelcomeTransition(4, 1, undefined)).toEqual({
      kind: 'reject',
      reason: 'legacy-downgrade',
    });
  });

  test.each([3, 4])(
    'rejects non-increasing v2 generation %i over generation 4',
    (incomingGeneration) => {
      expect(
        evaluateBeeKEMWelcomeTransition(4, 2, incomingGeneration),
      ).toEqual({ kind: 'reject', reason: 'non-increasing-v2' });
    },
  );

  test('accepts a strictly newer v2 generation', () => {
    expect(evaluateBeeKEMWelcomeTransition(4, 2, 5)).toEqual({
      kind: 'accept',
    });
  });
});
