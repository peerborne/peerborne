import { describe, expect, test } from '@jest/globals';

import { SubtleCrypto } from './auth-subtlecrypto.js';
import {
  assertInvitationBootstrapEpochBinding,
  DEFAULT_INVITATION_CLOCK_SKEW_MS,
  INVITATION_WIRE_VERSION,
  InvitationAcceptanceV1,
  InvitationJoinRequestV1,
  InvitationOfferV1,
  InvitationSignatureProvider,
  InvitationWireError,
  MAX_INVITATION_DOCUMENT_ID_BYTES,
  MAX_INVITATION_MESSAGE_BYTES,
  MAX_INVITATION_OPAQUE_PAYLOAD_BYTES,
  MAX_INVITATION_RENDEZVOUS_ENTRIES,
  MAX_INVITATION_TTL_MS,
  UnsignedInvitationAcceptanceV1,
  UnsignedInvitationJoinRequestV1,
  UnsignedInvitationOfferV1,
  assertInvitationAcceptanceMatches,
  assertInvitationAcceptanceUsable,
  assertInvitationJoinMatchesOffer,
  assertInvitationOfferUsable,
  decodeInvitationAcceptance,
  decodeInvitationJoinRequest,
  decodeInvitationOffer,
  digestInvitationJoinRequest,
  digestInvitationOffer,
  encodeInvitationAcceptance,
  encodeInvitationJoinRequest,
  encodeInvitationOffer,
  invitationAcceptanceSigningBytes,
  invitationJoinRequestSigningBytes,
  invitationOfferSigningBytes,
  signInvitationAcceptance,
  signInvitationJoinRequest,
  signInvitationOffer,
  verifyInvitationAcceptance,
  verifyInvitationJoinRequest,
  verifyInvitationOffer,
} from './invitation-wire.js';

const NOW = 2_000_000_000_000;
const auth = new SubtleCrypto();

interface SigningIdentity {
  readonly keys: CryptoKeyPair;
  readonly serialized: string;
}

function bytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((fulfill) => {
    resolve = fulfill;
  });
  return { promise, resolve };
}

async function signingIdentity(): Promise<SigningIdentity> {
  const keys = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return { keys, serialized: await auth.serializePublicKey(keys.publicKey) };
}

async function makeOffer(
  issuer: SigningIdentity,
  overrides: Partial<UnsignedInvitationOfferV1> = {},
): Promise<InvitationOfferV1> {
  const unsigned: UnsignedInvitationOfferV1 = {
    version: INVITATION_WIRE_VERSION,
    invitationId: bytes(32, 1),
    documentId: '/documents/launch-plan',
    issuer: issuer.serialized,
    role: 'editor',
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000,
    rendezvous: ['/dns4/relay.peerborne.io/tcp/443/wss'],
    ...overrides,
  };
  return signInvitationOffer(
    unsigned,
    issuer.keys.privateKey,
    issuer.keys.publicKey,
    auth,
  );
}

async function makeJoinRequest(
  offer: InvitationOfferV1,
  recipient: SigningIdentity,
  overrides: Partial<UnsignedInvitationJoinRequestV1> = {},
): Promise<InvitationJoinRequestV1> {
  const unsigned: UnsignedInvitationJoinRequestV1 = {
    version: INVITATION_WIRE_VERSION,
    offerDigest: await digestInvitationOffer(offer),
    requestId: bytes(32, 2),
    documentId: offer.documentId,
    role: offer.role,
    recipient: recipient.serialized,
    recipientKemPublicKey: bytes(65, 3),
    ...overrides,
  };
  unsigned.recipientKemPublicKey[0] = 4;
  return signInvitationJoinRequest(
    unsigned,
    recipient.keys.privateKey,
    recipient.keys.publicKey,
    auth,
  );
}

async function makeAcceptance(
  offer: InvitationOfferV1,
  request: InvitationJoinRequestV1,
  issuer: SigningIdentity,
  overrides: Partial<UnsignedInvitationAcceptanceV1> = {},
): Promise<InvitationAcceptanceV1> {
  const unsigned: UnsignedInvitationAcceptanceV1 = {
    version: INVITATION_WIRE_VERSION,
    acceptanceId: bytes(32, 4),
    offerDigest: await digestInvitationOffer(offer),
    requestDigest: await digestInvitationJoinRequest(request),
    documentId: offer.documentId,
    issuer: offer.issuer,
    recipient: request.recipient,
    recipientKemPublicKey: request.recipientKemPublicKey.slice(),
    role: request.role,
    welcomeEpochId: bytes(32, 5),
    sealedWelcome: bytes(125, 6),
    encryptedBootstrap: bytes(64, 7),
    issuedAtMs: NOW,
    expiresAtMs: offer.expiresAtMs,
    ...overrides,
  };
  return signInvitationAcceptance(
    unsigned,
    issuer.keys.privateKey,
    issuer.keys.publicKey,
    auth,
  );
}

function expectWireCode(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error('expected InvitationWireError');
  } catch (error) {
    expect(error).toBeInstanceOf(InvitationWireError);
    expect(error).toMatchObject({ code });
  }
}

async function expectWireCodeAsync(
  action: () => Promise<unknown>,
  code: string,
): Promise<void> {
  try {
    await action();
    throw new Error('expected InvitationWireError');
  } catch (error) {
    expect(error).toBeInstanceOf(InvitationWireError);
    expect(error).toMatchObject({ code });
  }
}

describe('public invitation wire format', () => {
  test('round-trips offer, join, and acceptance through canonical codecs', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);
    const acceptance = await makeAcceptance(offer, request, issuer);

    const decodedOffer = decodeInvitationOffer(encodeInvitationOffer(offer));
    const decodedRequest = decodeInvitationJoinRequest(
      encodeInvitationJoinRequest(request),
    );
    const decodedAcceptance = decodeInvitationAcceptance(
      encodeInvitationAcceptance(acceptance),
    );

    expect(decodedOffer).toEqual(offer);
    expect(decodedRequest).toEqual(request);
    expect(decodedAcceptance).toEqual(acceptance);
    expect(encodeInvitationOffer(decodedOffer)).toEqual(
      encodeInvitationOffer(offer),
    );
    expect(encodeInvitationJoinRequest(decodedRequest)).toEqual(
      encodeInvitationJoinRequest(request),
    );
    expect(encodeInvitationAcceptance(decodedAcceptance)).toEqual(
      encodeInvitationAcceptance(acceptance),
    );
  });

  test('signatures are domain-separated and bound to wire identities', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const stranger = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);
    const acceptance = await makeAcceptance(offer, request, issuer);

    await expect(verifyInvitationOffer(offer, issuer.keys.publicKey, auth)).resolves.toBe(
      true,
    );
    await expect(
      verifyInvitationJoinRequest(request, recipient.keys.publicKey, auth),
    ).resolves.toBe(true);
    await expect(
      verifyInvitationAcceptance(acceptance, issuer.keys.publicKey, auth),
    ).resolves.toBe(true);
    await expect(
      verifyInvitationOffer(offer, stranger.keys.publicKey, auth),
    ).resolves.toBe(false);

    await expect(
      auth.verify(
        invitationJoinRequestSigningBytes(request),
        issuer.keys.publicKey,
        offer.signature,
      ),
    ).resolves.toBe(false);
  });

  test('signers snapshot every envelope before awaiting the provider', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const baseOffer = await makeOffer(issuer);
    const baseRequest = await makeJoinRequest(baseOffer, recipient);
    const baseAcceptance = await makeAcceptance(
      baseOffer,
      baseRequest,
      issuer,
    );

    const { signature: _offerSignature, ...unsignedOffer } =
      decodeInvitationOffer(encodeInvitationOffer(baseOffer));
    const offerBytes = invitationOfferSigningBytes(unsignedOffer);
    const offerIdentity = deferred<string>();
    let observedOfferBytes: Uint8Array | undefined;
    const signingOffer = signInvitationOffer(
      unsignedOffer,
      {},
      {},
      {
        serializePublicKey: () => offerIdentity.promise,
        sign: async (data) => {
          observedOfferBytes = data.slice();
          return bytes(64, 81);
        },
        verify: async () => true,
      },
    );
    unsignedOffer.invitationId[0] ^= 1;
    unsignedOffer.rendezvous[0] = '/ip4/203.0.113.1/tcp/1';
    (unsignedOffer as { documentId: string }).documentId = '/mutated';
    offerIdentity.resolve(issuer.serialized);
    const signedOffer = await signingOffer;
    expect(observedOfferBytes).toEqual(offerBytes);
    expect(invitationOfferSigningBytes(signedOffer)).toEqual(offerBytes);

    const { signature: _requestSignature, ...unsignedRequest } =
      decodeInvitationJoinRequest(encodeInvitationJoinRequest(baseRequest));
    const requestBytes = invitationJoinRequestSigningBytes(unsignedRequest);
    const requestIdentity = deferred<string>();
    let observedRequestBytes: Uint8Array | undefined;
    const signingRequest = signInvitationJoinRequest(
      unsignedRequest,
      {},
      {},
      {
        serializePublicKey: () => requestIdentity.promise,
        sign: async (data) => {
          observedRequestBytes = data.slice();
          return bytes(64, 82);
        },
        verify: async () => true,
      },
    );
    unsignedRequest.requestId[0] ^= 1;
    unsignedRequest.recipientKemPublicKey[1] ^= 1;
    (unsignedRequest as { documentId: string }).documentId = '/mutated';
    requestIdentity.resolve(recipient.serialized);
    const signedRequest = await signingRequest;
    expect(observedRequestBytes).toEqual(requestBytes);
    expect(invitationJoinRequestSigningBytes(signedRequest)).toEqual(
      requestBytes,
    );

    const { signature: _acceptanceSignature, ...unsignedAcceptance } =
      decodeInvitationAcceptance(
        encodeInvitationAcceptance(baseAcceptance),
      );
    const acceptanceBytes =
      invitationAcceptanceSigningBytes(unsignedAcceptance);
    const acceptanceIdentity = deferred<string>();
    let observedAcceptanceBytes: Uint8Array | undefined;
    const signingAcceptance = signInvitationAcceptance(
      unsignedAcceptance,
      {},
      {},
      {
        serializePublicKey: () => acceptanceIdentity.promise,
        sign: async (data) => {
          observedAcceptanceBytes = data.slice();
          return bytes(64, 83);
        },
        verify: async () => true,
      },
    );
    unsignedAcceptance.acceptanceId[0] ^= 1;
    unsignedAcceptance.sealedWelcome[0] ^= 1;
    unsignedAcceptance.encryptedBootstrap[0] ^= 1;
    (unsignedAcceptance as { documentId: string }).documentId = '/mutated';
    acceptanceIdentity.resolve(issuer.serialized);
    const signedAcceptance = await signingAcceptance;
    expect(observedAcceptanceBytes).toEqual(acceptanceBytes);
    expect(invitationAcceptanceSigningBytes(signedAcceptance)).toEqual(
      acceptanceBytes,
    );
  });

  test('verifiers snapshot every envelope before awaiting the provider', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const baseOffer = await makeOffer(issuer);
    const baseRequest = await makeJoinRequest(baseOffer, recipient);
    const baseAcceptance = await makeAcceptance(
      baseOffer,
      baseRequest,
      issuer,
    );

    const mutableOffer = decodeInvitationOffer(encodeInvitationOffer(baseOffer));
    const expectedOfferBytes = invitationOfferSigningBytes(mutableOffer);
    const expectedOfferSignature = mutableOffer.signature.slice();
    const offerIdentity = deferred<string>();
    let verifiedOfferBytes: Uint8Array | undefined;
    let verifiedOfferSignature: Uint8Array | undefined;
    const offerVerification = verifyInvitationOffer(mutableOffer, {}, {
      serializePublicKey: () => offerIdentity.promise,
      sign: async () => bytes(64, 1),
      verify: async (data, _key, signature) => {
        verifiedOfferBytes = data.slice();
        verifiedOfferSignature = signature.slice();
        return true;
      },
    });
    mutableOffer.invitationId[0] ^= 1;
    mutableOffer.signature[0] ^= 1;
    (mutableOffer as { documentId: string }).documentId = '/mutated';
    offerIdentity.resolve(issuer.serialized);
    await expect(offerVerification).resolves.toBe(true);
    expect(verifiedOfferBytes).toEqual(expectedOfferBytes);
    expect(verifiedOfferSignature).toEqual(expectedOfferSignature);

    const mutableRequest = decodeInvitationJoinRequest(
      encodeInvitationJoinRequest(baseRequest),
    );
    const expectedRequestBytes =
      invitationJoinRequestSigningBytes(mutableRequest);
    const expectedRequestSignature = mutableRequest.signature.slice();
    const requestIdentity = deferred<string>();
    let verifiedRequestBytes: Uint8Array | undefined;
    let verifiedRequestSignature: Uint8Array | undefined;
    const requestVerification = verifyInvitationJoinRequest(
      mutableRequest,
      {},
      {
        serializePublicKey: () => requestIdentity.promise,
        sign: async () => bytes(64, 1),
        verify: async (data, _key, signature) => {
          verifiedRequestBytes = data.slice();
          verifiedRequestSignature = signature.slice();
          return true;
        },
      },
    );
    mutableRequest.requestId[0] ^= 1;
    mutableRequest.signature[0] ^= 1;
    (mutableRequest as { documentId: string }).documentId = '/mutated';
    requestIdentity.resolve(recipient.serialized);
    await expect(requestVerification).resolves.toBe(true);
    expect(verifiedRequestBytes).toEqual(expectedRequestBytes);
    expect(verifiedRequestSignature).toEqual(expectedRequestSignature);

    const mutableAcceptance = decodeInvitationAcceptance(
      encodeInvitationAcceptance(baseAcceptance),
    );
    const expectedAcceptanceBytes =
      invitationAcceptanceSigningBytes(mutableAcceptance);
    const expectedAcceptanceSignature = mutableAcceptance.signature.slice();
    const acceptanceIdentity = deferred<string>();
    let verifiedAcceptanceBytes: Uint8Array | undefined;
    let verifiedAcceptanceSignature: Uint8Array | undefined;
    const acceptanceVerification = verifyInvitationAcceptance(
      mutableAcceptance,
      {},
      {
        serializePublicKey: () => acceptanceIdentity.promise,
        sign: async () => bytes(64, 1),
        verify: async (data, _key, signature) => {
          verifiedAcceptanceBytes = data.slice();
          verifiedAcceptanceSignature = signature.slice();
          return true;
        },
      },
    );
    mutableAcceptance.acceptanceId[0] ^= 1;
    mutableAcceptance.signature[0] ^= 1;
    mutableAcceptance.sealedWelcome[0] ^= 1;
    acceptanceIdentity.resolve(issuer.serialized);
    await expect(acceptanceVerification).resolves.toBe(true);
    expect(verifiedAcceptanceBytes).toEqual(expectedAcceptanceBytes);
    expect(verifiedAcceptanceSignature).toEqual(expectedAcceptanceSignature);
  });

  test('tampering with signed semantic or opaque fields is detected', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);
    const acceptance = await makeAcceptance(offer, request, issuer);

    const tamperedOffer = { ...offer, documentId: '/documents/other' };
    const tamperedKem = request.recipientKemPublicKey.slice();
    tamperedKem[20] ^= 1;
    const tamperedRequest = { ...request, recipientKemPublicKey: tamperedKem };
    const tamperedBootstrap = acceptance.encryptedBootstrap.slice();
    tamperedBootstrap[0] ^= 1;
    const tamperedAcceptance = {
      ...acceptance,
      encryptedBootstrap: tamperedBootstrap,
    };

    await expect(
      verifyInvitationOffer(tamperedOffer, issuer.keys.publicKey, auth),
    ).resolves.toBe(false);
    await expect(
      verifyInvitationJoinRequest(
        tamperedRequest,
        recipient.keys.publicKey,
        auth,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyInvitationAcceptance(
        tamperedAcceptance,
        issuer.keys.publicKey,
        auth,
      ),
    ).resolves.toBe(false);
  });

  test('signing refuses a public key that does not match the wire identity', async () => {
    const issuer = await signingIdentity();
    const stranger = await signingIdentity();
    await expectWireCodeAsync(
      () =>
        makeOffer(issuer).then((offer) => {
          const { signature: _signature, ...unsigned } = offer;
          return signInvitationOffer(
            unsigned,
            issuer.keys.privateKey,
            stranger.keys.publicKey,
            auth,
          );
        }),
      'identity-mismatch',
    );
  });

  test('signing refuses providers without a canonical identity serializer', async () => {
    const issuer = await signingIdentity();
    const offer = await makeOffer(issuer);
    const { signature: _signature, ...unsigned } = offer;
    await expectWireCodeAsync(
      () =>
        signInvitationOffer(
          unsigned,
          issuer.keys.privateKey,
          issuer.keys.publicKey,
          {
            sign: auth.sign.bind(auth),
            verify: auth.verify.bind(auth),
          } as unknown as InvitationSignatureProvider<CryptoKey, CryptoKey>,
        ),
      'missing-identity-serializer',
    );
  });

  test('rejects alternate JSON, trailing fields, and padded Base64', async () => {
    const issuer = await signingIdentity();
    const offer = await makeOffer(issuer);
    const encoded = encodeInvitationOffer(offer);
    const text = new TextDecoder().decode(encoded);

    expectWireCode(
      () => decodeInvitationOffer(new TextEncoder().encode(`${text} `)),
      'non-canonical-encoding',
    );

    const trailing = JSON.parse(text) as unknown[];
    trailing.push('ignored');
    expectWireCode(
      () =>
        decodeInvitationOffer(
          new TextEncoder().encode(JSON.stringify(trailing)),
        ),
      'invalid-encoding',
    );

    const padded = JSON.parse(text) as unknown[];
    padded[2] = `${String(padded[2])}=`;
    expectWireCode(
      () =>
        decodeInvitationOffer(new TextEncoder().encode(JSON.stringify(padded))),
      'invalid-encoding',
    );
  });

  test('rejects unsupported versions, malformed UTF-8, and wrong key widths', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);

    const versioned = JSON.parse(
      new TextDecoder().decode(encodeInvitationOffer(offer)),
    ) as unknown[];
    versioned[1] = 2;
    expectWireCode(
      () =>
        decodeInvitationOffer(
          new TextEncoder().encode(JSON.stringify(versioned)),
        ),
      'unsupported-version',
    );
    expectWireCode(
      () => decodeInvitationOffer(new Uint8Array([0xff])),
      'invalid-encoding',
    );

    const shortKem = JSON.parse(
      new TextDecoder().decode(encodeInvitationJoinRequest(request)),
    ) as unknown[];
    shortKem[7] = 'AA';
    expectWireCode(
      () =>
        decodeInvitationJoinRequest(
          new TextEncoder().encode(JSON.stringify(shortKem)),
        ),
      'invalid-field',
    );

    await expectWireCodeAsync(
      () => makeOffer(issuer, { documentId: '/documents/control\u0000byte' }),
      'invalid-field',
    );
  });

  test('enforces envelope, rendezvous, and lifetime limits before signing', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    expectWireCode(
      () =>
        decodeInvitationOffer(
          new Uint8Array(MAX_INVITATION_MESSAGE_BYTES + 1),
        ),
      'size-limit',
    );

    await expectWireCodeAsync(
      () =>
        makeOffer(issuer, {
          rendezvous: Array.from(
            { length: MAX_INVITATION_RENDEZVOUS_ENTRIES + 1 },
            (_, i) => `/dns4/relay-${i}.peerborne.io/tcp/443/wss`,
          ),
        }),
      'size-limit',
    );
    await expectWireCodeAsync(
      () =>
        makeOffer(issuer, {
          rendezvous: ['/dns4/repeated', '/dns4/repeated'],
        }),
      'invalid-field',
    );
    await expectWireCodeAsync(
      () =>
        makeOffer(issuer, {
          issuedAtMs: NOW,
          expiresAtMs: NOW + MAX_INVITATION_TTL_MS + 1,
        }),
      'size-limit',
    );
    await expectWireCodeAsync(
      () =>
        makeOffer(issuer, {
          documentId: 'x'.repeat(MAX_INVITATION_DOCUMENT_ID_BYTES + 1),
        }),
      'size-limit',
    );

    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);
    const accepted = await makeAcceptance(offer, request, issuer);
    expectWireCode(
      () =>
        encodeInvitationAcceptance({
          ...accepted,
          sealedWelcome: new Uint8Array(
            MAX_INVITATION_OPAQUE_PAYLOAD_BYTES + 1,
          ),
        }),
      'size-limit',
    );
  });
});

describe('public invitation expiry and binding', () => {
  test('binds the encrypted bootstrap key prefix to the signed epoch', () => {
    const advertisedEpoch = bytes(32, 7);
    expect(() =>
      assertInvitationBootstrapEpochBinding(
        advertisedEpoch,
        advertisedEpoch.slice(),
      ),
    ).not.toThrow();

    const differentEpoch = advertisedEpoch.slice();
    differentEpoch[31] ^= 1;
    expect(() =>
      assertInvitationBootstrapEpochBinding(
        advertisedEpoch,
        differentEpoch,
      ),
    ).toThrow(/does not match its signed acceptance/);
  });

  test('uses hard expiration with bounded future clock skew', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);
    const acceptance = await makeAcceptance(offer, request, issuer);

    expect(() => assertInvitationOfferUsable(offer, NOW)).not.toThrow();
    expect(() =>
      assertInvitationAcceptanceUsable(acceptance, NOW),
    ).not.toThrow();
    expectWireCode(
      () => assertInvitationOfferUsable(offer, offer.expiresAtMs),
      'expired',
    );
    expectWireCode(
      () =>
        assertInvitationOfferUsable(
          offer,
          offer.issuedAtMs - DEFAULT_INVITATION_CLOCK_SKEW_MS - 1,
        ),
      'not-yet-valid',
    );
    expectWireCode(
      () =>
        assertInvitationOfferUsable(offer, offer.expiresAtMs, {
          clockSkewMs: DEFAULT_INVITATION_CLOCK_SKEW_MS,
        }),
      'expired',
    );
    expectWireCode(
      () =>
        assertInvitationOfferUsable(offer, NOW, {
          clockSkewMs: MAX_INVITATION_TTL_MS + 1,
        }),
      'invalid-field',
    );
  });

  test('binds join requests to the exact offer, document, and role', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);

    await expect(assertInvitationJoinMatchesOffer(request, offer)).resolves.toBeUndefined();

    const forged = await makeJoinRequest(offer, recipient, {
      documentId: '/documents/different',
    });
    await expectWireCodeAsync(
      () => assertInvitationJoinMatchesOffer(forged, offer),
      'binding-mismatch',
    );

    const wrongRole = await makeJoinRequest(offer, recipient, {
      role: 'reader',
    });
    await expectWireCodeAsync(
      () => assertInvitationJoinMatchesOffer(wrongRole, offer),
      'binding-mismatch',
    );
  });

  test('binds acceptance to recipient identity, KEM key, and offer lifetime', async () => {
    const issuer = await signingIdentity();
    const recipient = await signingIdentity();
    const otherRecipient = await signingIdentity();
    const offer = await makeOffer(issuer);
    const request = await makeJoinRequest(offer, recipient);
    const acceptance = await makeAcceptance(offer, request, issuer);

    await expect(
      assertInvitationAcceptanceMatches(acceptance, offer, request),
    ).resolves.toBeUndefined();

    const repointed = await makeAcceptance(offer, request, issuer, {
      recipient: otherRecipient.serialized,
    });
    await expectWireCodeAsync(
      () => assertInvitationAcceptanceMatches(repointed, offer, request),
      'binding-mismatch',
    );

    const otherKem = request.recipientKemPublicKey.slice();
    otherKem[10] ^= 1;
    const reboundKem = await makeAcceptance(offer, request, issuer, {
      recipientKemPublicKey: otherKem,
    });
    await expectWireCodeAsync(
      () => assertInvitationAcceptanceMatches(reboundKem, offer, request),
      'binding-mismatch',
    );

    const extended = await makeAcceptance(offer, request, issuer, {
      expiresAtMs: offer.expiresAtMs + 1,
    });
    await expectWireCodeAsync(
      () => assertInvitationAcceptanceMatches(extended, offer, request),
      'binding-mismatch',
    );
  });
});
