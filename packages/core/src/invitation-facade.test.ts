import { describe, expect, jest, test } from '@jest/globals';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('libp2p', () => ({}), { virtual: true });
jest.mock('@libp2p/peer-id', () => ({ peerIdFromString: jest.fn() }), {
  virtual: true,
});
jest.mock(
  '@multiformats/multiaddr',
  () => ({ multiaddr: jest.fn((value: string) => value) }),
  { virtual: true },
);
jest.mock('./peerborne-config.js', () => ({
  defaultBootstrapConfig: jest.fn(),
  defaultConfig: jest.fn(),
}));
jest.mock('./peerborne-document.js', () => ({
  PeerborneDocument: class {},
}));
jest.mock('./helia-node.js', () => ({
  createAndStartHeliaNode: jest.fn(),
}));

import { Peerborne } from './peerborne.js';
import { createAndStartHeliaNode } from './helia-node.js';
import {
  INVITATION_ID_LENGTH,
  type InvitationOfferV1,
} from './invitation-wire.js';

const MAX_ACTIVE_INVITATION_OFFERS = 128;

function createFacade(): Peerborne<
  unknown,
  unknown,
  unknown,
  unknown,
  unknown,
  unknown
> {
  return new Peerborne(
    { id: 'recipient-private' },
    { id: 'recipient-public' },
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
  );
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((fulfill, fail) => {
    resolve = fulfill;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function invitationOffer(
  seed: number,
  documentId: string,
  issuer = 'issuer-key',
): InvitationOfferV1 {
  const now = Date.now();
  return {
    version: 1,
    invitationId: new Uint8Array(INVITATION_ID_LENGTH).fill(seed),
    documentId,
    issuer,
    role: 'reader',
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    rendezvous: ['/ip4/127.0.0.1/tcp/4001'],
    signature: new Uint8Array(64).fill(seed + 1),
  };
}

describe('public invitation facade', () => {
  test('rejects reinitialization while invitation acceptance is active', async () => {
    const peerborne = createFacade();
    const pending = new Map([['/pending-invitation', { id: 'document' }]]);
    (peerborne as any)._pendingInvitationDocuments = pending;

    await expect(peerborne.initialize({} as never)).rejects.toThrow(
      /invitation acceptance is active/,
    );
    expect(createAndStartHeliaNode).not.toHaveBeenCalled();
    expect((peerborne as any)._pendingInvitationDocuments).toBe(pending);
    expect(pending.size).toBe(1);
  });

  test('rejects invitation acceptance while initialization is active', async () => {
    const peerborne = createFacade();
    let rejectInitialization!: (error: Error) => void;
    jest.mocked(createAndStartHeliaNode).mockReturnValueOnce(
      new Promise((_resolve, reject) => {
        rejectInitialization = reject;
      }),
    );

    const initialization = peerborne.initialize({
      enableNetworkStats: false,
      loadQuorumEnabled: false,
      helia: {},
    } as never);
    await expect(
      peerborne.acceptInvitation(
        new Uint8Array([0xff]),
        {} as CryptoKeyPair,
      ),
    ).rejects.toThrow(/initialization is active/);

    rejectInitialization(new Error('test initialization stopped'));
    await expect(initialization).rejects.toThrow(/test initialization stopped/);
    expect((peerborne as any)._initializationInFlight).toBe(false);
  });

  test('does not register an offer if its document closes during signing', async () => {
    const peerborne = createFacade();
    const signStarted = deferred<void>();
    const signature = deferred<Uint8Array>();
    (peerborne as any)._invitationSignatureProvider = () => ({
      serializePublicKey: async () => 'founder-key',
      sign: async () => {
        signStarted.resolve();
        return signature.promise;
      },
      verify: async () => true,
    });
    const document = {
      documentPath: '/closed-during-signing',
      historyVisibility: 'full_history',
      assertCanCreateInitialInvitation: async () => {},
      getKemPublicKeyRaw: () => new Uint8Array([4]),
    };
    (peerborne as any)._documentRegistry.set(
      document.documentPath,
      document,
    );

    const creating = peerborne.createInvitationForDocument(
      document as never,
      {
        role: 'reader',
        rendezvous: ['/ip4/127.0.0.1/tcp/4001'],
      },
    );
    await signStarted.promise;
    (peerborne as any)._documentRegistry.delete(document.documentPath);
    signature.resolve(new Uint8Array(64).fill(7));

    await expect(creating).rejects.toThrow(/closed before offer registration/);
    expect((peerborne as any)._invitationRegistry.size).toBe(0);
  });

  test('enforces offer capacity again at the synchronous commit point', async () => {
    const peerborne = createFacade();
    const signatures: Array<(value: Uint8Array) => void> = [];
    const bothSigning = deferred<void>();
    (peerborne as any)._invitationSignatureProvider = () => ({
      serializePublicKey: async () => 'founder-key',
      sign: async () =>
        new Promise<Uint8Array>((resolve) => {
          signatures.push(resolve);
          if (signatures.length === 2) bothSigning.resolve();
        }),
      verify: async () => true,
    });

    const existingDocument = { documentPath: '/existing' };
    (peerborne as any)._documentRegistry.set(
      existingDocument.documentPath,
      existingDocument,
    );
    for (let i = 0; i < MAX_ACTIVE_INVITATION_OFFERS - 1; i++) {
      (peerborne as any)._invitationRegistry.set(`existing-${i}`, {
        offer: invitationOffer(i + 1, '/existing', 'founder-key'),
        document: existingDocument,
      });
    }
    const documents = ['/capacity-a', '/capacity-b'].map((documentPath) => ({
      documentPath,
      historyVisibility: 'full_history',
      assertCanCreateInitialInvitation: async () => {},
      getKemPublicKeyRaw: () => new Uint8Array([4]),
    }));
    for (const document of documents) {
      (peerborne as any)._documentRegistry.set(
        document.documentPath,
        document,
      );
    }

    const creations = documents.map((document) =>
      peerborne.createInvitationForDocument(document as never, {
        role: 'reader',
        rendezvous: ['/ip4/127.0.0.1/tcp/4001'],
      }),
    );
    await bothSigning.promise;
    for (const resolve of signatures) {
      resolve(new Uint8Array(64).fill(9));
    }
    const results = await Promise.allSettled(creations);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(
      1,
    );
    const rejection = results.find(
      (result): result is PromiseRejectedResult =>
        result.status === 'rejected',
    );
    expect(rejection?.reason).toBeInstanceOf(Error);
    expect((rejection?.reason as Error).message).toMatch(
      /Cannot create more than 128 active invitations/,
    );
    expect((peerborne as any)._invitationRegistry.size).toBe(
      MAX_ACTIVE_INVITATION_OFFERS,
    );
  });

  test('enforces retry capacity again before caching a signed request', async () => {
    const peerborne = createFacade();
    const signatures: Array<(value: Uint8Array) => void> = [];
    const bothSigning = deferred<void>();
    const serializePublicKey = async (key: { id: string }) =>
      key.id === 'issuer-public' ? 'issuer-key' : 'recipient-key';
    const signatureProvider = {
      serializePublicKey,
      sign: async () =>
        new Promise<Uint8Array>((resolve) => {
          signatures.push(resolve);
          if (signatures.length === 2) bothSigning.resolve();
        }),
      verify: async () => true,
    };
    (peerborne as any)._authProvider = {
      ...signatureProvider,
      deserializePublicKey: async () => ({ id: 'issuer-public' }),
    };
    (peerborne as any)._invitationSignatureProvider = () =>
      signatureProvider;
    (peerborne as any)._heliaNode = {
      libp2p: {
        dialProtocol: jest.fn(async () => {
          throw new Error('test rendezvous unavailable');
        }),
      },
    };
    const now = Date.now();
    for (let i = 0; i < MAX_ACTIVE_INVITATION_OFFERS - 1; i++) {
      (peerborne as any)._outboundInvitationRequests.set(`retry-${i}`, {
        request: {},
        expiresAtMs: now + 60_000,
      });
    }
    const offers = [
      invitationOffer(91, '/retry-capacity-a'),
      invitationOffer(92, '/retry-capacity-b'),
    ];
    const documents = offers.map(() => ({
      setKemKeyPair: async () => {},
      getKemPublicKeyRaw: () => {
        const key = new Uint8Array(65).fill(3);
        key[0] = 4;
        return key;
      },
    }));
    const kemKeyPair = {
      privateKey: { id: 'kem-private' },
      publicKey: { id: 'kem-public' },
    } as unknown as CryptoKeyPair;

    const acceptances = offers.map((offer, index) =>
      (peerborne as any)._acceptInvitationOffer(
        offer,
        kemKeyPair,
        documents[index],
      ) as Promise<unknown>,
    );
    await bothSigning.promise;
    for (const resolve of signatures) {
      resolve(new Uint8Array(64).fill(10));
    }
    const results = await Promise.allSettled(acceptances);
    const messages = results.map((result) =>
      result.status === 'rejected' && result.reason instanceof Error
        ? result.reason.message
        : '',
    );

    expect(results.every((result) => result.status === 'rejected')).toBe(true);
    expect(messages).toContain(
      'Cannot track more than 128 invitation retries',
    );
    expect(messages.some((message) =>
      message.includes('test rendezvous unavailable'),
    )).toBe(true);
    expect((peerborne as any)._outboundInvitationRequests.size).toBe(
      MAX_ACTIVE_INVITATION_OFFERS,
    );
  });

  test('rejects disabled signing before parsing or KEM/network work', async () => {
    const peerborne = createFacade();
    (peerborne as any)._config = { enableSigning: false };
    const doc = jest.fn();
    (peerborne as any).doc = doc;

    await expect(
      peerborne.acceptInvitation(
        new Uint8Array([0xff]),
        {} as CryptoKeyPair,
      ),
    ).rejects.toThrow(/require application-level signing/);
    expect(doc).not.toHaveBeenCalled();
  });

  test('canonicalizes decoded offers and snapshots the KEM record synchronously', async () => {
    const peerborne = createFacade();
    const now = Date.now();
    const mutableOffer = {
      version: 1,
      invitationId: new Uint8Array(INVITATION_ID_LENGTH).fill(1),
      documentId: '/facade-copy',
      issuer: 'issuer-key',
      role: 'reader',
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      rendezvous: ['/ip4/127.0.0.1/tcp/4001'],
      signature: new Uint8Array(96).fill(2),
    } satisfies InvitationOfferV1;
    const firstPrivate = { id: 'first-private' } as unknown as CryptoKey;
    const firstPublic = { id: 'first-public' } as unknown as CryptoKey;
    const mutableKem = {
      privateKey: firstPrivate,
      publicKey: firstPublic,
    };
    const fakeDocument = { id: 'document' };
    let capturedOffer: InvitationOfferV1 | undefined;
    let capturedKem: CryptoKeyPair | undefined;
    (peerborne as any).doc = jest.fn(() => fakeDocument);
    (peerborne as any)._acceptInvitationOffer = jest.fn(
      async (offer: InvitationOfferV1, kem: CryptoKeyPair) => {
        capturedOffer = offer;
        capturedKem = kem;
        return fakeDocument;
      },
    );

    const accepted = peerborne.acceptInvitation(mutableOffer, mutableKem);
    mutableOffer.invitationId[0] = 9;
    mutableOffer.rendezvous[0] = '/ip4/203.0.113.1/tcp/9999';
    mutableOffer.signature[0] = 9;
    mutableKem.privateKey = { id: 'second-private' } as unknown as CryptoKey;
    mutableKem.publicKey = { id: 'second-public' } as unknown as CryptoKey;

    await expect(accepted).resolves.toBe(fakeDocument);
    expect(capturedOffer).toBeDefined();
    expect(capturedOffer).not.toBe(mutableOffer);
    expect(capturedOffer?.invitationId[0]).toBe(1);
    expect(capturedOffer?.rendezvous).toEqual([
      '/ip4/127.0.0.1/tcp/4001',
    ]);
    expect(capturedOffer?.signature[0]).toBe(2);
    expect(capturedKem?.privateKey).toBe(firstPrivate);
    expect(capturedKem?.publicKey).toBe(firstPublic);
    expect(Object.isFrozen(capturedKem)).toBe(true);
  });
});
