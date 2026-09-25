import { beforeAll, describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { eciesSeal } from './ecies.js';
import { encodeWelcomeSealedPayloadV2 } from './welcome-sealed-payload.js';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { JSONSerializer } from './json-serializer.js';
import type { SyncMessageContext } from './sync-message-context.js';

import { PeerborneDocument } from './peerborne-document.js';

jest.mock(
  'it-pipe',
  () => ({
    pipe: async (...stages: unknown[]) => {
      let value = stages[0];
      for (const stage of stages.slice(1)) {
        value = await (stage as (input: unknown) => unknown)(value);
      }
      return value;
    },
  }),
  { virtual: true },
);
jest.mock(
  'multiformats',
  () => ({
    CID: class {
      static parse(value: string) {
        return { toString: () => value };
      }
    },
  }),
  { virtual: true },
);
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Reject: 'reject' } }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

const documentPath = '/signature-relabel';
const serializer = new JSONSerializer<any, CryptoKey>();
const auth = new SubtleCrypto();
let writer: CryptoKeyPair;

beforeAll(async () => {
  writer = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
});

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    _authProvider: auth,
    _syncMessageSerializer: serializer,
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    ...fields,
  });
}

async function signedWire(
  signedAs: string,
  deliveredAs: SyncMessageContext,
  extraFields: Record<string, unknown> = {},
): Promise<Uint8Array> {
  const body = {
    documentId: documentPath,
    signatureContext: signedAs,
    changeId: 'root',
    changes: { kind: 'document', change: { value: 1 } },
    ...extraFields,
  };
  const signer = fakeDocument({ _userKey: writer.privateKey });
  const signature: string = await signer._signAsWriterUnconditional(body);
  return serializer.serializeSyncMessage({
    ...body,
    signatureContext: deliveredAs,
    signature,
  });
}

function loadHarness(plaintext: Uint8Array) {
  const sync = jest.fn(async () => true);
  const document = fakeDocument({
    swarm: { config: { loadQuorumTimeoutMs: 1000 } },
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: () => ({}) },
    _authProvider: {
      nonceBits: 1,
      decrypt: async () => plaintext,
      verify: auth.verify.bind(auth),
    },
    _isSigningEnabled: () => true,
    _getWriterKeys: async () => [writer.publicKey],
    _hashes: new Set(),
    _bootstrapLoadApplicationState: 'complete',
    _syncUnlocked: sync,
  });
  const stream = {
    sink: async () => undefined,
    source: (async function* () {
      yield new Uint8Array([1, 2, 3]);
    })(),
    abort: jest.fn(),
  };
  return { document, stream, sync };
}

async function invitationHarness(plaintext: Uint8Array) {
  const founder = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const recipient = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const tree = new BeeKEM();
  await tree.initialize(founder.privateKey, founder.publicKey);
  const { welcome } = await tree.addMember(recipient.publicKey);
  const sealedWelcome = await eciesSeal(
    encodeWelcomeSealedPayloadV2({
      beekemWelcome: welcome,
      keychainChanges: new Uint8Array([1]),
    }),
    recipient.publicKey,
  );
  const epoch = new Uint8Array([1]);
  const sync = jest.fn(async () => true);
  const document = fakeDocument({
    _keychainProvider: { keyIDLength: 1 },
    _authProvider: {
      nonceBits: 1,
      decrypt: async () => plaintext,
      verify: auth.verify.bind(auth),
    },
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
    _hashes: new Set(),
    _subscribed: false,
    _createdLocally: false,
    _kemKeyPair: recipient,
    _kemPublicKeyRaw: new Uint8Array(
      await crypto.subtle.exportKey('raw', recipient.publicKey),
    ),
    _changesSerializer: {
      deserializeChanges: () => ({}),
      serializeChanges: () => new Uint8Array([1]),
    },
    _keychain: {
      merge: () => undefined,
      keys: async () => [],
      getKey: () => undefined,
      prepareMerge: () => ({
        changes: {},
        keyIds: [epoch],
        currentKeyId: epoch,
        hydrateKeys: async () => [[epoch, {}]],
        getKey: () => ({}),
        commit: () => undefined,
      }),
    },
    _syncUnlocked: sync,
  });
  return {
    document,
    sync,
    bundle: {
      welcomeEpochId: epoch,
      sealedWelcome,
      encryptedBootstrap: new Uint8Array([1, 2, 3]),
    },
  };
}

describe('context-relabeled signed sync messages', () => {
  describe('ordinary sync', () => {
    function ordinaryDocument() {
      const collectACL = jest.fn(() => undefined);
      const document = fakeDocument({
        _isSigningEnabled: () => true,
        _getWriterKeys: async () => [writer.publicKey],
        _collectACLFromTree: collectACL,
      });
      return { document, collectACL };
    }

    test('accepts a genuinely signed ordinary message', async () => {
      const { document, collectACL } = ordinaryDocument();
      const message = serializer.deserializeSyncMessage(
        await signedWire('ordinary-sync-v1', 'ordinary-sync-v1'),
      );
      await expect(document.sync(message)).resolves.toBe(true);
      expect(collectACL).toHaveBeenCalled();
    });

    test.each([
      'load-response-v3',
      'invitation-bootstrap-v1',
      'document-publish-v1',
    ] as const)(
      'rejects a %s signature relabeled as ordinary sync',
      async (signedAs) => {
        const { document, collectACL } = ordinaryDocument();
        const message = serializer.deserializeSyncMessage(
          await signedWire(signedAs, 'ordinary-sync-v1'),
        );
        await expect(document.sync(message)).resolves.toBe(false);
        expect(collectACL).not.toHaveBeenCalled();
      },
    );
  });

  describe('load response v3', () => {
    test('accepts a genuinely signed load response', async () => {
      const { document, stream, sync } = loadHarness(
        await signedWire('load-response-v3', 'load-response-v3'),
      );
      await expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).resolves.toBe(true);
      expect(sync).toHaveBeenCalledWith(
        expect.objectContaining({ signatureContext: 'load-response-v3' }),
        false,
        'load-response-v3',
        undefined,
        false,
        undefined,
        expect.anything(),
      );
    });

    test.each([
      'ordinary-sync-v1',
      'invitation-bootstrap-v1',
      'document-publish-v1',
    ] as const)(
      'rejects a %s signature relabeled as a load response',
      async (signedAs) => {
        const { document, stream, sync } = loadHarness(
          await signedWire(signedAs, 'load-response-v3'),
        );
        await expect(
          document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
        ).resolves.toBe(false);
        expect(sync).not.toHaveBeenCalled();
      },
    );
  });

  describe('invitation bootstrap', () => {
    test('verifies a genuinely signed invitation bootstrap', async () => {
      const { document, bundle, sync } = await invitationHarness(
        await signedWire('invitation-bootstrap-v1', 'invitation-bootstrap-v1', {
          keychainChanges: { key: 'epoch' },
        }),
      );
      await expect(
        document.acceptInvitationBootstrap(
          bundle,
          writer.publicKey,
          'reader',
          '/founder',
        ),
      ).rejects.toThrow(/advertised CIDs were not installed/);
      expect(sync).toHaveBeenCalledWith(
        expect.objectContaining({ signatureContext: 'invitation-bootstrap-v1' }),
        false,
        'invitation-bootstrap-v1',
        undefined,
        true,
        undefined,
        expect.anything(),
      );
    });

    test.each([
      'load-response-v3',
      'ordinary-sync-v1',
      'document-publish-v1',
    ] as const)(
      'rejects a %s signature relabeled as an invitation bootstrap',
      async (signedAs) => {
        const { document, bundle, sync } = await invitationHarness(
          await signedWire(signedAs, 'invitation-bootstrap-v1'),
        );
        await expect(
          document.acceptInvitationBootstrap(
            bundle,
            writer.publicKey,
            'reader',
            '/founder',
          ),
        ).rejects.toThrow('Invitation bootstrap signature does not match the offer issuer');
        expect(sync).not.toHaveBeenCalled();
      },
    );
  });
});
