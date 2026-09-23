import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { eciesSeal } from './ecies.js';
import { encodeWelcomeSealedPayloadV2 } from './welcome-sealed-payload.js';

import {
  PeerborneDocument,
} from './peerborne-document.js';

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

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), fields);
}


const documentPath = '/detached-load';

function loadHarness(message: any, context = 'load-response-v3') {
  const contextualMessage = Object.create(
    Object.getPrototypeOf(message),
    {
      ...Object.getOwnPropertyDescriptors(message),
      signatureContext: { value: context, enumerable: true },
      tips: { value: [], enumerable: true },
    },
  );
  const verify = jest.fn(async () => true);
  const sync = jest.fn(async () => true);
  const document = fakeDocument({
    documentPath,
    swarm: {
      config: { loadQuorumTimeoutMs: 1000 },
      isPendingInvitationDocument: () => true,
    },
    _writerKeysVersion: 0,
    _writerMutationsInFlight: 0,
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: () => ({}) },
    _authProvider: {
      nonceBytes: 1,
      decrypt: async () => new Uint8Array([1]),
      verify,
    },
    _syncMessageSerializer: {
      deserializeSyncMessage: () => contextualMessage,
      serializeSyncMessage: () => new Uint8Array([1]),
    },
    _isSigningEnabled: () => true,
    _deserializeSignature: () => new Uint8Array([1]),
    _getWriterKeys: async () => ['writer'],
    _syncUnlocked: sync,
    _mutationQueue: { run: (operation: () => Promise<unknown>) => operation() },
  });
  const stream = {
    sink: async () => undefined,
    source: (async function* () { yield new Uint8Array([1, 2, 3]); })(),
    abort: jest.fn(),
  };
  return { document, stream, verify, sync };
}

async function invitationHarness(message: any) {
  const founder = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
  );
  const recipient = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
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
  const { document, verify } = loadHarness(message, 'invitation-bootstrap-v1');
  const epoch = new Uint8Array([1]);
  Object.assign(document, {
    _hashes: new Set(),
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
    _subscribed: false,
    _kemKeyPair: recipient,
    _kemPublicKeyRaw: new Uint8Array(
      await crypto.subtle.exportKey('raw', recipient.publicKey),
    ),
    _changesSerializer: { deserializeChanges: () => ({}) },
    _keychain: {
      merge: () => undefined,
      keys: async () => [],
      getKey: () => ({}),
    },
  });
  document._keychain.prepareMerge = () => ({
      hydrateKeys: async () => [[epoch, {}]],
      currentKeyId: epoch,
      keyIds: [epoch],
      getKey: () => ({}),
      commit: () => undefined,
  });
  return {
    document, verify,
    bundle: {
      welcomeEpochId: epoch,
      sealedWelcome,
      encryptedBootstrap: new Uint8Array([1, 2, 3]),
    },
  };
}

describe('deserialized load message boundaries', () => {
  test.each(['documentId', 'changes'])(
    'rejects an accessor-backed load %s before routing or verification',
    async (field) => {
      const getter = jest.fn(() => field === 'documentId' ? documentPath : {});
      const message = { documentId: documentPath, signature: 'AQ==' };
      Object.defineProperty(message, field, { enumerable: true, get: getter });
      const { document, stream, verify, sync } = loadHarness(message);
      await expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).resolves.toBe(false);
      expect(getter).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
      expect(sync).not.toHaveBeenCalled();
    },
  );

  test('detaches load contents before awaiting the trusted writer set', async () => {
    const message = {
      documentId: documentPath,
      signature: 'AQ==',
      changes: { kind: 'document', change: { value: 1 } },
    };
    const { document, stream, sync } = loadHarness(message);
    document._getWriterKeys = async () => {
      message.documentId = '/substituted';
      message.changes.change.value = 9;
      return ['writer'];
    };
    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(true);
    expect(sync).toHaveBeenCalledWith(
      expect.objectContaining({
        documentId: documentPath,
        changes: { kind: 'document', change: { value: 1 } },
      }),
      false,
      'load-response-v3',
      undefined,
      false,
      undefined,
      expect.any(Object),
    );
  });

  test.each(['documentId', 'changes'])(
    'rejects an accessor-backed invitation %s before routing or verification',
    async (field) => {
      const getter = jest.fn(() => field === 'documentId' ? documentPath : {});
      const message = { documentId: documentPath, signature: 'AQ==' };
      Object.defineProperty(message, field, { enumerable: true, get: getter });
      const { document, bundle, verify } = await invitationHarness(message);
      await expect(
        document.acceptInvitationBootstrap(bundle, 'issuer', 'reader', '/founder'),
      ).rejects.toThrow(/malformed or cross-context fields/);
      expect(getter).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
    },
  );
});
