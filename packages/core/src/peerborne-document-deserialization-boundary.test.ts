import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { eciesSeal } from './ecies.js';
import { encodeWelcomeSealedPayload } from './welcome-sealed-payload.js';

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

function loadHarness(message: any) {
  const verify = jest.fn(async () => true);
  const sync = jest.fn(async () => true);
  const document = fakeDocument({
    documentPath,
    swarm: { config: { loadQuorumTimeoutMs: 1000 } },
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: () => ({}) },
    _authProvider: {
      nonceBits: 1,
      decrypt: async () => new Uint8Array([1]),
      verify,
    },
    _syncMessageSerializer: {
      deserializeSyncMessage: () => message,
      serializeSyncMessage: () => new Uint8Array([1]),
    },
    _isSigningEnabled: () => true,
    _deserializeSignature: () => new Uint8Array([1]),
    _getWriterKeys: async () => ['writer'],
    _syncValidatedProtocolMessage: sync,
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
    encodeWelcomeSealedPayload({
      beekemWelcome: welcome,
      keychainChanges: new Uint8Array([1]),
    }),
    recipient.publicKey,
  );
  const { document, verify } = loadHarness(message);
  const epoch = new Uint8Array([1]);
  Object.assign(document, {
    _hashes: new Set(),
    _subscribed: false,
    _kemKeyPair: recipient,
    _kemPublicKeyRaw: new Uint8Array(
      await crypto.subtle.exportKey('raw', recipient.publicKey),
    ),
    _changesSerializer: { deserializeChanges: () => ({}) },
    _keychain: {
      merge: () => undefined,
      keys: async () => [[epoch, {}]],
      getKey: () => ({}),
    },
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
      ).rejects.toThrow(/data propert/);
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
      'load-response-v3',
    );
  });

  test.each([1, 2])(
    'rejects a load serializer that mutates on call %i',
    async (mutationCall) => {
      const message = {
        documentId: documentPath,
        signature: 'AQ==',
        changes: { kind: 'document', change: { value: 1 } },
      };
      const { document, stream, sync } = loadHarness(message);
      let serializationCount = 0;
      document._syncMessageSerializer.serializeSyncMessage = (
        unsigned: typeof message,
      ) => {
        serializationCount += 1;
        if (serializationCount === mutationCall) {
          unsigned.changes.change.value = 9;
        }
        return new Uint8Array([1]);
      };
      await expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).resolves.toBe(false);
      expect(sync).not.toHaveBeenCalled();
    },
  );

  test.each([1, 2])(
    'rejects an invitation serializer that mutates on call %i',
    async (mutationCall) => {
      const message = {
        documentId: documentPath,
        signature: 'AQ==',
        changes: { kind: 'document', change: { value: 1 } },
      };
      const { document, bundle, verify } = await invitationHarness(message);
      let serializationCount = 0;
      document._syncMessageSerializer.serializeSyncMessage = (
        unsigned: typeof message,
      ) => {
        serializationCount += 1;
        if (serializationCount === mutationCall) {
          unsigned.changes.change.value = 9;
        }
        return new Uint8Array([1]);
      };
      await expect(
        document.acceptInvitationBootstrap(bundle, 'issuer', 'reader', '/founder'),
      ).rejects.toThrow('Invitation bootstrap serialization is unstable');
      expect(verify).toHaveBeenCalledTimes(mutationCall === 1 ? 0 : 1);
    },
  );

  test.each(['documentId', 'changes'])(
    'rejects an accessor-backed invitation %s before routing or verification',
    async (field) => {
      const getter = jest.fn(() => field === 'documentId' ? documentPath : {});
      const message = { documentId: documentPath, signature: 'AQ==' };
      Object.defineProperty(message, field, { enumerable: true, get: getter });
      const { document, bundle, verify } = await invitationHarness(message);
      await expect(
        document.acceptInvitationBootstrap(bundle, 'issuer', 'reader', '/founder'),
      ).rejects.toThrow(/data propert/);
      expect(getter).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
    },
  );
});
