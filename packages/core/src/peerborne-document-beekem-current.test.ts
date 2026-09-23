import { afterEach, describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';
import { BeeKEM } from './beekem/beekem.js';
import { generateEciesKeyPair } from './ecies.js';
import { deriveEpochIdFromRootSecret } from './derive-doc-key.js';
import { serializePathUpdateV2ForWire } from './path-update-wire.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: { Accept: 'accept', Reject: 'reject' },
  }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

const serializer = {
  serializeSyncMessage(message: any): Uint8Array {
    return new TextEncoder().encode(
      JSON.stringify({
        ...message,
        pathUpdateEpochId: Array.from(message.pathUpdateEpochId),
      }),
    );
  },
  deserializeSyncMessage(bytes: Uint8Array): any {
    const value = JSON.parse(new TextDecoder().decode(bytes));
    return {
      ...value,
      pathUpdateEpochId: new Uint8Array(value.pathUpdateEpochId),
    };
  },
};

afterEach(() => jest.restoreAllMocks());

describe('document current BeeKEM delivery', () => {
  test('signed skipped, stale, obsolete, and wrong-parent updates cannot replace the live tree or append an epoch', async () => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'log').mockImplementation(() => {});
    const founderKeys = await generateEciesKeyPair();
    const readerKeys = await generateEciesKeyPair();
    const founder = new BeeKEM();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const { welcome } = await founder.addMember(readerKeys.publicKey);
    const reader = new BeeKEM();
    await reader.processWelcome(
      welcome,
      readerKeys.privateKey,
      readerKeys.publicKey,
    );
    const staleFounder = founder.clone();
    const signing = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const installedEpochs: Uint8Array[] = [];
    const prepareEpochKey = jest.fn(async (epoch: Uint8Array) => ({
      claimCommit: () => ({
        finalize: () => {
          installedEpochs.push(new Uint8Array(epoch));
        },
      }),
    }));
    const document: any = Object.assign(
      Object.create(PeerborneDocument.prototype),
      {
        documentPath: '/current-beekem',
        _bootstrapLoadApplicationState: 'complete',
        _beekem: reader,
        _beekemInitialized: true,
        _syncMessageSerializer: serializer,
        _keychain: { prepareEpochKey },
        _getWriterKeys: async () => [signing.publicKey],
        _deserializeSignature: (signature: string) =>
          new Uint8Array(Buffer.from(signature, 'base64')),
        _authProvider: {
          verify: async (
            data: Uint8Array,
            key: CryptoKey,
            signature: Uint8Array,
          ) =>
            crypto.subtle.verify(
              { name: 'ECDSA', hash: 'SHA-384' },
              key,
              signature as BufferSource,
              data as BufferSource,
            ),
        },
      },
    );
    async function deliver(
      update: Awaited<ReturnType<BeeKEM['update']>>,
      obsolete = false,
    ) {
      const pathUpdate: any = serializePathUpdateV2ForWire(update.pathUpdate);
      if (obsolete) {
        delete pathUpdate.version;
        delete pathUpdate.generation;
        delete pathUpdate.parentTreeHash;
      }
      const message = {
        documentId: document.documentPath,
        signatureContext: 'beekem-path-update-v2' as const,
        pathUpdate,
        pathUpdateEpochId: await deriveEpochIdFromRootSecret(update.rootSecret),
      };
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' },
        signing.privateKey,
        serializer.serializeSyncMessage(message) as BufferSource,
      );
      await document._handleBeeKEMPathUpdateRequestDataUnlocked(
        serializer.serializeSyncMessage({
          ...message,
          signature: Buffer.from(signature).toString('base64'),
        }),
      );
    }
    const first = await founder.update();
    const second = await founder.update();
    await deliver(second);
    expect(document._beekem).toBe(reader);
    expect(prepareEpochKey).not.toHaveBeenCalled();

    await deliver(first);
    await deliver(second);
    expect(installedEpochs).toHaveLength(2);
    expect(document._beekem.generation).toBe(second.pathUpdate.generation);
    const committedTree = document._beekem;
    const committedRoot = await committedTree.getRootSecret();
    expect(
      Buffer.from(committedRoot).equals(Buffer.from(second.rootSecret)),
    ).toBe(true);

    await deliver(first);
    await deliver(first, true);
    await staleFounder.update();
    await staleFounder.update();
    const wrongParent = await staleFounder.update();
    await deliver(wrongParent);
    expect(document._beekem).toBe(committedTree);
    expect(prepareEpochKey).toHaveBeenCalledTimes(2);
    expect(installedEpochs).toHaveLength(2);
    expect(
      Buffer.from(await committedTree.getRootSecret()).equals(
        Buffer.from(committedRoot),
      ),
    ).toBe(true);
  });
});
