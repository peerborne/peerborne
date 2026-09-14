import { describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
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
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/membership-preflight',
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    ...fields,
  });
}

async function validKemPublicKey(): Promise<Uint8Array> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  )) as CryptoKeyPair;
  return new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey),
  );
}

describe('reader membership preflight', () => {
  test('key projection failure precedes ACL and BeeKEM mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const registerBeeKEMReader = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _keychainChangesForWelcome: jest.fn(async () => {
        throw new Error('Current-key projection is unavailable');
      }),
      _makeChange: makeChange,
      _registerBeeKEMReader: registerBeeKEMReader,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document.addReader({ reader: true }, readerKemPublicKey),
    ).rejects.toThrow(/Current-key projection is unavailable/);
    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(registerBeeKEMReader).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });

  test('passes one detached preflight projection to the Welcome sender', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const reader = { reader: true };
    const serializedProjection = new Uint8Array([1, 2, 3]);
    const welcome = { generation: 1 };
    const keychainChangesForWelcome = jest.fn(async () => ({ key: true }));
    const sendBeeKEMWelcome = jest.fn(async () => undefined);
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add: jest.fn(async () => ({ acl: true })),
      },
      _changesSerializer: {
        serializeChanges: jest.fn(() => serializedProjection),
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: jest.fn(async () => {
        serializedProjection.fill(9);
      }),
      _registerBeeKEMReader: jest.fn(async () => welcome),
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(document.addReader(reader, readerKemPublicKey)).resolves.toBe(
      welcome,
    );
    expect(keychainChangesForWelcome).toHaveBeenCalledTimes(1);
    expect(sendBeeKEMWelcome).toHaveBeenCalledWith(
      reader,
      readerKemPublicKey,
      welcome,
      new Uint8Array([1, 2, 3]),
    );
  });

  test('rejects base64-expanded Welcome capacity before mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const registerBeeKEMReader = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _changesSerializer: {
        serializeChanges: jest.fn(() => new Uint8Array(900 * 1024)),
      },
      _keychainChangesForWelcome: jest.fn(async () => ({ key: true })),
      _makeChange: makeChange,
      _registerBeeKEMReader: registerBeeKEMReader,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document.addReader({ reader: true }, readerKemPublicKey),
    ).rejects.toThrow(/too large before onboarding/);
    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(registerBeeKEMReader).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });
});
