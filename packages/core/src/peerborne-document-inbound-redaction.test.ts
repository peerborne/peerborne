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

const privatePath = '/private/document/path';
const privateFailure =
  'provider failure with payload, CID bafy-private, path, and key material';

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: privatePath,
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    ...fields,
  });
}

function captureFailureLogs() {
  const error = jest
    .spyOn(console, 'error')
    .mockImplementation(() => undefined);
  const warn = jest
    .spyOn(console, 'warn')
    .mockImplementation(() => undefined);
  const log = jest
    .spyOn(console, 'log')
    .mockImplementation(() => undefined);
  const debug = jest
    .spyOn(console, 'debug')
    .mockImplementation(() => undefined);
  return {
    debug,
    error,
    log,
    warn,
    text: () =>
      [
        ...debug.mock.calls,
        ...error.mock.calls,
        ...log.mock.calls,
        ...warn.mock.calls,
      ]
        .flat()
        .join(' '),
    restore: () => {
      debug.mockRestore();
      error.mockRestore();
      log.mockRestore();
      warn.mockRestore();
    },
  };
}

describe('concrete inbound handler log redaction', () => {
  test('write authorization requires an explicit boolean true', async () => {
    const document = fakeDocument({
      _writers: {
        check: async () => ({ writer: true }) as never,
      },
    });
    await expect(document._ensureCurrentUserCanWrite()).rejects.toThrow(
      /does not have write permissions/,
    );
  });

  test.each([
    'handleLoadRequestData',
    'handleSnapshotLoadRequestData',
    'handleTipAdvertiseRequestData',
  ] as const)(
    '%s rejects a truthy non-boolean signature result',
    async (methodName) => {
      const current = jest.fn(async () => {
        throw new Error('authorization gate was bypassed');
      });
      const document = fakeDocument({
        _isSigningEnabled: () => true,
        _readers: { users: async () => [{}] },
        _writers: { users: async () => [] },
        _authProvider: {
          verify: async () => ({ truthy: true }) as never,
        },
        _keychain: { current },
      });
      const sink = jest.fn(async () => undefined);
      const logs = captureFailureLogs();

      try {
        await document[methodName](
          { documentId: privatePath, signature: 'AA==' },
          { sink },
        );
        expect(sink).toHaveBeenCalledTimes(1);
        expect(sink).toHaveBeenCalledWith([]);
        expect(current).not.toHaveBeenCalled();
      } finally {
        logs.restore();
      }
    },
  );

  test.each([
    'handleBeeKEMWelcomeRequestData',
    'handleBeeKEMPathUpdateRequestData',
    'handleKeyUpdateRequestData',
  ] as const)(
    '%s does no work after shared-handler admission expires',
    async (methodName) => {
      const deserializeSyncMessage = jest.fn(() => {
        throw new Error('must not deserialize after expiry');
      });
      const admission = {
        isActive: () => false,
        runMutation: jest.fn(),
      };
      const document = fakeDocument({
        _syncMessageSerializer: { deserializeSyncMessage },
      });

      await document[methodName](new Uint8Array([1, 2, 3]), admission);
      expect(deserializeSyncMessage).not.toHaveBeenCalled();
      expect(admission.runMutation).not.toHaveBeenCalled();
    },
  );

  test('key-update cannot merge after admission expires during verification', async () => {
    let active = true;
    const merge = jest.fn();
    const admission = {
      isActive: () => active,
      runMutation: jest.fn(async (operation: () => unknown) => {
        if (!active) return { admitted: false as const };
        return { admitted: true as const, value: await operation() };
      }),
    };
    const document = fakeDocument({
      _authProvider: { nonceBits: 1 },
      _keychainProvider: { keyIDLength: 1 },
      _decryptBlock: async () => new Uint8Array([9]),
      _syncMessageSerializer: {
        deserializeSyncMessage: () => ({
          documentId: privatePath,
          signature: 'AA==',
          keychainChanges: new Uint8Array([7]),
        }),
        serializeSyncMessage: () => new Uint8Array([8]),
      },
      _isSigningEnabled: () => true,
      _verifyWriterSignature: async () => {
        active = false;
        return true;
      },
      _keychain: { merge },
    });
    const logs = captureFailureLogs();

    try {
      await document.handleKeyUpdateRequestData(
        new Uint8Array([1, 2, 3]),
        admission,
      );
      expect(admission.runMutation).not.toHaveBeenCalled();
      expect(merge).not.toHaveBeenCalled();
    } finally {
      logs.restore();
    }
  });

  test.each([
    [
      'doc-load',
      'handleLoadRequestData',
      'Shared doc-load request handling failed',
    ],
    [
      'snapshot-load',
      'handleSnapshotLoadRequestData',
      'Shared snapshot-load request handling failed',
    ],
    [
      'tip-advertise',
      'handleTipAdvertiseRequestData',
      'Shared tip-advertise request handling failed',
    ],
  ] as const)(
    'redacts an internal provider failure in the real %s responder',
    async (_protocolName, methodName, classification) => {
      const document = fakeDocument({
        _isSigningEnabled: () => true,
        _readers: {
          users: async () => {
            throw new Error(privateFailure);
          },
        },
        _writers: { users: async () => [] },
      });
      const sink = jest.fn(async () => undefined);
      const logs = captureFailureLogs();

      try {
        await document[methodName](
          { documentId: privatePath, signature: 'signature' },
          { sink },
        );
        expect(logs.error).toHaveBeenCalledWith(classification);
        expect(sink).toHaveBeenCalledWith([]);
        expect(logs.text()).not.toContain(privateFailure);
        expect(logs.text()).not.toContain(privatePath);
      } finally {
        logs.restore();
      }
    },
  );

  test('redacts a serializer failure in the real BeeKEM Welcome handler', async () => {
    const document = fakeDocument({
      _syncMessageSerializer: {
        deserializeSyncMessage: () => {
          throw new Error(privateFailure);
        },
      },
    });
    const logs = captureFailureLogs();

    try {
      await document.handleBeeKEMWelcomeRequestData(new Uint8Array([1]));
      expect(logs.error).toHaveBeenCalledWith(
        'Shared BeeKEM Welcome handling failed',
      );
      expect(logs.text()).not.toContain(privateFailure);
      expect(logs.text()).not.toContain(privatePath);
    } finally {
      logs.restore();
    }
  });

  test('redacts a serializer failure in the real BeeKEM PathUpdate handler', async () => {
    const document = fakeDocument({
      _syncMessageSerializer: {
        deserializeSyncMessage: () => {
          throw new Error(privateFailure);
        },
      },
    });
    const logs = captureFailureLogs();

    try {
      await document.handleBeeKEMPathUpdateRequestData(new Uint8Array([2]));
      expect(logs.warn).toHaveBeenCalledWith(
        'Dropping malformed BeeKEM PathUpdate',
      );
      expect(logs.text()).not.toContain(privateFailure);
      expect(logs.text()).not.toContain(privatePath);
    } finally {
      logs.restore();
    }
  });

  test('redacts a decryptor failure in the real key-update handler', async () => {
    const document = fakeDocument({
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => {
          throw new Error(privateFailure);
        },
      },
      _keychain: { getKey: () => ({}) },
      _keychainProvider: { keyIDLength: 1 },
    });
    const logs = captureFailureLogs();

    try {
      await document.handleKeyUpdateRequestData(new Uint8Array([3, 4, 5]));
      expect(logs.warn).toHaveBeenCalledWith(
        'Failed to decrypt shared key-update request',
      );
      expect(logs.text()).not.toContain(privateFailure);
      expect(logs.text()).not.toContain(privatePath);
    } finally {
      logs.restore();
    }
  });
});
