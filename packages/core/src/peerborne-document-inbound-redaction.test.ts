import { describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: {
      Accept: 'accept',
      Ignore: 'ignore',
      Reject: 'reject',
    }, }),
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
  const undecryptableCases = [
    {
      name: 'an unknown key ID',
      getKey: () => undefined,
      decrypt: async (): Promise<Uint8Array> => {
        throw new Error('decrypt must not run without a key');
      },
    },
    {
      name: 'a known key with a failed authentication tag',
      getKey: () => new Uint8Array([7]),
      decrypt: async (): Promise<Uint8Array> => {
        throw new Error(privateFailure);
      },
    },
  ];

  function undecryptableDocument(
    testCase: (typeof undecryptableCases)[number],
    extra: Record<string, unknown> = {},
  ) {
    const addEventListener = jest.fn();
    const subscribe = jest.fn();
    const topicValidators = new Map<string, unknown>();
    const load = jest.fn(async () => true);
    const deserializeSyncMessage = jest.fn();
    const decrypt = jest.fn(testCase.decrypt);
    const document = fakeDocument({
      _invitationBootstrapReady: true,
      _hashes: new Set(),
      _computeTopic: () => '/topic',
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: jest.fn(testCase.getKey) },
      _authProvider: { nonceBytes: 1, decrypt },
      _syncMessageSerializer: { deserializeSyncMessage },
      load,
      swarm: {
        config: {},
        registerDocument: jest.fn(),
        heliaNode: {
          libp2p: {
            services: {
              pubsub: { addEventListener, subscribe, topicValidators },
            },
          },
        },
      },
      ...extra,
    });
    return { document, load, deserializeSyncMessage, topicValidators };
  }

  test.each(undecryptableCases)(
    'drops a pubsub message with $name without load or logs',
    async (testCase) => {
      const { document, load, deserializeSyncMessage } =
        undecryptableDocument(testCase);
      const logs = captureFailureLogs();

      try {
        await document.open();
        load.mockClear();
        deserializeSyncMessage.mockClear();
        for (let i = 0; i < 3; i++) {
          document._pubsubHandler({
            detail: {
              data: new Uint8Array([1, 2, 3]),
              topic: '/topic',
              type: 'signed',
              from: { toString: () => 'untrusted-sender' },
            },
          });
        }
        await new Promise<void>((resolve) => setImmediate(resolve));

        expect(load).not.toHaveBeenCalled();
        expect(deserializeSyncMessage).not.toHaveBeenCalled();
        expect(logs.text()).toBe('');
      } finally {
        logs.restore();
      }
    },
  );

  test.each(undecryptableCases)(
    'topic validator ignores a message with $name without logs',
    async (testCase) => {
      const { document, deserializeSyncMessage, topicValidators } =
        undecryptableDocument(testCase, { _isSigningEnabled: () => true });
      document.swarm.config.enableTopicValidators = true;
      const logs = captureFailureLogs();

      try {
        await document.open();
        const validator = topicValidators.get('/topic') as (
          peerId: unknown,
          message: { data: Uint8Array },
        ) => Promise<string>;
        expect(validator).toBeDefined();
        deserializeSyncMessage.mockClear();

        for (let i = 0; i < 3; i++) {
          await expect(
            validator(
              { toString: () => 'untrusted-sender' },
              { data: new Uint8Array([1, 2, 3]) },
            ),
          ).resolves.toBe('ignore');
        }

        expect(deserializeSyncMessage).not.toHaveBeenCalled();
        expect(logs.text()).toBe('');
      } finally {
        logs.restore();
      }
    },
  );

  test('observes and redacts rejected pubsub receive work', async () => {
    const addEventListener = jest.fn();
    const subscribe = jest.fn();
    const document = fakeDocument({
      _invitationBootstrapReady: true,
      _hashes: new Set(),
      _computeTopic: () => '/topic',
      _keychainProvider: { keyIDLength: 1 },
      _authProvider: { nonceBytes: 1 },
      _decryptBlock: async () => new Uint8Array([9]),
      _syncMessageSerializer: {
        deserializeSyncMessage: () => {
          throw new RangeError(privateFailure);
        },
      },
      swarm: {
        config: {},
        registerDocument: jest.fn(),
        heliaNode: {
          libp2p: {
            services: {
              pubsub: { addEventListener, subscribe },
            },
          },
        },
      },
    });
    const logs = captureFailureLogs();

    try {
      await document.open();
      document._pubsubHandler({
        detail: {
          data: new Uint8Array([1, 2, 3]),
          topic: '/topic',
          type: 'unsigned',
        },
      });
      await new Promise<void>((resolve) => setImmediate(resolve));

      expect(logs.error).toHaveBeenCalledWith(
        'Inbound sync message handling failed',
      );
      expect(logs.text()).not.toContain(privateFailure);
      expect(logs.text()).not.toContain(privatePath);
    } finally {
      logs.restore();
    }
  });

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
      const responseSend = jest.fn(() => true);
      const responseClose = jest.fn(async () => undefined);
      const logs = captureFailureLogs();

      try {
        await document[methodName](
          { documentId: privatePath, signature: 'AA==' },
          { send: responseSend, close: responseClose, onDrain: async () => {} },
        );
        expect(responseClose).toHaveBeenCalledTimes(1);
        expect(responseSend).not.toHaveBeenCalled();
        expect(responseClose).toHaveBeenCalled();
        expect(current).not.toHaveBeenCalled();
      } finally {
        logs.restore();
      }
    },
  );

  test.each([
    'handleBeeKEMWelcomeRequestData',
    'handleBeeKEMPathUpdateRequestData',
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
      const responseSend = jest.fn(() => true);
      const responseClose = jest.fn(async () => undefined);
      const logs = captureFailureLogs();

      try {
        await document[methodName](
          { documentId: privatePath, signature: 'signature' },
          { send: responseSend, close: responseClose, onDrain: async () => {} },
        );
        expect(logs.error).toHaveBeenCalledWith(classification);
        expect(responseSend).not.toHaveBeenCalled();
        expect(responseClose).toHaveBeenCalled();
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

  test('redacts a serializer failure in the real BeeKEM PathUpdateV2 handler', async () => {
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
        'Dropping malformed BeeKEM PathUpdateV2',
      );
      expect(logs.text()).not.toContain(privateFailure);
      expect(logs.text()).not.toContain(privatePath);
    } finally {
      logs.restore();
    }
  });

  test('redacts a rejected pending-Welcome drain', async () => {
    const document = fakeDocument({
      _pendingWelcomes: new Map([['pending', {}]]),
      _mutationQueue: {
        run: jest.fn(async () => {
          throw new Error(privateFailure);
        }),
      },
    });
    const logs = captureFailureLogs();

    try {
      document._schedulePendingWelcomeDrain();
      await Promise.resolve();
      await Promise.resolve();

      expect(logs.error).toHaveBeenCalledWith(
        'Failed to drain pending BeeKEM Welcomes',
      );
      expect(logs.text()).not.toContain(privateFailure);
      expect(logs.text()).not.toContain(privatePath);
    } finally {
      logs.restore();
    }
  });
});
