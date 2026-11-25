import { describe, expect, jest, test } from '@jest/globals';

import {
  PeerborneDocument,
} from './peerborne-document.js';
import { invitationCatchUpV1 } from './wire-protocols.js';

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


function catchUpHarness(
  conflicts: number,
  signatureValid = true,
  onConflict?: () => void,
) {
  const continuation = {};
  // Invitation catch-up runs inside the acceptance transaction, which already
  // owns the mutation FIFO, so model a writer change during verification.
  const verify = jest.fn(async () => {
    if (conflicts-- > 0) {
      document._writerKeysVersion++;
      onConflict?.();
    }
    return signatureValid;
  });
  const sync = jest.fn(async () => true);
  const streams: any[] = [];
  const requests: any[] = [];
  const newStream = jest.fn(async (_protocols: string[], _options: unknown) => {
    const stream = {
      send: () => true,
      onDrain: async () => undefined,
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
      abort: jest.fn(),
      async *[Symbol.asyncIterator]() { yield new Uint8Array([1, 2, 3]); },
    };
    streams.push(stream);
    return stream;
  });
  const dial = jest.fn(async (_address: unknown, _options: unknown) => ({
    remotePeer: { toString: () => 'founder-peer' },
    newStream,
  }));
  const document = fakeDocument({
    documentPath: '/invitation-retry',
    swarm: { config: {}, heliaNode: { libp2p: { dial } } },
    _encoder: new TextEncoder(),
    _serializeSignature: () => 'AQ==',
    _deserializeSignature: () => new Uint8Array([1]),
    _authProvider: {
      nonceBytes: 1,
      serializePublicKey: async (key: string) => key,
      deserializePublicKey: async (key: string) => key,
      sign: async () => new Uint8Array([1]),
      decrypt: async () => new Uint8Array([1]),
      verify,
    },
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: () => ({}) },
    _loadMessageSerializer: { serializeLoadRequest: (request: any) => {
      requests.push(request);
      return new Uint8Array([1]);
    } },
    _syncMessageSerializer: {
      deserializeSyncMessage: () => ({
        documentId: '/invitation-retry',
        signatureContext: 'invitation-catch-up-v1',
        loadChallenge: new Uint8Array(requests.at(-1).loadChallenge),
        signature: 'AQ==',
        tips: [],
      }),
      serializeSyncMessage: () => new Uint8Array([1]),
    },
    _writerKeysVersion: 0,
    _writerMutationsInFlight: 0,
    _hashes: new Set(['bootstrap-cid']),
    _bootstrapLoadApplicationState: 'pending',
    _activeInvitationBootstrapContinuation: continuation,
    _assertAcceptedInvitationMembership: jest.fn(async () => undefined),
    _syncUnlocked: sync,
    _mutationQueue: {
      run: async () => {
        throw new Error('invitation catch-up must not re-enter the FIFO');
      },
    },
  });
  const catchUp = () =>
    document._loadInvitationCatchUp('/founder', 'issuer', 'reader', continuation);
  return { document, verify, sync, dial, newStream, streams, requests, catchUp };
}

describe('invitation catch-up writer-version races', () => {
  test('addresses each request to the dialed connection peer', async () => {
    const { dial, newStream, requests, catchUp } = catchUpHarness(1);
    await expect(catchUp()).resolves.toBe(true);
    expect(requests.map((request) => request.responder)).toEqual([
      'founder-peer',
      'founder-peer',
    ]);
    expect(dial.mock.calls.map(([, options]) => (options as any).force)).toEqual([
      false,
      false,
    ]);
    expect(newStream).toHaveBeenCalledWith(
      [invitationCatchUpV1],
      expect.objectContaining({ runOnLimitedConnection: true }),
    );
  });

  test('retries a queued writer change with a fresh issuer-verified response', async () => {
    const { verify, sync, dial, streams, requests, catchUp } =
      catchUpHarness(1);
    await expect(catchUp()).resolves.toBe(true);
    expect(dial).toHaveBeenCalledTimes(2);
    expect(requests[0].loadChallenge).not.toEqual(requests[1].loadChallenge);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(sync).toHaveBeenCalledTimes(1);
    expect(streams[0].abort).toHaveBeenCalledTimes(1);
    expect(streams[1].closeRead).toHaveBeenCalledTimes(1);
  });

  test('bounds repeated writer conflicts to three attempts without applying state', async () => {
    const { sync, dial, catchUp } = catchUpHarness(Infinity);
    await expect(catchUp()).rejects.toThrow(/writer.*changed/i);
    expect(dial).toHaveBeenCalledTimes(3);
    expect(sync).not.toHaveBeenCalled();
  });

  test('shares one deadline across conflict retries', async () => {
    let now = 100;
    const clock = jest.spyOn(Date, 'now').mockImplementation(() => now);
    try {
      const { sync, dial, catchUp } = catchUpHarness(1, true, () => {
        now += 30_001;
      });
      await expect(catchUp()).rejects.toThrow(/deadline exceeded/);
      expect(dial).toHaveBeenCalledTimes(1);
      expect(sync).not.toHaveBeenCalled();
    } finally {
      clock.mockRestore();
    }
  });

  test('does not retry a rejected issuer signature', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const { verify, sync, dial, catchUp } = catchUpHarness(0, false);
      await expect(catchUp()).resolves.toBe(false);
      expect(dial).toHaveBeenCalledTimes(1);
      expect(verify).toHaveBeenCalledTimes(1);
      expect(sync).not.toHaveBeenCalled();
    } finally { warn.mockRestore(); }
  });
});
