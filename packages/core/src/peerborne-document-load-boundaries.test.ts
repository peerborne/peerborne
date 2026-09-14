import { describe, expect, jest, test } from '@jest/globals';

import {
  MAX_DOCUMENT_LOAD_RESPONSE_SIZE,
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

describe('document load response boundaries', () => {
  test('bounds ordinary document responses before deserialization', async () => {
    const abort = jest.fn();
    const document = fakeDocument({
      swarm: { config: { loadQuorumTimeoutMs: 1000 } },
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      source: (async function* () {
        yield new Uint8Array(MAX_DOCUMENT_LOAD_RESPONSE_SIZE + 1);
      })(),
      abort,
    };

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/maximum allowed size/);
    expect(abort).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Document load response rejected' }),
    );
  });

  test('aborts a normal load whose peer withholds response EOF', async () => {
    jest.useFakeTimers();
    const abort = jest.fn();
    const document = fakeDocument({
      swarm: { config: { loadQuorumTimeoutMs: 25 } },
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      source: {
        [Symbol.asyncIterator]: () => ({
          next: () => new Promise<IteratorResult<Uint8Array>>(() => {}),
        }),
      },
      abort,
    };

    try {
      const result = expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).rejects.toThrow(/response deadline exceeded/);
      await jest.advanceTimersByTimeAsync(25);
      await result;
      expect(abort).toHaveBeenCalledTimes(1);
      expect(abort).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Document load response deadline exceeded',
        }),
      );
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
  });

  test('fully aborts a completed probe even when the peer response ends early', async () => {
    const rawStream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
      abort: jest.fn(),
      async *[Symbol.asyncIterator]() {
        yield new Uint8Array([0xff]);
      },
    };
    const document = fakeDocument({
      swarm: {
        heliaNode: {
          libp2p: { dialProtocol: jest.fn(async () => rawStream) },
        },
      },
    });

    await expect(
      document._probeTipAdvertise({}, new Uint8Array([1])),
    ).resolves.toBe('unknown-doc');
    expect(rawStream.close).toHaveBeenCalledTimes(1);
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
    expect(rawStream.abort).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'tip-advertise probe completed' }),
    );
    expect(rawStream.closeRead).not.toHaveBeenCalled();
  });
});
