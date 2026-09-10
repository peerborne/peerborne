import { afterEach, describe, expect, jest, test } from '@jest/globals';
import { Peerborne } from './peerborne.js';
import {
  beekemPathUpdateV2,
  beekemWelcomeV2,
  documentKeyUpdateV2,
  documentLoadV4,
  snapshotLoadV4,
} from './wire-protocols.js';

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
jest.mock('./peerborne-config.js', () => ({
  defaultBootstrapConfig: jest.fn(),
  defaultConfig: jest.fn(),
}));
jest.mock('./peerborne-document.js', () => ({ PeerborneDocument: class {} }));
jest.mock('./helia-node.js', () => ({
  createAndStartHeliaNode: jest.fn(),
}));
jest.mock('@libp2p/peer-id', () => ({ peerIdFromString: jest.fn() }), {
  virtual: true,
});
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});

type RegisteredHandler = (stream: unknown) => Promise<void>;

function makePeerborneWithHandlers(): {
  handlers: Map<string, RegisteredHandler>;
  peerborne: Peerborne<unknown, unknown, unknown, unknown, unknown, unknown>;
} {
  const handlers = new Map<string, RegisteredHandler>();
  const libp2p = {
    handle: jest.fn(
      async (protocol: string, handler: RegisteredHandler): Promise<void> => {
        handlers.set(protocol, handler);
      },
    ),
  };
  const loadSerializer = {
    deserializeLoadRequest: jest.fn(() => {
      throw new Error('incomplete request');
    }),
  };
  const peerborne = new Peerborne(
    {},
    {},
    {} as never,
    {} as never,
    {} as never,
    loadSerializer as never,
    {} as never,
    {} as never,
    {} as never,
  );
  (peerborne as any)._heliaNode = { libp2p };
  return { handlers, peerborne };
}

function makeStalledStream(firstChunk: Uint8Array) {
  let readCount = 0;
  let rejectPending: ((error: Error) => void) | undefined;
  const iterator: AsyncIterator<Uint8Array> = {
    next: jest.fn(() => {
      if (readCount++ === 0) {
        return Promise.resolve({ done: false as const, value: firstChunk });
      }
      return new Promise<IteratorResult<Uint8Array>>((_, reject) => {
        rejectPending = reject;
      });
    }),
    return: jest.fn(async () => ({ done: true as const, value: undefined })),
  };
  const stream = {
    [Symbol.asyncIterator]: () => iterator,
    send: jest.fn(() => true),
    onDrain: jest.fn(async () => undefined),
    close: jest.fn(async () => undefined),
    abort: jest.fn((error: Error) => {
      rejectPending?.(error);
    }),
  };
  return { stream, iterator };
}

function makeDribblingStream(intervalMs: number) {
  let readCount = 0;
  let pendingTimer: ReturnType<typeof setTimeout> | undefined;
  let rejectPending: ((error: Error) => void) | undefined;
  const iterator: AsyncIterator<Uint8Array> = {
    next: jest.fn(() => {
      if (readCount++ === 0) {
        return Promise.resolve({
          done: false as const,
          value: new TextEncoder().encode('{'),
        });
      }
      return new Promise<IteratorResult<Uint8Array>>((resolve, reject) => {
        rejectPending = reject;
        pendingTimer = setTimeout(() => {
          pendingTimer = undefined;
          rejectPending = undefined;
          resolve({ done: false, value: new Uint8Array([0x20]) });
        }, intervalMs);
      });
    }),
    return: jest.fn(async () => {
      if (pendingTimer !== undefined) clearTimeout(pendingTimer);
      return { done: true as const, value: undefined };
    }),
  };
  const stream = {
    [Symbol.asyncIterator]: () => iterator,
    send: jest.fn(() => true),
    onDrain: jest.fn(async () => undefined),
    close: jest.fn(async () => undefined),
    abort: jest.fn((error: Error) => {
      if (pendingTimer !== undefined) clearTimeout(pendingTimer);
      rejectPending?.(error);
    }),
  };
  return { stream, iterator };
}

describe('shared protocol inbound read deadlines', () => {
  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  test.each([
    ['document-load v4', documentLoadV4, new TextEncoder().encode('{')],
    ['snapshot-load v4', snapshotLoadV4, new TextEncoder().encode('{')],
    ['key-update v2', documentKeyUpdateV2, new Uint8Array([0])],
    ['BeeKEM Welcome v2', beekemWelcomeV2, new Uint8Array([0])],
    ['BeeKEM PathUpdate v2', beekemPathUpdateV2, new Uint8Array([0])],
  ])(
    'aborts a stalled partial %s request and releases the handler',
    async (_label, protocol, firstChunk) => {
      jest.useFakeTimers();
      jest.spyOn(console, 'warn').mockImplementation(() => undefined);
      jest.spyOn(console, 'error').mockImplementation(() => undefined);
      const fixture = makePeerborneWithHandlers();
      await (fixture.peerborne as any)._registerSharedProtocolHandlers();

      const handler = fixture.handlers.get(protocol);
      expect(handler).toBeDefined();
      const { stream, iterator } = makeStalledStream(firstChunk);
      const handled = handler!(stream);
      for (let i = 0; i < 10 && jest.getTimerCount() === 0; i++) {
        await Promise.resolve();
      }
      expect(jest.getTimerCount()).toBeGreaterThan(0);

      await jest.advanceTimersByTimeAsync(5_001);
      await handled;

      expect(stream.abort).toHaveBeenCalledTimes(1);
      expect(stream.abort).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringMatching(/idle read deadline/),
        }),
      );
      expect(iterator.return).toHaveBeenCalled();
      expect(stream.close).toHaveBeenCalled();
    },
  );

  test('aborts a continuously dribbled V4 request at the total deadline', async () => {
    jest.useFakeTimers();
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const fixture = makePeerborneWithHandlers();
    await (fixture.peerborne as any)._registerSharedProtocolHandlers();
    const handler = fixture.handlers.get(documentLoadV4);
    expect(handler).toBeDefined();
    const { stream, iterator } = makeDribblingStream(4_000);
    const handled = handler!(stream);
    for (let i = 0; i < 10 && jest.getTimerCount() === 0; i++) {
      await Promise.resolve();
    }

    await jest.advanceTimersByTimeAsync(30_001);
    await handled;

    expect(stream.abort).toHaveBeenCalledTimes(1);
    expect(stream.abort).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringMatching(/total read deadline/),
      }),
    );
    expect(iterator.next).toHaveBeenCalledTimes(9);
    expect(iterator.return).toHaveBeenCalled();
    expect(stream.close).toHaveBeenCalled();
  });

  test.each([
    ['document-load', documentLoadV4],
    ['snapshot-load', snapshotLoadV4],
  ])(
    'does not log an attacker-controlled unknown document ID in the shared %s router',
    async (_label, protocol) => {
      const secretDocumentId = '/ATTACKER-CONTROLLED-DOCUMENT-ID';
      const completionFactory = jest.fn(() => () => true);
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);
      jest.spyOn(console, 'error').mockImplementation(() => undefined);
      const fixture = makePeerborneWithHandlers();
      Object.defineProperty(fixture.peerborne, '_loadMessageSerializer', {
        value: {
          deserializeLoadRequest: jest.fn(() => ({
            documentId: secretDocumentId,
            signature: 'signature',
          })),
          createLoadRequestCompletionDetector: completionFactory,
        },
      });
      await (fixture.peerborne as any)._registerSharedProtocolHandlers();

      const handler = fixture.handlers.get(protocol);
      expect(handler).toBeDefined();
      const { stream } = makeStalledStream(new Uint8Array([1]));
      await handler!(stream);

      expect(completionFactory).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls.flat().join(' ')).toContain(
        'no document registered',
      );
      expect(warn.mock.calls.flat().join(' ')).not.toContain(secretDocumentId);
    },
  );
});
