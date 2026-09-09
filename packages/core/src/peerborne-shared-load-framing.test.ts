import { describe, expect, jest, test } from '@jest/globals';
import { JSONSerializer } from './json-serializer.js';
import { Peerborne } from './peerborne.js';
import {
  beekemPathUpdateV1,
  beekemWelcomeV1,
  documentKeyUpdateV2,
  documentLoadV3,
  snapshotLoadV3,
  tipAdvertiseV1,
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

type Handler = (stream: unknown) => Promise<void>;

const jsonProtocols = [
  ['doc-load', documentLoadV3, 'handleLoadRequestData'],
  ['snapshot-load', snapshotLoadV3, 'handleSnapshotLoadRequestData'],
  ['tip-advertise', tipAdvertiseV1, 'handleTipAdvertiseRequestData'],
] as const;

const rawProtocols = [
  ['key-update', documentKeyUpdateV2, 'handleKeyUpdateRequestData'],
  ['beekem-welcome', beekemWelcomeV1, 'handleBeeKEMWelcomeRequestData'],
  [
    'beekem-pathupdate',
    beekemPathUpdateV1,
    'handleBeeKEMPathUpdateRequestData',
  ],
] as const;

async function registerHandlers(
  serializer: unknown = new JSONSerializer<unknown>(),
  timeoutMs?: number,
): Promise<{ peerborne: Peerborne<unknown>; handlers: Map<string, Handler> }> {
  const handlers = new Map<string, Handler>();
  const libp2p = {
    handle: jest.fn(async (protocol: string, handler: Handler) => {
      handlers.set(protocol, handler);
    }),
  };
  const peerborne = new Peerborne(
    {},
    {},
    {} as never,
    {} as never,
    {} as never,
    serializer as never,
    {} as never,
    {} as never,
    {} as never,
  );
  (peerborne as any)._heliaNode = { libp2p };
  if (timeoutMs !== undefined) {
    (peerborne as any)._config = { loadQuorumTimeoutMs: timeoutMs };
  }
  await (peerborne as any)._registerSharedProtocolHandlers();
  return { peerborne, handlers };
}

function streamFromChunks(
  chunks: Uint8Array[],
  options: {
    endAfterChunks?: boolean;
    close?: () => Promise<void>;
    closeRead?: () => Promise<void>;
    abort?: (error: Error) => void;
    send?: (chunk: Uint8Array) => boolean;
    onDrain?: () => Promise<void>;
  } = {},
) {
  const resource = {
    status: 'open' as 'open' | 'write-closed' | 'read-closed' | 'reset',
    inboundQuota: 1,
  };
  let index = 0;
  const iterator: AsyncIterator<Uint8Array> = {
    next: jest.fn(() => {
      if (index < chunks.length) {
        return Promise.resolve({
          done: false as const,
          value: chunks[index++]!,
        });
      }
      if (options.endAfterChunks) {
        return Promise.resolve({ done: true as const, value: undefined });
      }
      return new Promise<IteratorResult<Uint8Array>>(() => {});
    }),
    return: jest.fn(async () => ({
      done: true as const,
      value: undefined,
    })),
  };
  const stream = {
    [Symbol.asyncIterator]: () => iterator,
    send: jest.fn(options.send ?? ((_chunk: Uint8Array) => true)),
    onDrain: jest.fn(options.onDrain ?? (async () => undefined)),
    close: jest.fn(async () => {
      await options.close?.();
      if (resource.status === 'open') resource.status = 'write-closed';
    }),
    closeRead: jest.fn(async () => {
      await options.closeRead?.();
      if (resource.status !== 'reset') resource.status = 'read-closed';
    }),
    abort: jest.fn((error: Error) => {
      options.abort?.(error);
      resource.status = 'reset';
      resource.inboundQuota = 0;
    }),
  };
  return { iterator, resource, stream };
}

function pathPrefixedMessage(path: string, payload = new Uint8Array([7])) {
  const pathBytes = new TextEncoder().encode(path);
  const message = new Uint8Array(4 + pathBytes.length + payload.length);
  new DataView(message.buffer).setUint32(0, pathBytes.length);
  message.set(pathBytes, 4);
  message.set(payload, 4 + pathBytes.length);
  return message;
}

async function waitForCall(mock: jest.Mock): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (mock.mock.calls.length > 0) return;
    await Promise.resolve();
  }
  throw new Error('expected mock was not called');
}

describe('shared protocol request boundaries', () => {
  test.each(jsonProtocols)(
    'finishes and cleans up an early-framed %s response only after it flushes',
    async (_handlerName, protocol, documentMethod) => {
      jest.useFakeTimers();
      const writeClosed = Promise.withResolvers<void>();
      const { peerborne, handlers } = await registerHandlers(undefined, 25);
      const response = new Uint8Array([9, 8, 7]);
      const documentHandler = jest.fn(
        async (
          _request: unknown,
          stream: { sink(data: Uint8Array[]): Promise<void> },
        ) => {
          await stream.sink([response]);
        },
      );
      (peerborne as any)._documentRegistry.set('/fragmented', {
        [documentMethod]: documentHandler,
      });
      const { iterator, resource, stream } = streamFromChunks(
        [
          new TextEncoder().encode('{"documentId":"/frag'),
          new TextEncoder().encode('mented","signature":"sig"}'),
        ],
        {
          close: () => writeClosed.promise,
        },
      );

      let settled = false;
      const result = handlers.get(protocol)!(stream).then(() => {
        settled = true;
      });

      try {
        await waitForCall(stream.close);
        expect(stream.send).toHaveBeenCalledWith(response);
        expect(stream.abort).not.toHaveBeenCalled();
        expect(settled).toBe(false);
        expect(resource.inboundQuota).toBe(1);
        expect(jest.getTimerCount()).toBe(1);

        writeClosed.resolve();
        await result;
        expect(iterator.next).toHaveBeenCalledTimes(2);
        expect(documentHandler).toHaveBeenCalledTimes(1);
        expect(stream.close).toHaveBeenCalledTimes(1);
        expect(stream.closeRead).not.toHaveBeenCalled();
        expect(stream.abort).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Shared protocol request completed',
          }),
        );
        expect(resource.status).toBe('reset');
        expect(resource.inboundQuota).toBe(0);
        expect(jest.getTimerCount()).toBe(0);
        await jest.advanceTimersByTimeAsync(100);
        expect(stream.abort).toHaveBeenCalledTimes(1);
      } finally {
        writeClosed.resolve();
        jest.useRealTimers();
      }
    },
  );

  test.each([
    ['permanently backpressured onDrain', 'drain'],
    ['never-resolving first response close', 'close'],
  ] as const)(
    'bounds the post-read phase with %s',
    async (_caseName, blockedAt) => {
      jest.useFakeTimers();
      const { peerborne, handlers } = await registerHandlers(undefined, 25);
      const response = new Uint8Array([4, 5, 6]);
      const documentHandler = jest.fn(
        async (
          _request: unknown,
          stream: { sink(data: Uint8Array[]): Promise<void> },
        ) => stream.sink([response]),
      );
      (peerborne as any)._documentRegistry.set('/registered', {
        handleLoadRequestData: documentHandler,
      });
      const { resource, stream } = streamFromChunks(
        [
          new TextEncoder().encode(
            JSON.stringify({ documentId: '/registered' }),
          ),
        ],
        blockedAt === 'drain'
          ? {
              send: () => false,
              onDrain: () => new Promise<void>(() => {}),
            }
          : { close: () => new Promise<void>(() => {}) },
      );
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);
      const error = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);

      try {
        const result = handlers.get(documentLoadV3)!(stream);
        await waitForCall(
          blockedAt === 'drain' ? stream.onDrain : stream.close,
        );
        expect(stream.abort).not.toHaveBeenCalled();
        expect(resource.inboundQuota).toBe(1);
        expect(jest.getTimerCount()).toBe(1);

        await jest.advanceTimersByTimeAsync(25);
        await result;
        expect(documentHandler).toHaveBeenCalledTimes(1);
        expect(stream.abort).toHaveBeenCalledTimes(1);
        expect(stream.abort).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Shared protocol handler timed out',
          }),
        );
        expect(warn).toHaveBeenCalledWith(
          'Shared doc-load handler: post-read processing timed out, dropping',
        );
        expect(error).not.toHaveBeenCalled();
        expect(resource.status).toBe('reset');
        expect(resource.inboundQuota).toBe(0);
        expect(jest.getTimerCount()).toBe(0);
      } finally {
        warn.mockRestore();
        error.mockRestore();
        jest.useRealTimers();
      }
    },
  );

  test.each(rawProtocols)(
    'revokes deferred %s mutation admission before releasing the stream',
    async (handlerName, protocol, documentMethod) => {
      jest.useFakeTimers();
      const releaseWork = Promise.withResolvers<void>();
      const workFinished = Promise.withResolvers<void>();
      const { peerborne, handlers } = await registerHandlers(undefined, 25);
      let mutations = 0;
      const documentHandler = jest.fn(
        async (_payload: Uint8Array, admission: any) => {
          try {
            await releaseWork.promise;
            const committed = await admission.runMutation(() => {
              mutations++;
            });
            expect(committed.admitted).toBe(false);
          } finally {
            workFinished.resolve();
          }
        },
      );
      (peerborne as any)._documentRegistry.set('/registered', {
        [documentMethod]: documentHandler,
      });
      const { resource, stream } = streamFromChunks(
        [pathPrefixedMessage('/registered')],
        { endAfterChunks: true },
      );
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);

      try {
        const result = handlers.get(protocol)!(stream);
        await waitForCall(documentHandler);
        await jest.advanceTimersByTimeAsync(25);
        await result;

        expect(stream.abort).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Shared protocol handler timed out',
          }),
        );
        expect(resource.inboundQuota).toBe(0);
        expect(mutations).toBe(0);

        releaseWork.resolve();
        await workFinished.promise;
        expect(mutations).toBe(0);
        expect(warn).toHaveBeenCalledWith(
          `Shared ${handlerName} handler: post-read processing timed out, dropping`,
        );
      } finally {
        releaseWork.resolve();
        warn.mockRestore();
        jest.useRealTimers();
      }
    },
  );

  test.each(rawProtocols)(
    'waits for an admitted %s commit before reporting timeout',
    async (_handlerName, protocol, documentMethod) => {
      jest.useFakeTimers();
      const commitStarted = Promise.withResolvers<void>();
      const releaseCommit = Promise.withResolvers<void>();
      const { peerborne, handlers } = await registerHandlers(undefined, 25);
      let mutations = 0;
      const documentHandler = jest.fn(
        async (_payload: Uint8Array, admission: any) => {
          await admission.runMutation(async () => {
            commitStarted.resolve();
            await releaseCommit.promise;
            mutations++;
          });
        },
      );
      (peerborne as any)._documentRegistry.set('/registered', {
        [documentMethod]: documentHandler,
      });
      const { resource, stream } = streamFromChunks(
        [pathPrefixedMessage('/registered')],
        { endAfterChunks: true },
      );
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);

      try {
        let settled = false;
        const result = handlers.get(protocol)!(stream).then(() => {
          settled = true;
        });
        await commitStarted.promise;
        await jest.advanceTimersByTimeAsync(25);

        expect(settled).toBe(false);
        expect(stream.abort).not.toHaveBeenCalled();
        expect(resource.inboundQuota).toBe(1);

        releaseCommit.resolve();
        await result;
        expect(mutations).toBe(1);
        expect(stream.abort).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Shared protocol handler timed out',
          }),
        );
        expect(resource.inboundQuota).toBe(0);
      } finally {
        releaseCommit.resolve();
        warn.mockRestore();
        jest.useRealTimers();
      }
    },
  );

  test.each(jsonProtocols)(
    'aborts a %s stream after a fragmented deserialization failure',
    async (handlerName, protocol) => {
      const serializer = {
        createLoadRequestCompletionDetector: () => {
          let chunkCount = 0;
          return () => ++chunkCount === 2;
        },
        deserializeLoadRequest: jest.fn(() => {
          throw new Error('private deserializer detail');
        }),
      };
      const { handlers } = await registerHandlers(serializer);
      const { iterator, stream } = streamFromChunks([
        new TextEncoder().encode('{"documentId":'),
        new TextEncoder().encode('}'),
      ]);
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);
      const error = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);

      try {
        await handlers.get(protocol)!(stream);
        expect(iterator.next).toHaveBeenCalledTimes(2);
        expect(serializer.deserializeLoadRequest).toHaveBeenCalledTimes(1);
        expect(stream.abort).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Shared protocol request rejected',
          }),
        );
        expect(stream.send).not.toHaveBeenCalled();
        expect(stream.close).not.toHaveBeenCalled();
        expect(stream.closeRead).not.toHaveBeenCalled();
        expect(warn).toHaveBeenCalledWith(
          `Shared ${handlerName} handler: failed to read request, dropping`,
        );
        expect(error).not.toHaveBeenCalled();
        expect(warn.mock.calls.flat().join(' ')).not.toContain('private');
      } finally {
        warn.mockRestore();
        error.mockRestore();
      }
    },
  );

  test.each(rawProtocols)(
    'aborts a malformed %s stream instead of substituting a half-close',
    async (_handlerName, protocol) => {
      const { handlers } = await registerHandlers();
      const { stream } = streamFromChunks(
        [new Uint8Array([0, 0, 0])],
        { endAfterChunks: true },
      );
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);

      try {
        await handlers.get(protocol)!(stream);
        expect(stream.abort).toHaveBeenCalledTimes(1);
        expect(stream.close).not.toHaveBeenCalled();
        expect(stream.closeRead).not.toHaveBeenCalled();
      } finally {
        warn.mockRestore();
      }
    },
  );

  test.each([
    ...jsonProtocols.map(([name, protocol]) => [name, protocol, 'json'] as const),
    ...rawProtocols.map(([name, protocol]) => [name, protocol, 'raw'] as const),
  ])(
    'times out and fully aborts a partial half-open %s request',
    async (handlerName, protocol, framing) => {
      jest.useFakeTimers();
      const { handlers } = await registerHandlers(undefined, 25);
      const partial =
        framing === 'json'
          ? new TextEncoder().encode('{"documentId":')
          : new Uint8Array([0, 0, 0]);
      const { stream } = streamFromChunks([partial]);
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);
      const error = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);

      try {
        const result = handlers.get(protocol)!(stream);
        expect(jest.getTimerCount()).toBe(1);
        await jest.advanceTimersByTimeAsync(25);
        await result;

        expect(stream.abort).toHaveBeenCalledTimes(1);
        expect(stream.close).not.toHaveBeenCalled();
        expect(stream.closeRead).not.toHaveBeenCalled();
        expect(warn).toHaveBeenCalledWith(
          `Shared ${handlerName} handler: request timed out, dropping`,
        );
        expect(error).not.toHaveBeenCalled();
        expect(jest.getTimerCount()).toBe(0);
      } finally {
        warn.mockRestore();
        error.mockRestore();
        jest.useRealTimers();
      }
    },
  );

  test('bounds both graceful close fallbacks when full-stream abort throws', async () => {
    jest.useFakeTimers();
    const serializer = {
      createLoadRequestCompletionDetector: () => () => true,
      deserializeLoadRequest: jest.fn(() => {
        throw new Error('private deserializer detail');
      }),
    };
    const { handlers } = await registerHandlers(serializer, 25);
    const { stream } = streamFromChunks(
      [new TextEncoder().encode('{}')],
      {
        abort: () => {
          throw new Error('private abort detail');
        },
        close: () => new Promise<void>(() => {}),
        closeRead: () => new Promise<void>(() => {}),
      },
    );
    const warn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);
    const error = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);
    let settled = false;
    const result = handlers.get(documentLoadV3)!(stream).then(() => {
      settled = true;
    });

    try {
      await waitForCall(stream.close);
      expect(stream.abort).toHaveBeenCalledTimes(1);
      expect(stream.closeRead).not.toHaveBeenCalled();
      expect(settled).toBe(false);

      await jest.advanceTimersByTimeAsync(25);
      await waitForCall(stream.closeRead);
      expect(settled).toBe(false);

      await jest.advanceTimersByTimeAsync(25);
      await result;
      expect(stream.abort).toHaveBeenCalledTimes(1);
      expect(stream.close).toHaveBeenCalledTimes(1);
      expect(stream.closeRead).toHaveBeenCalledTimes(1);
      expect(error).not.toHaveBeenCalled();
      expect(
        [...warn.mock.calls, ...error.mock.calls].flat().join(' '),
      ).not.toContain('private');
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      warn.mockRestore();
      error.mockRestore();
      jest.useRealTimers();
    }
  });

  test.each(rawProtocols)(
    'reclaims inbound quota after successful fire-and-forget %s processing',
    async (_handlerName, protocol, documentMethod) => {
      const { peerborne, handlers } = await registerHandlers();
      const documentHandler = jest.fn(async () => undefined);
      (peerborne as any)._documentRegistry.set('/registered', {
        [documentMethod]: documentHandler,
      });
      const { resource, stream } = streamFromChunks(
        [pathPrefixedMessage('/registered')],
        { endAfterChunks: true },
      );

      await handlers.get(protocol)!(stream);
      expect(documentHandler).toHaveBeenCalledTimes(1);
      expect(stream.close).not.toHaveBeenCalled();
      expect(stream.closeRead).not.toHaveBeenCalled();
      expect(stream.abort).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Shared protocol request completed',
        }),
      );
      expect(resource.status).toBe('reset');
      expect(resource.inboundQuota).toBe(0);
    },
  );

  test.each([
    ['doc-load', documentLoadV3],
    ['snapshot-load', snapshotLoadV3],
  ] as const)(
    'does not log an attacker-controlled unknown document ID in %s',
    async (handlerName, protocol) => {
      const { handlers } = await registerHandlers();
      const attackerId = '/private-document-id-that-must-not-reach-logs';
      const { stream } = streamFromChunks([
        new TextEncoder().encode(JSON.stringify({ documentId: attackerId })),
      ]);
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);
      const error = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);

      try {
        await handlers.get(protocol)!(stream);
        expect(warn).toHaveBeenCalledWith(
          `Shared ${handlerName} handler: no document registered, dropping`,
        );
        expect(
          [...warn.mock.calls, ...error.mock.calls].flat().join(' '),
        ).not.toContain(attackerId);
      } finally {
        warn.mockRestore();
        error.mockRestore();
      }
    },
  );

  test.each([
    ...jsonProtocols.map(
      ([name, protocol, method]) => [name, protocol, method, 'json'] as const,
    ),
    ...rawProtocols.map(
      ([name, protocol, method]) => [name, protocol, method, 'raw'] as const,
    ),
  ])(
    'redacts downstream exceptions from the shared %s handler log',
    async (handlerName, protocol, documentMethod, framing) => {
      const { peerborne, handlers } = await registerHandlers();
      const privateDetail = `private ${handlerName} provider detail`;
      const documentHandler = jest.fn(async () => {
        throw new Error(privateDetail);
      });
      (peerborne as any)._documentRegistry.set('/registered', {
        [documentMethod]: documentHandler,
      });
      const request =
        framing === 'json'
          ? new TextEncoder().encode(
              JSON.stringify({ documentId: '/registered' }),
            )
          : pathPrefixedMessage('/registered');
      const { resource, stream } = streamFromChunks([request], {
        endAfterChunks: framing === 'raw',
      });
      const warn = jest
        .spyOn(console, 'warn')
        .mockImplementation(() => undefined);
      const error = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);

      try {
        await handlers.get(protocol)!(stream);
        expect(documentHandler).toHaveBeenCalledTimes(1);
        expect(error).toHaveBeenCalledWith(
          `Shared ${handlerName} handler failed`,
        );
        expect(
          [...warn.mock.calls, ...error.mock.calls].flat().join(' '),
        ).not.toContain(privateDetail);
        expect(stream.close).not.toHaveBeenCalled();
        expect(stream.closeRead).not.toHaveBeenCalled();
        expect(stream.abort).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Shared protocol handler failed',
          }),
        );
        expect(resource.status).toBe('reset');
        expect(resource.inboundQuota).toBe(0);
      } finally {
        warn.mockRestore();
        error.mockRestore();
      }
    },
  );
});
