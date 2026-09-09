import { describe, expect, jest, test } from '@jest/globals';
import { JSONSerializer } from './json-serializer.js';
import { Peerborne } from './peerborne.js';
import { documentLoadV3 } from './wire-protocols.js';

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

describe('shared load request framing', () => {
  test('handles a fragmented JSON request without waiting for stream EOF', async () => {
    const handlers = new Map<string, (stream: unknown) => Promise<void>>();
    const libp2p = {
      handle: jest.fn(
        async (
          protocol: string,
          handler: (stream: unknown) => Promise<void>,
        ) => {
          handlers.set(protocol, handler);
        },
      ),
    };
    const serializer = new JSONSerializer<unknown>();
    const peerborne = new Peerborne(
      {},
      {},
      {} as never,
      {} as never,
      {} as never,
      serializer,
      {} as never,
      {} as never,
      {} as never,
    );
    (peerborne as any)._heliaNode = { libp2p };
    const handleLoadRequestData = jest.fn(
      async (..._args: unknown[]) => undefined,
    );
    (peerborne as any)._documentRegistry.set('/fragmented', {
      handleLoadRequestData,
    });
    await (peerborne as any)._registerSharedProtocolHandlers();

    const chunks = [
      new TextEncoder().encode('{"documentId":"/frag'),
      new TextEncoder().encode('mented","signature":"sig"}'),
    ];
    let index = 0;
    const iterator: AsyncIterator<Uint8Array> = {
      next: jest.fn(() => {
        if (index < chunks.length) {
          return Promise.resolve({
            done: false as const,
            value: chunks[index++]!,
          });
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
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      abort: jest.fn((_error: Error) => undefined),
    };
    const handler = handlers.get(documentLoadV3);
    expect(handler).toBeDefined();

    await expect(
      Promise.race([
        handler!(stream),
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error('handler waited for EOF')), 250),
        ),
      ]),
    ).resolves.toBeUndefined();
    expect(iterator.next).toHaveBeenCalledTimes(2);
    expect(handleLoadRequestData).toHaveBeenCalledTimes(1);
    expect(handleLoadRequestData.mock.calls[0]?.[0]).toEqual(
      expect.objectContaining({ documentId: '/fragmented' }),
    );
    expect(handleLoadRequestData.mock.calls[0]?.[1]).toEqual(
      expect.any(Object),
    );
  });
});
