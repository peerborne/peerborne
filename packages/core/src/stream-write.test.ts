import { describe, expect, jest, test } from '@jest/globals';
import { writeStream } from './stream-write.js';

describe('native protocol stream writes', () => {
  test('waits for backpressure before sending the next chunk or closing', async () => {
    const drain = Promise.withResolvers<void>();
    const draining = Promise.withResolvers<void>();
    const chunks = [new Uint8Array([1]), new Uint8Array([2])];
    const stream = {
      send: jest
        .fn<() => boolean>()
        .mockReturnValueOnce(false)
        .mockReturnValue(true),
      onDrain: jest.fn(() => {
        draining.resolve();
        return drain.promise;
      }),
      close: jest.fn(async () => undefined),
    };
    const pending = writeStream(stream, chunks);
    await draining.promise;
    expect(stream.send).toHaveBeenCalledTimes(1);
    expect(stream.close).not.toHaveBeenCalled();
    drain.resolve();
    await pending;
    expect(stream.send).toHaveBeenNthCalledWith(2, chunks[1]);
    expect(stream.close).toHaveBeenCalledTimes(1);
  });

  test('awaits write-side flush without closing the response reader', async () => {
    const flushed = Promise.withResolvers<void>();
    const closing = Promise.withResolvers<void>();
    const stream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(() => {
        closing.resolve();
        return flushed.promise;
      }),
      closeRead: jest.fn(async () => undefined),
      abort: jest.fn(),
    };
    let complete = false;
    const pending = writeStream(stream, [new Uint8Array([1])]).then(() => {
      complete = true;
    });
    await closing.promise;
    expect(complete).toBe(false);
    flushed.resolve();
    await pending;
    expect(stream.closeRead).not.toHaveBeenCalled();
    expect(stream.abort).not.toHaveBeenCalled();
  });

  test('closes an empty response without sending a chunk', async () => {
    const stream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
    };
    await writeStream(stream, []);
    expect(stream.send).not.toHaveBeenCalled();
    expect(stream.close).toHaveBeenCalledTimes(1);
  });

  test('propagates a send failure before attempting a successful flush', async () => {
    const stream = {
      send: jest.fn(() => {
        throw new Error('send failed');
      }),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
    };
    await expect(writeStream(stream, [new Uint8Array([1])])).rejects.toThrow(
      'send failed',
    );
    expect(stream.close).not.toHaveBeenCalled();
  });
});
