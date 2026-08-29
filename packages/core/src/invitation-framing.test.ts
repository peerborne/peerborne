import { describe, expect, jest, test } from '@jest/globals';

import {
  encodeInvitationProtocolFrame,
  readInvitationProtocolFrame,
  readInvitationProtocolMessage,
} from './invitation-framing.js';

async function* chunks(...values: Uint8Array[]): AsyncIterable<Uint8Array> {
  for (const value of values) yield value;
}

describe('invitation protocol framing', () => {
  test('decodes a valid frame split into one-byte chunks exactly once', async () => {
    const payload = new TextEncoder().encode('one bounded message');
    const frame = encodeInvitationProtocolFrame(payload, 1024);
    const deserialize = jest.fn((value: Uint8Array) =>
      new TextDecoder().decode(value),
    );

    await expect(
      readInvitationProtocolMessage(
        chunks(...Array.from(frame, (byte) => new Uint8Array([byte]))),
        deserialize,
        1024,
      ),
    ).resolves.toBe('one bounded message');
    expect(deserialize).toHaveBeenCalledTimes(1);
  });

  test('rejects a complete invalid message without awaiting another chunk', async () => {
    const frame = encodeInvitationProtocolFrame(new Uint8Array([0xff]), 1024);
    const deserialize = jest.fn(() => {
      throw new Error('invalid invitation tuple');
    });
    const source = (async function* () {
      yield frame;
      await new Promise<void>(() => {});
    })();

    await expect(
      readInvitationProtocolMessage(source, deserialize, 1024),
    ).rejects.toThrow(/invalid invitation tuple/);
    expect(deserialize).toHaveBeenCalledTimes(1);
  });

  test('rejects an oversized declared length before payload allocation', async () => {
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, 1025, false);

    await expect(
      readInvitationProtocolFrame(chunks(header), 1024),
    ).rejects.toThrow(RangeError);
  });

  test('rejects truncated and same-chunk trailing data', async () => {
    const frame = encodeInvitationProtocolFrame(new Uint8Array([1, 2]), 16);
    await expect(
      readInvitationProtocolFrame(chunks(frame.subarray(0, 5)), 16),
    ).rejects.toThrow(/payload is truncated/);

    const trailing = new Uint8Array(frame.byteLength + 1);
    trailing.set(frame);
    trailing[trailing.byteLength - 1] = 3;
    await expect(
      readInvitationProtocolFrame(chunks(trailing), 16),
    ).rejects.toThrow(/trailing bytes/);
  });
});
