import { describe, expect, jest, test } from '@jest/globals';
import {
  encodeInvitationProtocolFrame,
  readInvitationProtocolFrame,
  readInvitationProtocolMessage,
} from './invitation-framing';

async function* chunks(...values: Uint8Array[]): AsyncIterable<Uint8Array> {
  for (const value of values) yield value;
}

describe('invitation-framing', () => {
  const maxBytes = 4096;

  describe('encodeInvitationProtocolFrame', () => {
    test('encodes valid payload with length prefix', () => {
      const payload = new Uint8Array([1, 2, 3, 4]);
      const frame = encodeInvitationProtocolFrame(payload, maxBytes);
      expect(frame.length).toBe(8);
      const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
      expect(view.getUint32(0, false)).toBe(4);
      expect(frame[4]).toBe(1);
      expect(frame[5]).toBe(2);
    });

    test('rejects empty payload (line 12)', () => {
      expect(() => encodeInvitationProtocolFrame(new Uint8Array(0), maxBytes)).toThrow(
        'must not be empty',
      );
    });

    test('rejects oversized payload (line 15)', () => {
      const big = new Uint8Array(5000);
      expect(() => encodeInvitationProtocolFrame(big, maxBytes)).toThrow(
        'exceeds',
      );
    });

    test('rejects invalid maxPayloadBytes (line 108)', () => {
      const payload = new Uint8Array([1]);
      expect(() => encodeInvitationProtocolFrame(payload, 0)).toThrow(
        'positive uint32',
      );
    });
  });

  describe('readInvitationProtocolFrame', () => {
    test('round-trip encode then read', async () => {
      const payload = new Uint8Array([9, 8, 7, 6, 5]);
      const frame = encodeInvitationProtocolFrame(payload, maxBytes);

      async function* source() {
        yield frame;
      }

      const result = await readInvitationProtocolFrame(source(), maxBytes);
      expect(result).toEqual(payload);
    });

    test('reads from streamed chunks', async () => {
      const payload = new TextEncoder().encode('hello');
      const frame = encodeInvitationProtocolFrame(payload, maxBytes);

      async function* chunked(): AsyncIterable<Uint8Array> {
        yield frame.subarray(0, 4);
        await new Promise((r) => setTimeout(r, 1));
        yield frame.subarray(4);
      }

      const result = await readInvitationProtocolFrame(chunked(), maxBytes);
      expect(new TextDecoder().decode(result)).toBe('hello');
    });

    test('rejects zero-length declared payload (line 59)', async () => {
      const header = new Uint8Array(4);
      new DataView(header.buffer).setUint32(0, 0, false);

      async function* source() {
        yield header;
      }

      await expect(readInvitationProtocolFrame(source(), maxBytes)).rejects.toThrow(
        'must not be empty',
      );
    });

    test('rejects frame exceeding max bytes (line 62)', async () => {
      const header = new Uint8Array(4);
      new DataView(header.buffer).setUint32(0, maxBytes + 1, false);

      async function* source() {
        yield header;
      }

      await expect(readInvitationProtocolFrame(source(), maxBytes)).rejects.toThrow(
        'exceeds',
      );
    });

    test('rejects trailing bytes after complete frame (line 78)', async () => {
      const payload = new Uint8Array([1, 2, 3]);
      const frame = encodeInvitationProtocolFrame(payload, maxBytes);
      const withTrailing = new Uint8Array(frame.length + 2);
      withTrailing.set(frame, 0);
      withTrailing[frame.length] = 0x42;

      async function* source() {
        yield withTrailing;
      }

      await expect(readInvitationProtocolFrame(source(), maxBytes)).rejects.toThrow(
        'trailing bytes',
      );
    });

    test('rejects truncated header (line 86)', async () => {
      const short = new Uint8Array([0, 0]);

      async function* source() {
        yield short;
      }

      await expect(readInvitationProtocolFrame(source(), maxBytes)).rejects.toThrow(
        'truncated',
      );
    });

    test('rejects truncated payload (line 88)', async () => {
      const header = new Uint8Array(4);
      new DataView(header.buffer).setUint32(0, 100, false);

      async function* source() {
        yield header;
        yield new Uint8Array([1, 2]);
      }

      await expect(readInvitationProtocolFrame(source(), maxBytes)).rejects.toThrow(
        'truncated',
      );
    });

    test('rejects invalid frame limit', async () => {
      const payload = new Uint8Array([1]);
      expect(() => encodeInvitationProtocolFrame(payload, -1)).toThrow(
        'positive uint32',
      );
    });
  });

  describe('readInvitationProtocolMessage', () => {
    test('decodes one-byte chunks exactly once', async () => {
      const payload = new TextEncoder().encode('one bounded message');
      const frame = encodeInvitationProtocolFrame(payload, maxBytes);
      const deserialize = jest.fn((value: Uint8Array) =>
        new TextDecoder().decode(value),
      );

      await expect(
        readInvitationProtocolMessage(
          chunks(...Array.from(frame, (byte) => new Uint8Array([byte]))),
          deserialize,
          maxBytes,
        ),
      ).resolves.toBe('one bounded message');
      expect(deserialize).toHaveBeenCalledTimes(1);
    });

    test('rejects an invalid complete message without awaiting another chunk', async () => {
      const frame = encodeInvitationProtocolFrame(
        new Uint8Array([0xff]),
        maxBytes,
      );
      const deserialize = jest.fn(() => {
        throw new Error('invalid invitation tuple');
      });
      const source = (async function* () {
        yield frame;
        await new Promise<void>(() => {});
      })();

      await expect(
        readInvitationProtocolMessage(source, deserialize, maxBytes),
      ).rejects.toThrow(/invalid invitation tuple/);
      expect(deserialize).toHaveBeenCalledTimes(1);
    });

    test('round-trip with custom deserializer', async () => {
      const payload = new TextEncoder().encode('test-data');
      const frame = encodeInvitationProtocolFrame(payload, maxBytes);

      async function* source() {
        yield frame;
      }

      const result = await readInvitationProtocolMessage(
        source(),
        (bytes) => new TextDecoder().decode(bytes),
        maxBytes,
      );
      expect(result).toBe('test-data');
    });
  });
});
