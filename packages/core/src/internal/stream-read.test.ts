import { describe, expect, jest, test } from '@jest/globals';
import {
  isBufferList,
  readFirstDeserializable,
  readUint8Iterable,
} from './stream-read.js';

/**
 * Minimal Uint8ArrayList stand-in for testing. The real package is ESM-only
 * and cannot be imported by Jest in CJS mode. This mock replicates the
 * subset used by readUint8Iterable: `.length` and `.subarray()`.
 */
class MockUint8ArrayList {
  private _data: Uint8Array;
  get length() {
    return this._data.length;
  }
  constructor(...arrays: Uint8Array[]) {
    const totalLength = arrays.reduce((acc, a) => acc + a.length, 0);
    this._data = new Uint8Array(totalLength);
    let offset = 0;
    for (const a of arrays) {
      this._data.set(a, offset);
      offset += a.length;
    }
  }
  subarray(): Uint8Array {
    return this._data;
  }
}

class MockBufferList {
  readonly [Symbol.for('BufferList')] = true;

  constructor(private readonly _data = new Uint8Array()) {}

  get length() {
    return this._data.length;
  }

  slice(start?: number, end?: number): Uint8Array {
    return this._data.slice(start, end);
  }
}

describe('isBufferList', () => {
  test('returns true for BufferList instances', () => {
    const bl = new MockBufferList();
    expect(isBufferList(bl)).toBe(true);
  });

  test('returns true for BufferList with data', () => {
    const bl = new MockBufferList(new Uint8Array([1, 2, 3]));
    expect(isBufferList(bl)).toBe(true);
  });

  test('returns false for Uint8Array', () => {
    const arr = new Uint8Array([1, 2, 3]);
    expect(isBufferList(arr)).toBe(false);
  });

  test('returns false for Uint8ArrayList-like object', () => {
    const list = new MockUint8ArrayList(new Uint8Array([1, 2, 3]));
    expect(isBufferList(list as any)).toBe(false);
  });

  test('returns false when the marker lacks the BufferList structure', () => {
    expect(isBufferList({ [Symbol.for('BufferList')]: true })).toBe(false);
    expect(
      isBufferList({
        [Symbol.for('BufferList')]: true,
        length: 1,
        slice: null,
      }),
    ).toBe(false);
  });
});

describe('readUint8Iterable', () => {
  async function* toAsyncIterable<T>(items: T[]): AsyncIterable<T> {
    for (const item of items) {
      yield item;
    }
  }

  test('correctly reads a stream of Uint8Array chunks', async () => {
    const chunks = [
      new Uint8Array([1, 2, 3]),
      new Uint8Array([4, 5]),
      new Uint8Array([6]),
    ];
    const result = await readUint8Iterable(toAsyncIterable(chunks));
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  test('does not retain unused growth capacity', async () => {
    const result = await readUint8Iterable(
      toAsyncIterable([new Uint8Array([1, 2, 3]), new Uint8Array([4])]),
    );

    expect(result).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(result.byteOffset).toBe(0);
    expect(result.buffer.byteLength).toBe(result.byteLength);
  });

  test('correctly reads a stream with BufferList chunks', async () => {
    const bl1 = new MockBufferList(new Uint8Array([10, 20, 30]));
    const bl2 = new MockBufferList(new Uint8Array([40, 50]));
    const slice1 = jest.spyOn(bl1, 'slice');
    const slice2 = jest.spyOn(bl2, 'slice');
    const result = await readUint8Iterable(toAsyncIterable([bl1, bl2]));
    expect(result).toEqual(new Uint8Array([10, 20, 30, 40, 50]));
    expect(slice1).toHaveBeenCalledTimes(1);
    expect(slice2).toHaveBeenCalledTimes(1);
  });

  test('correctly reads a stream with Uint8ArrayList chunks', async () => {
    const list1 = new MockUint8ArrayList(new Uint8Array([7, 8]));
    const list2 = new MockUint8ArrayList(new Uint8Array([9, 10, 11]));
    const result = await readUint8Iterable(
      toAsyncIterable([list1, list2]) as any,
    );
    expect(result).toEqual(new Uint8Array([7, 8, 9, 10, 11]));
  });

  test('handles mixed chunk types', async () => {
    const chunks = [
      new Uint8Array([1, 2]),
      new MockBufferList(new Uint8Array([3, 4])),
      new MockUint8ArrayList(new Uint8Array([5, 6])),
    ];
    const result = await readUint8Iterable(toAsyncIterable(chunks) as any);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  test('returns empty Uint8Array for empty stream', async () => {
    const result = await readUint8Iterable(toAsyncIterable([]));
    expect(result).toEqual(new Uint8Array([]));
    expect(result.length).toBe(0);
  });

  describe('maxSize enforcement', () => {
    test('throws RangeError when stream exceeds maxSize', async () => {
      const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
      await expect(
        readUint8Iterable(toAsyncIterable(chunks), 5),
      ).rejects.toThrow(RangeError);
    });

    test('succeeds when stream is exactly at maxSize', async () => {
      const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])];
      const result = await readUint8Iterable(toAsyncIterable(chunks), 5);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });

    test('assembles many tiny chunks at the exact size limit', async () => {
      async function* tinyChunks() {
        for (let index = 0; index < 4096; index++) {
          yield new Uint8Array([index & 0xff]);
        }
      }

      const result = await readUint8Iterable(tinyChunks(), 4096);
      expect(result).toHaveLength(4096);
      expect(result[0]).toBe(0);
      expect(result[4095]).toBe(255);
    });

    test('bounds streams that yield unlimited empty chunks', async () => {
      async function* emptyChunkFlood() {
        for (let index = 0; index < 65_537; index++) {
          yield new Uint8Array(0);
        }
      }

      await expect(readUint8Iterable(emptyChunkFlood(), 1)).rejects.toThrow(
        /maximum allowed chunk count/,
      );
    });

    test('succeeds when stream is under maxSize', async () => {
      const chunks = [new Uint8Array([1, 2])];
      const result = await readUint8Iterable(toAsyncIterable(chunks), 100);
      expect(result).toEqual(new Uint8Array([1, 2]));
    });

    test('throws on first chunk exceeding maxSize', async () => {
      const chunks = [new Uint8Array(1000)];
      await expect(
        readUint8Iterable(toAsyncIterable(chunks), 10),
      ).rejects.toThrow(/exceeded maximum allowed size/);
    });

    test('no limit when maxSize is undefined', async () => {
      const chunks = [new Uint8Array(1000)];
      const result = await readUint8Iterable(toAsyncIterable(chunks));
      expect(result.length).toBe(1000);
    });
  });
});

describe('readFirstDeserializable', () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const deserialize = (bytes: Uint8Array): { documentId: string } =>
    JSON.parse(decoder.decode(bytes));

  test('returns a complete request without waiting for stream EOF', async () => {
    async function* sourceThatRemainsOpen() {
      yield encoder.encode('{"documentId":');
      yield encoder.encode('"/relay-test"}');
      await new Promise<void>(() => {});
    }

    const completionDetector = (chunk: Uint8Array) => chunk.includes(0x7d);
    const result = await Promise.race([
      readFirstDeserializable(
        sourceThatRemainsOpen(),
        deserialize,
        1024,
        completionDetector,
      ),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('reader waited for EOF')), 100),
      ),
    ]);

    expect(result).toEqual({ documentId: '/relay-test' });
  });

  test('does not repeatedly deserialize byte-dribbled prefixes', async () => {
    const payload = encoder.encode('{"documentId":"/dribble"}');
    async function* oneByteAtATime() {
      for (const byte of payload) yield new Uint8Array([byte]);
    }
    const countingDeserialize = jest.fn(deserialize);

    await expect(
      readFirstDeserializable(oneByteAtATime(), countingDeserialize, 1024),
    ).resolves.toEqual({ documentId: '/dribble' });
    expect(countingDeserialize).toHaveBeenCalledTimes(2);
  });

  test('ignores empty chunks without invoking the deserializer', async () => {
    async function* emptyThenComplete() {
      for (let index = 0; index < 100; index++) yield new Uint8Array(0);
      yield encoder.encode('{"documentId":"/complete"}');
      await new Promise<void>(() => {});
    }
    const countingDeserialize = jest.fn(deserialize);

    const result = await Promise.race([
      readFirstDeserializable(emptyThenComplete(), countingDeserialize, 1024),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('reader waited for EOF')), 100),
      ),
    ]);
    expect(result).toEqual({ documentId: '/complete' });
    expect(countingDeserialize).toHaveBeenCalledTimes(1);
  });

  test('rejects a request that exceeds the size limit before it is complete', async () => {
    async function* oversizedSource() {
      yield encoder.encode('{"documentId":"');
      yield encoder.encode('too-large-to-accept');
    }

    await expect(
      readFirstDeserializable(oversizedSource(), deserialize, 20),
    ).rejects.toThrow(RangeError);
  });

  test('rejects an oversized BufferList before copying it', async () => {
    const chunk = new MockBufferList(new Uint8Array(1024));
    const slice = jest.spyOn(chunk, 'slice');

    async function* oversizedSource() {
      yield chunk;
    }

    await expect(
      readFirstDeserializable(oversizedSource(), deserialize, 20),
    ).rejects.toThrow(RangeError);
    expect(slice).not.toHaveBeenCalled();
  });

  test('surfaces the deserializer error when the stream ends incomplete', async () => {
    async function* incompleteSource() {
      yield encoder.encode('{"documentId":');
    }

    await expect(
      readFirstDeserializable(incompleteSource(), deserialize),
    ).rejects.toThrow();
  });
});
