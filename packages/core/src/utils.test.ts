import { describe, expect, jest, test } from '@jest/globals';
import BufferList from 'bl';
import {
  shuffleArray,
  firstTrue,
  concatUint8Arrays,
  isBufferList,
  readFirstDeserializable,
  readUint8Iterable,
  generateAndExportHmacKey,
  generateAndExportSymmetricKey,
  importHmacKey,
  importSymmetricKey,
} from './utils.js';

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

describe('shuffleArray', () => {
  test('should shuffle array elements', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const original = [...arr];
    shuffleArray(arr);
    // Array should have same elements but potentially in different order
    expect(arr.sort()).toEqual(original.sort());
    expect(arr.length).toBe(original.length);
  });

  test('should handle empty array', () => {
    const arr: number[] = [];
    shuffleArray(arr);
    expect(arr).toEqual([]);
  });

  test('should handle single element array', () => {
    const arr = [1];
    shuffleArray(arr);
    expect(arr).toEqual([1]);
  });
});

describe('firstTrue', () => {
  test('should resolve with true when first promise resolves true', async () => {
    const promises = [
      Promise.resolve(true),
      Promise.resolve(false),
      Promise.resolve(false),
    ];
    const result = await firstTrue(promises);
    expect(result).toBe(true);
  });

  test('should resolve with false when all promises resolve false', async () => {
    const promises = [
      Promise.resolve(false),
      Promise.resolve(false),
      Promise.resolve(false),
    ];
    const result = await firstTrue(promises);
    expect(result).toBe(false);
  });

  test('should handle empty promise array', async () => {
    const promises: Promise<boolean>[] = [];
    const result = await firstTrue(promises);
    expect(result).toBe(false);
  });
});

describe('concatUint8Arrays', () => {
  test('should concatenate multiple Uint8Array', () => {
    const arr1 = new Uint8Array([1, 2, 3]);
    const arr2 = new Uint8Array([4, 5, 6]);
    const arr3 = new Uint8Array([7, 8, 9]);
    const result = concatUint8Arrays(arr1, arr2, arr3);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
  });

  test('should handle empty arrays', () => {
    const arr1 = new Uint8Array([]);
    const arr2 = new Uint8Array([1, 2]);
    const result = concatUint8Arrays(arr1, arr2);
    expect(result).toEqual(new Uint8Array([1, 2]));
  });

  test('should handle single array', () => {
    const arr = new Uint8Array([1, 2, 3]);
    const result = concatUint8Arrays(arr);
    expect(result).toEqual(arr);
  });

  test('should handle no arrays', () => {
    const result = concatUint8Arrays();
    expect(result).toEqual(new Uint8Array([]));
  });
});

describe('isBufferList', () => {
  test('returns true for BufferList instances', () => {
    const bl = new BufferList();
    expect(isBufferList(bl)).toBe(true);
  });

  test('returns true for BufferList with data', () => {
    const bl = new BufferList(Buffer.from([1, 2, 3]));
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

  test('correctly reads a stream with BufferList chunks', async () => {
    const bl1 = new BufferList(Buffer.from([10, 20, 30]));
    const bl2 = new BufferList(Buffer.from([40, 50]));
    const result = await readUint8Iterable(toAsyncIterable([bl1, bl2]));
    expect(result).toEqual(new Uint8Array([10, 20, 30, 40, 50]));
  });

  test('correctly reads a stream with Uint8ArrayList chunks', async () => {
    const list1 = new MockUint8ArrayList(new Uint8Array([7, 8]));
    const list2 = new MockUint8ArrayList(new Uint8Array([9, 10, 11]));
    const result = await readUint8Iterable(toAsyncIterable([list1, list2]) as any);
    expect(result).toEqual(new Uint8Array([7, 8, 9, 10, 11]));
  });

  test('handles mixed chunk types', async () => {
    const chunks = [
      new Uint8Array([1, 2]),
      new BufferList(Buffer.from([3, 4])),
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
      const chunks = [
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
      ];
      await expect(
        readUint8Iterable(toAsyncIterable(chunks), 5),
      ).rejects.toThrow(RangeError);
    });

    test('succeeds when stream is exactly at maxSize', async () => {
      const chunks = [
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5]),
      ];
      const result = await readUint8Iterable(toAsyncIterable(chunks), 5);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
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

    const result = await Promise.race([
      readFirstDeserializable(sourceThatRemainsOpen(), deserialize, 1024),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('reader waited for EOF')), 100),
      ),
    ]);

    expect(result).toEqual({ documentId: '/relay-test' });
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
    const chunk = new BufferList(Buffer.alloc(1024));
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

describe('crypto key utilities', () => {
  test('should generate and export HMAC key pair', async () => {
    const [privateKey, publicKey] = await generateAndExportHmacKey();
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    expect(privateKey.kty).toBe('EC');
    expect(publicKey.kty).toBe('EC');
    expect(privateKey.crv).toBe('P-384');
    expect(publicKey.crv).toBe('P-384');
  });

  test('should generate and export symmetric key', async () => {
    const key = await generateAndExportSymmetricKey();
    expect(key).toBeDefined();
    expect(key.kty).toBe('oct');
    // Note: native Web Crypto and some polyfills populate `alg` (e.g. "A256GCM")
    // on the exported JWK, but @peculiar/webcrypto >=1.7.0 leaves it as an empty
    // string. Validate via re-import instead of inspecting the JWK header.
    const reimported = await crypto.subtle.importKey(
      'jwk',
      key,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    expect(reimported.algorithm.name).toBe('AES-GCM');
    expect((reimported.algorithm as AesKeyAlgorithm).length).toBe(256);
  });

  test('should import HMAC key from raw data', async () => {
    const keyData = new Uint8Array(32);
    crypto.getRandomValues(keyData);
    const key = await importHmacKey(keyData);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
  });

  test('should import symmetric key from raw data', async () => {
    const keyData = new Uint8Array(32);
    crypto.getRandomValues(keyData);
    const key = await importSymmetricKey(keyData);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
  });

  test.each(['AES-GCM', 'AES-CTR', 'AES-CBC'] as const)(
    'should import symmetric key for %s',
    async (alg) => {
      const keyData = new Uint8Array(32);
      crypto.getRandomValues(keyData);
      const key = await importSymmetricKey(keyData, 'raw', alg);
      expect(key).toBeDefined();
      expect(key.type).toBe('secret');
      expect(key.algorithm.name).toBe(alg);
    },
  );

  test.each(['AES-GCM', 'AES-CTR', 'AES-CBC'] as const)(
    'should generate and export symmetric key for %s',
    async (alg) => {
      const jwk = await generateAndExportSymmetricKey(alg);
      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('oct');

      // Re-import the JWK and verify the algorithm matches
      const reimported = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: alg, length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );
      expect(reimported.algorithm.name).toBe(alg);
    },
  );
});
