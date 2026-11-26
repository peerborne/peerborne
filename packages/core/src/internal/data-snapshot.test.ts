import { describe, expect, test } from '@jest/globals';
import {
  snapshotDeepEnumerableData,
  snapshotEnumerableOwnDataObject,
} from './data-snapshot.js';

describe('snapshotEnumerableOwnDataObject', () => {
  test('rejects an excessive root key count before reading descriptors', () => {
    let descriptorCalls = 0;
    const value = new Proxy(
      { first: 1, second: 2, third: 3 },
      {
        getOwnPropertyDescriptor(target, property) {
          descriptorCalls++;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );

    expect(() =>
      snapshotEnumerableOwnDataObject(value, 'bounded root', {
        maxProperties: 2,
        maxKeyBytes: 128,
      }),
    ).toThrow(/own properties/);
    expect(descriptorCalls).toBe(0);
  });

  test('rejects excessive root key bytes before reading descriptors', () => {
    let descriptorCalls = 0;
    const value = new Proxy(
      { oversized: 1 },
      {
        getOwnPropertyDescriptor(target, property) {
          descriptorCalls++;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );

    expect(() =>
      snapshotEnumerableOwnDataObject(value, 'bounded root', {
        maxProperties: 1,
        maxKeyBytes: 2,
      }),
    ).toThrow(/key bytes/);
    expect(descriptorCalls).toBe(0);
  });
});

describe('snapshotDeepEnumerableData', () => {
  test('detaches nested Proxy descriptors without invoking property gets', () => {
    const nested = { payload: new Uint8Array([1, 2, 3]) };
    let getCalls = 0;
    let descriptorCalls = 0;
    const proxy = new Proxy(nested, {
      get(target, property, receiver) {
        getCalls++;
        return Reflect.get(target, property, receiver);
      },
      getOwnPropertyDescriptor(target, property) {
        descriptorCalls++;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    const snapshot = snapshotDeepEnumerableData({
      first: proxy,
      second: proxy,
    });
    nested.payload[0] = 9;

    expect(getCalls).toBe(0);
    expect(descriptorCalls).toBeGreaterThan(0);
    expect(snapshot.first).not.toBe(snapshot.second);
    expect(snapshot.first.payload).toEqual(new Uint8Array([1, 2, 3]));
    expect(snapshot.first.payload).not.toBe(snapshot.second.payload);
  });

  test('rejects nested accessors without invoking them', () => {
    let getterCalls = 0;
    const nested = Object.defineProperty({}, 'payload', {
      enumerable: true,
      get() {
        getterCalls++;
        return new Uint8Array([1]);
      },
    });

    expect(() => snapshotDeepEnumerableData({ nested })).toThrow(
      /enumerable data properties/,
    );
    expect(getterCalls).toBe(0);
  });

  test('rejects cycles, exotic objects, and SharedArrayBuffer views', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => snapshotDeepEnumerableData(cyclic)).toThrow(/cycles/);
    expect(() => snapshotDeepEnumerableData({ date: new Date() })).toThrow(
      /non-plain object/,
    );
    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        snapshotDeepEnumerableData({
          bytes: new Uint8Array(new SharedArrayBuffer(4)),
        }),
      ).toThrow(/invalid length or backing buffer/);
    }
  });

  test('enforces aggregate bytes, properties, and explicit depth bounds', () => {
    expect(() =>
      snapshotDeepEnumerableData({ bytes: new Uint8Array(5) }, 'bounded', {
        maxDepth: 8,
        maxObjects: 8,
        maxProperties: 8,
        maxArrayLength: 8,
        maxValueBytes: 4,
      }),
    ).toThrow(/detached value bytes/);
    expect(() =>
      snapshotDeepEnumerableData({ a: 1, b: 2 }, 'bounded', {
        maxDepth: 8,
        maxObjects: 8,
        maxProperties: 1,
        maxArrayLength: 8,
        maxValueBytes: 64,
      }),
    ).toThrow(/detached properties/);
    expect(() =>
      snapshotDeepEnumerableData({ oversized: 1 }, 'bounded', {
        maxDepth: 8,
        maxObjects: 8,
        maxProperties: 8,
        maxArrayLength: 8,
        maxValueBytes: 2,
      }),
    ).toThrow(/detached value bytes/);

    const deep: Record<string, unknown> = {};
    let cursor = deep;
    for (let depth = 0; depth < 5_000; depth++) {
      const child: Record<string, unknown> = {};
      cursor.child = child;
      cursor = child;
    }
    expect(() => snapshotDeepEnumerableData(deep)).not.toThrow();

    expect(() =>
      snapshotDeepEnumerableData(deep, 'bounded', {
        maxDepth: 8,
        maxObjects: 10_000,
        maxProperties: 10_000,
        maxArrayLength: 8,
        maxValueBytes: 1_000_000,
      }),
    ).toThrow(/maximum depth 8/);
  });

  test('does not charge array index keys as detached value bytes', () => {
    const values = Array.from({ length: 12 }, (_, index) => index);

    expect(
      snapshotDeepEnumerableData(values, 'bounded', {
        maxDepth: 8,
        maxObjects: 8,
        maxProperties: 12,
        maxArrayLength: 12,
        maxValueBytes: 0,
      }),
    ).toEqual(values);
  });

  test('checks the aggregate property budget before nested descriptors', () => {
    let descriptorCalls = 0;
    const nested = new Proxy(
      { first: 1, second: 2 },
      {
        getOwnPropertyDescriptor(target, property) {
          descriptorCalls++;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );

    expect(() =>
      snapshotDeepEnumerableData({ nested }, 'bounded', {
        maxDepth: 8,
        maxObjects: 8,
        maxProperties: 2,
        maxArrayLength: 8,
        maxValueBytes: 128,
      }),
    ).toThrow(/detached properties/);
    expect(descriptorCalls).toBe(0);
  });

  test.each([
    ['a non-index key', ['length', 'fake']],
    ['a symbol key', [Symbol('extra'), 'length']],
    ['reordered keys', ['length', '0']],
  ])(
    'rejects arrays whose own keys contain %s before reading descriptors',
    (_label, ownKeys) => {
      let descriptorCalls = 0;
      const array = new Proxy([1], {
        ownKeys: () => ownKeys,
        getOwnPropertyDescriptor(target, property) {
          descriptorCalls++;
          if (property === 'fake' || typeof property === 'symbol') {
            return {
              value: 2,
              writable: true,
              enumerable: true,
              configurable: true,
            };
          }
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      });

      expect(() =>
        snapshotDeepEnumerableData({ array }, 'bounded', {
          maxDepth: 8,
          maxObjects: 8,
          maxProperties: 8,
          maxArrayLength: 8,
          maxValueBytes: 128,
        }),
      ).toThrow(/dense data arrays/);
      expect(descriptorCalls).toBe(1);
    },
  );

  test('rejects an array Proxy whose reported length changes during detachment', () => {
    let lengthDescriptorCalls = 0;
    const values = new Proxy([1, 2], {
      getOwnPropertyDescriptor(target, property) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, property);
        if (property !== 'length') return descriptor;
        lengthDescriptorCalls++;
        return {
          ...descriptor!,
          value: lengthDescriptorCalls === 1 ? 2 : 1,
        };
      },
    });

    expect(() =>
      snapshotDeepEnumerableData({ values }, 'bounded', {
        maxDepth: 8,
        maxObjects: 16,
        maxProperties: 16,
        maxArrayLength: 8,
        maxValueBytes: 64,
      }),
    ).toThrow(/invalid array/);
    expect(lengthDescriptorCalls).toBe(2);
  });
});
