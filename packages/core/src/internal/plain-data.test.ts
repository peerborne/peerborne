import { describe, expect, test } from '@jest/globals';
import {
  snapshotPlainDataArray,
  snapshotPlainDataObject,
} from './plain-data.js';

describe('snapshotPlainDataObject', () => {
  test('detaches allowed enumerable data fields onto a null prototype', () => {
    const value = { id: 'a', version: 1 };
    const snapshot = snapshotPlainDataObject(
      value,
      ['id', 'version'],
      'protocol',
    );
    value.id = 'b';
    expect(Object.getPrototypeOf(snapshot)).toBeNull();
    expect({ ...snapshot }).toEqual({ id: 'a', version: 1 });
  });

  test('treats keys outside required as optional', () => {
    expect(
      snapshotPlainDataObject({ a: 1 }, ['a', 'b'], 'record', ['a']),
    ).toEqual(Object.assign(Object.create(null), { a: 1 }));
    expect(() =>
      snapshotPlainDataObject({ b: 1 }, ['a', 'b'], 'record', ['a']),
    ).toThrow('record has unexpected or missing fields');
  });

  test.each([
    [null, 'record must be an object'],
    ['text', 'record must be an object'],
    [new Map(), 'record must be a plain object'],
    [{ a: 1, extra: 2 }, 'record has unexpected or missing fields'],
    [{ a: 1, [Symbol('extra')]: 2 }, 'record has unexpected or missing fields'],
  ])('rejects %p', (value, message) => {
    expect(() => snapshotPlainDataObject(value, ['a'], 'record')).toThrow(
      message,
    );
  });

  test('reports accessor and hidden fields before key-set mismatches', () => {
    let reads = 0;
    const accessor = Object.defineProperty({}, 'a', {
      enumerable: true,
      get: () => ++reads,
    });
    expect(() =>
      snapshotPlainDataObject(accessor, ['a', 'b'], 'record'),
    ).toThrow('a must be an enumerable own data property');
    const hidden = Object.defineProperty({}, 'a', { value: 1 });
    expect(() => snapshotPlainDataObject(hidden, ['a'], 'record')).toThrow(
      'a must be an enumerable own data property',
    );
    expect(reads).toBe(0);
  });

  test('fails closed when reflection traps throw', () => {
    const hostile = new Proxy(
      { a: 1 },
      {
        ownKeys: () => {
          throw new Error('trap');
        },
      },
    );
    expect(() => snapshotPlainDataObject(hostile, ['a'], 'record')).toThrow(
      'record must be a plain data object',
    );
    const descriptorTrap = new Proxy(
      { a: 1 },
      {
        getOwnPropertyDescriptor: () => {
          throw new Error('trap');
        },
      },
    );
    expect(() =>
      snapshotPlainDataObject(descriptorTrap, ['a'], 'record'),
    ).toThrow('record must contain only own data properties');
  });
});

describe('snapshotPlainDataArray', () => {
  test('copies dense data elements', () => {
    const value = [1, 2];
    const snapshot = snapshotPlainDataArray(value, 'items', 2);
    value[0] = 9;
    expect(snapshot).toEqual([1, 2]);
  });

  test('rejects oversized, sparse, decorated and accessor arrays', () => {
    expect(() => snapshotPlainDataArray([1, 2, 3], 'items', 2)).toThrow(
      'items must be a bounded plain array',
    );
    expect(() => snapshotPlainDataArray({ length: 0 }, 'items', 2)).toThrow(
      'items must be a bounded plain array',
    );
    expect(() => snapshotPlainDataArray([1, , 3], 'items', 4)).toThrow(
      'items must not be sparse or contain extra properties',
    );
    expect(() =>
      snapshotPlainDataArray(Object.assign([1], { extra: true }), 'items', 4),
    ).toThrow('items must not be sparse or contain extra properties');
    const accessor = [0];
    Object.defineProperty(accessor, 0, { enumerable: true, get: () => 1 });
    expect(() => snapshotPlainDataArray(accessor, 'items', 4)).toThrow(
      'items must contain only own data properties',
    );
  });
});
