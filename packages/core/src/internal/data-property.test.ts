import { describe, expect, test } from '@jest/globals';
import {
  optionalOwnDataProperty,
  ownDataProperty,
  requireIntrinsicGetter,
} from './data-property.js';

describe('own data properties', () => {
  test('read enumerable data fields without invoking accessors', () => {
    let reads = 0;
    const value = Object.defineProperties(
      { field: 1 },
      {
        hidden: { value: 2, enumerable: false },
        accessor: {
          enumerable: true,
          get: () => {
            reads += 1;
            return 3;
          },
        },
      },
    );
    expect(ownDataProperty(value, 'field')).toBe(1);
    expect(() => ownDataProperty(value, 'hidden', 'record')).toThrow(
      'record hidden must be an enumerable own data property',
    );
    expect(() => ownDataProperty(value, 'accessor')).toThrow(
      'accessor must be an enumerable own data property',
    );
    expect(() => ownDataProperty(value, 'missing')).toThrow(/missing/);
    expect(reads).toBe(0);
  });

  test('optional reads treat absence as undefined but still reject accessors', () => {
    const value = Object.defineProperty({}, 'accessor', {
      enumerable: true,
      get: () => 1,
    });
    expect(optionalOwnDataProperty(value, 'missing')).toBeUndefined();
    expect(() => optionalOwnDataProperty(value, 'accessor')).toThrow(
      /enumerable own data property/,
    );
  });

  test('intrinsic getters must exist', () => {
    expect(
      requireIntrinsicGetter(Map.prototype, 'size', 'Map.prototype.size').call(
        new Map([[1, 1]]),
      ),
    ).toBe(1);
    expect(() =>
      requireIntrinsicGetter(Map.prototype, 'missing', 'Map.prototype.missing'),
    ).toThrow('Map.prototype.missing intrinsic is unavailable');
  });
});
