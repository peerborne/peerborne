import { describe, expect, test } from '@jest/globals';
import { extractField } from './field-extractor.js';

describe('extractField', () => {
  test.each([
    // [description, object, path, expected]
    ['simple top-level field', { name: 'Alice' }, 'name', 'Alice'],
    ['nested field', { a: { b: 'deep' } }, 'a.b', 'deep'],
    ['deeply nested field', { a: { b: { c: { d: 42 } } } }, 'a.b.c.d', 42],
    ['array index', { tags: ['foo', 'bar', 'baz'] }, 'tags.1', 'bar'],
    ['nested array index', { a: { b: [10, 20, 30] } }, 'a.b.2', 30],
    ['object inside array', { items: [{ name: 'x' }] }, 'items.0.name', 'x'],
    ['boolean value', { active: true }, 'active', true],
    ['numeric value', { count: 0 }, 'count', 0],
    ['null value at leaf', { val: null }, 'val', null],
    ['empty string value', { name: '' }, 'name', ''],

    // Missing paths
    ['missing top-level field', { name: 'Alice' }, 'age', undefined],
    ['missing nested field', { a: { b: 'x' } }, 'a.c', undefined],
    ['missing deep path', { a: {} }, 'a.b.c.d', undefined],
    ['null intermediate', { a: null }, 'a.b', undefined],
    ['undefined intermediate', {}, 'a.b', undefined],
    ['primitive intermediate', { a: 'string' }, 'a.b', undefined],
    ['number intermediate', { a: 42 }, 'a.b', undefined],

    // Edge cases
    ['empty object', {}, 'anything', undefined],
    ['root is null', null, 'a', undefined],
    ['root is undefined', undefined, 'a', undefined],
    ['root is number', 42, 'a', undefined],
    ['root is string', 'hello', 'length', undefined],
  ] as [string, unknown, string, unknown][])(
    '%s: extractField(%j, %j) → %j',
    (_description, obj, path, expected) => {
      expect(extractField(obj, path)).toStrictEqual(expected);
    },
  );
});
