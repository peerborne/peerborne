import { describe, expect, test } from '@jest/globals';
import { deserializeChangeNodeFromJSON, describeValue } from './merkle-dag-serialization';
import { crdtDocumentChangeNode, crdtWriterChangeNode } from './crdt-change-node';

const id = <T>(x: T): T => x;

describe('describeValue', () => {
  test('returns null for null', () => { expect(describeValue(null)).toBe('null'); });
  test('returns array for arrays', () => { expect(describeValue([])).toBe('array'); });
  test('returns typeof for primitives', () => {
    expect(describeValue('hello')).toBe('string');
    expect(describeValue(42)).toBe('number');
    expect(describeValue(true)).toBe('boolean');
  });
});

describe('deserializeChangeNodeFromJSON malformed inputs', () => {
  test('rejects null', () => {
    expect(() => deserializeChangeNodeFromJSON(null as any, id)).toThrow(/expected a plain object/);
  });
  test('rejects array', () => {
    expect(() => deserializeChangeNodeFromJSON([] as any, id)).toThrow(/expected a plain object/);
  });
  test('rejects string', () => {
    expect(() => deserializeChangeNodeFromJSON('bad' as any, id)).toThrow(/expected a plain object/);
  });
  test('rejects number', () => {
    expect(() => deserializeChangeNodeFromJSON(42 as any, id)).toThrow(/expected a plain object/);
  });
  test('rejects missing kind', () => {
    expect(() => deserializeChangeNodeFromJSON({} as any, id)).toThrow(/"kind"/);
  });
  test('rejects unknown kind', () => {
    expect(() => deserializeChangeNodeFromJSON({ kind: 'invalid-kind' } as any, id)).toThrow(/"kind"/);
  });
  test('rejects non-string keyID when present', () => {
    expect(() => deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, keyID: 123 } as any, id)).toThrow(/"keyID"/);
  });
  test('rejects object keyID when present', () => {
    expect(() => deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, keyID: {} } as any, id)).toThrow(/"keyID"/);
  });
  test('rejects non-object children', () => {
    expect(() => deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, children: 42 } as any, id)).toThrow(/"children"/);
  });
  test('rejects null children', () => {
    expect(() => deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, children: null } as any, id)).toThrow(/"children"/);
  });
  test('rejects array children', () => {
    expect(() => deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, children: [] } as any, id)).toThrow(/"children"/);
  });
});

describe('deserializeChangeNodeFromJSON valid inputs', () => {
  test('deserializes a leaf document-change node', () => {
    const result = deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, keyID: 'test-key-id', change: 'leaf' } as any, id);
    expect(result.kind).toBe(crdtDocumentChangeNode);
    expect(result.keyID).toBe('test-key-id');
    expect(result.change).toBe('leaf');
  });
  test('deserializes a leaf node without keyID', () => {
    const result = deserializeChangeNodeFromJSON({ kind: crdtDocumentChangeNode, change: 'data' } as any, id);
    expect(result.keyID).toBeUndefined();
  });
  test('deserializes a leaf node without change', () => {
    const result = deserializeChangeNodeFromJSON({ kind: crdtWriterChangeNode, keyID: 'writer-key' } as any, id);
    expect(result.kind).toBe(crdtWriterChangeNode);
    expect(result.change).toBeUndefined();
  });
  test('deserializes a node with nested children', () => {
    const wire: any = { kind: crdtDocumentChangeNode, children: { abc: { kind: crdtWriterChangeNode, keyID: 'child-key', change: 'child-payload' } } };
    const result: any = deserializeChangeNodeFromJSON(wire, id);
    expect(result.children.abc.kind).toBe(crdtWriterChangeNode);
    expect(result.children.abc.keyID).toBe('child-key');
  });
  test('children map uses null prototype', () => {
    const wire: any = { kind: crdtDocumentChangeNode, children: { abc: { kind: crdtWriterChangeNode } } };
    const result: any = deserializeChangeNodeFromJSON(wire, id);
    expect(Object.getPrototypeOf(result.children)).toBeNull();
  });
  test('children map resists __proto__ pollution', () => {
    const wire: any = { kind: crdtDocumentChangeNode, children: { __proto__: { kind: crdtWriterChangeNode, change: 'evil' }, legit: { kind: crdtWriterChangeNode, change: 'good' } } };
    const result: any = deserializeChangeNodeFromJSON(wire, id);
    expect(Object.getPrototypeOf(result.children)).toBeNull();
    expect(result.children.legit).toBeDefined();
    expect((Object.prototype as any).polluted).toBeUndefined();
  });
});
