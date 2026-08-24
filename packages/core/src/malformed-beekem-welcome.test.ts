import { describe, expect, test } from '@jest/globals';
import {
  deserializeBeeKEMWelcomeFromWire,
  serializeBeeKEMWelcomeForWire,
} from './beekem-welcome-wire';

function buildValidWelcome() {
  return {
    leafIndex: 3,
    pathKeys: [{
      nodeIndex: 4,
      publicKey: new Uint8Array(65).fill(2),
      encryptedPrivateKey: new Uint8Array([40, 50, 60]),
    }],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array(65).fill(70) },
      { nodeIndex: 1, publicKey: null },
    ],
    treeHash: new Uint8Array([99, 100, 101]),
  };
}

function buildValidWire() {
  return serializeBeeKEMWelcomeForWire(buildValidWelcome());
}

describe('deserializeBeeKEMWelcomeFromWire malformed inputs', () => {
  test('rejects null', () => {
    expect(() => deserializeBeeKEMWelcomeFromWire(null)).toThrow(/expected a plain object/);
  });
  test('rejects array', () => {
    expect(() => deserializeBeeKEMWelcomeFromWire([1, 2, 3])).toThrow(/expected a plain object/);
  });
  test('rejects string', () => {
    expect(() => deserializeBeeKEMWelcomeFromWire('bad')).toThrow(/expected a plain object/);
  });
  test('rejects boolean', () => {
    expect(() => deserializeBeeKEMWelcomeFromWire(true)).toThrow(/expected a plain object/);
  });
  test('rejects non-integer leafIndex', () => {
    const bad = { ...buildValidWire(), leafIndex: 1.5 };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/leafIndex/);
  });
  test('rejects negative leafIndex', () => {
    const bad = { ...buildValidWire(), leafIndex: -1 };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/leafIndex/);
  });
  test('rejects string leafIndex', () => {
    const bad = { ...buildValidWire(), leafIndex: 'three' };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/leafIndex/);
  });
  test('rejects non-array pathKeys', () => {
    const bad = { ...buildValidWire(), pathKeys: { 0: {} } };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/'pathKeys' must be an array/);
  });
  test('rejects null pathKeys', () => {
    const bad = { ...buildValidWire(), pathKeys: null };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/'pathKeys' must be an array/);
  });
  test('rejects non-array treeNodePublicKeys', () => {
    const bad = { ...buildValidWire(), treeNodePublicKeys: 'not-an-array' };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/'treeNodePublicKeys' must be an array/);
  });
  test('rejects non-string treeHash', () => {
    const bad = { ...buildValidWire(), treeHash: 123 };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/'treeHash' must be a base64/);
  });
  test('rejects pathKey element that is not an object', () => {
    const bad = { ...buildValidWire(), pathKeys: ['not-an-object'] as any };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/pathKeys\[0\] must be a plain object/);
  });
  test('rejects pathKey with non-integer nodeIndex', () => {
    const wire = buildValidWire();
    (wire.pathKeys[0] as any).nodeIndex = 1.5;
    expect(() => deserializeBeeKEMWelcomeFromWire(wire)).toThrow(/pathKeys\[0\].nodeIndex/);
  });
  test('rejects pathKey with non-string publicKey', () => {
    const wire = buildValidWire();
    (wire.pathKeys[0] as any).publicKey = 123;
    expect(() => deserializeBeeKEMWelcomeFromWire(wire)).toThrow(/pathKeys\[0\].publicKey must be a base64/);
  });
  test('rejects treeNodePublicKey element that is not an object', () => {
    const bad = { ...buildValidWire(), treeNodePublicKeys: ['bad'] };
    expect(() => deserializeBeeKEMWelcomeFromWire(bad)).toThrow(/treeNodePublicKeys\[0\] must be a plain object/);
  });
  test('rejects treeNodePublicKey with non-integer nodeIndex', () => {
    const wire = buildValidWire();
    (wire.treeNodePublicKeys[0] as any).nodeIndex = 'abc';
    expect(() => deserializeBeeKEMWelcomeFromWire(wire)).toThrow(/treeNodePublicKeys\[0\].nodeIndex/);
  });
  test('rejects treeNodePublicKey with invalid publicKey type', () => {
    const wire = buildValidWire();
    (wire.treeNodePublicKeys[0] as any).publicKey = 123;
    expect(() => deserializeBeeKEMWelcomeFromWire(wire)).toThrow(/treeNodePublicKeys\[0\].publicKey must be a base64/);
  });
});

describe('deserializeBeeKEMWelcomeFromWire valid inputs', () => {
  test('round-trips a valid welcome', () => {
    const wire = buildValidWire();
    const result = deserializeBeeKEMWelcomeFromWire(wire);
    expect(result.leafIndex).toBe(3);
    expect(result.pathKeys).toHaveLength(1);
    expect(result.treeNodePublicKeys).toHaveLength(2);
    expect(result.treeNodePublicKeys[1].publicKey).toBeNull();
  });
  test('handles empty pathKeys and treeNodePublicKeys', () => {
    const wire = { ...buildValidWire(), pathKeys: [], treeNodePublicKeys: [] };
    const result = deserializeBeeKEMWelcomeFromWire(wire);
    expect(result.pathKeys).toHaveLength(0);
    expect(result.treeNodePublicKeys).toHaveLength(0);
  });
});