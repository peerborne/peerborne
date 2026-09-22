import { welcomeFixture } from './__testutils__/beekem-v2.js';
import { describe, expect, test } from '@jest/globals';
import {
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMWelcomeV2ForWire,
} from './beekem-welcome-wire';

const buildValidWelcome = welcomeFixture;

function buildValidWire() {
  return serializeBeeKEMWelcomeV2ForWire(buildValidWelcome());
}

describe('deserializeBeeKEMWelcomeV2FromWire malformed inputs', () => {
  test('rejects null', () => {
    expect(() => deserializeBeeKEMWelcomeV2FromWire(null)).toThrow(/expected a plain object/);
  });
  test('rejects array', () => {
    expect(() => deserializeBeeKEMWelcomeV2FromWire([1, 2, 3])).toThrow(/expected a plain object/);
  });
  test('rejects string', () => {
    expect(() => deserializeBeeKEMWelcomeV2FromWire('bad')).toThrow(/expected a plain object/);
  });
  test('rejects boolean', () => {
    expect(() => deserializeBeeKEMWelcomeV2FromWire(true)).toThrow(/expected a plain object/);
  });
  test('rejects non-integer leafIndex', () => {
    const bad = { ...buildValidWire(), leafIndex: 1.5 };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/leafIndex/);
  });
  test('rejects negative leafIndex', () => {
    const bad = { ...buildValidWire(), leafIndex: -1 };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/leafIndex/);
  });
  test('rejects string leafIndex', () => {
    const bad = { ...buildValidWire(), leafIndex: 'three' };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/leafIndex/);
  });
  test('rejects non-array pathKeys', () => {
    const bad = { ...buildValidWire(), pathKeys: { 0: {} } };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/'pathKeys' must be an array/);
  });
  test('rejects null pathKeys', () => {
    const bad = { ...buildValidWire(), pathKeys: null };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/'pathKeys' must be an array/);
  });
  test('rejects non-array treeNodePublicKeys', () => {
    const bad = { ...buildValidWire(), treeNodePublicKeys: 'not-an-array' };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/'treeNodePublicKeys' must be an array/);
  });
  test('rejects non-string treeHash', () => {
    const bad = { ...buildValidWire(), treeHash: 123 };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/'treeHash' must be (a )?base64/);
  });
  test('rejects pathKey element that is not an object', () => {
    const bad = { ...buildValidWire(), pathKeys: ['not-an-object'] as any };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/pathKeys\[0\].*plain object/);
  });
  test('rejects pathKey with non-integer nodeIndex', () => {
    const wire = buildValidWire();
    (wire.pathKeys[0] as any).nodeIndex = 1.5;
    expect(() => deserializeBeeKEMWelcomeV2FromWire(wire)).toThrow(/pathKeys\[0\].nodeIndex/);
  });
  test('rejects pathKey with non-string publicKey', () => {
    const wire = buildValidWire();
    (wire.pathKeys[0] as any).publicKey = 123;
    expect(() => deserializeBeeKEMWelcomeV2FromWire(wire)).toThrow(/pathKeys\[0\].*base64/);
  });
  test('rejects treeNodePublicKey element that is not an object', () => {
    const bad = { ...buildValidWire(), treeNodePublicKeys: ['bad'] };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(bad)).toThrow(/treeNodePublicKeys\[0\].*plain object/);
  });
  test('rejects treeNodePublicKey with non-integer nodeIndex', () => {
    const wire = buildValidWire();
    (wire.treeNodePublicKeys[0] as any).nodeIndex = 'abc';
    expect(() => deserializeBeeKEMWelcomeV2FromWire(wire)).toThrow(/treeNodePublicKeys\[0\].nodeIndex/);
  });
  test('rejects treeNodePublicKey with invalid publicKey type', () => {
    const wire = buildValidWire();
    (wire.treeNodePublicKeys[0] as any).publicKey = 123;
    expect(() => deserializeBeeKEMWelcomeV2FromWire(wire)).toThrow(/treeNodePublicKeys\[0\].publicKey must be (a )?base64/);
  });
});

describe('deserializeBeeKEMWelcomeV2FromWire valid inputs', () => {
  test('round-trips a valid welcome', () => {
    const wire = buildValidWire();
    const result = deserializeBeeKEMWelcomeV2FromWire(wire);
    expect(result.leafIndex).toBe(2);
    expect(result.pathKeys).toHaveLength(1);
    expect(result.treeNodePublicKeys).toHaveLength(1);
  });
  test('rejects an incomplete Welcome tree', () => {
    const wire = { ...buildValidWire(), pathKeys: [], treeNodePublicKeys: [] };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(wire)).toThrow();
  });
});