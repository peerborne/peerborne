import { pathUpdateFixture } from './__mocks__/beekem-v2.js';
import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  deserializePathUpdateV2FromWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';

function buildValidPayload() {
  const update = pathUpdateFixture();
  return serializePathUpdateV2ForWire(update);
}

describe('deserializePathUpdateV2FromWire malformed inputs', () => {
  test('rejects null', () => {
    expect(() => deserializePathUpdateV2FromWire(null)).toThrow(/expected a plain object/);
  });
  test('rejects array', () => {
    expect(() => deserializePathUpdateV2FromWire([])).toThrow(/expected a plain object/);
  });
  test('rejects string', () => {
    expect(() => deserializePathUpdateV2FromWire('bad')).toThrow(/expected a plain object/);
  });
  test('rejects missing senderLeafIndex', () => {
    const bad = { ...buildValidPayload() };
    delete (bad as any).senderLeafIndex;
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects non-integer senderLeafIndex', () => {
    const bad = { ...buildValidPayload(), senderLeafIndex: 1.5 };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects negative senderLeafIndex', () => {
    const bad = { ...buildValidPayload(), senderLeafIndex: -1 };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects non-string senderLeafIndex', () => {
    const bad = { ...buildValidPayload(), senderLeafIndex: 'three' };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects non-string senderLeafPublicKey', () => {
    const bad = { ...buildValidPayload(), senderLeafPublicKey: 123 };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/senderLeafPublicKey/);
  });
  test('rejects non-array nodes', () => {
    const bad = { ...buildValidPayload(), nodes: { 0: {} } };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/'nodes' must be an array/);
  });
  test('rejects null nodes', () => {
    const bad = { ...buildValidPayload(), nodes: null };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/'nodes' must be an array/);
  });
  test('rejects node element that is not an object', () => {
    const bad = { ...buildValidPayload(), nodes: ['not-a-node'] as any };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/node\[0\].*plain object/);
  });
  test('rejects node element that is null', () => {
    const bad = { ...buildValidPayload(), nodes: [null] as any };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/node\[0\].*plain object/);
  });
  test('rejects node with missing nodeIndex', () => {
    const node = {
      publicKey: Base64.fromUint8Array(new Uint8Array(65).fill(2)),
      encryptedPathKeyBundles: buildValidPayload().nodes[0].encryptedPathKeyBundles,
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/node\[0\].nodeIndex/);
  });
  test('rejects node with negative nodeIndex', () => {
    const node = {
      nodeIndex: -1,
      publicKey: Base64.fromUint8Array(new Uint8Array(65).fill(2)),
      encryptedPathKeyBundles: buildValidPayload().nodes[0].encryptedPathKeyBundles,
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/node\[0\].nodeIndex/);
  });
  test('rejects node with non-string publicKey', () => {
    const node = {
      nodeIndex: 1,
      publicKey: 123,
      encryptedPathKeyBundles: buildValidPayload().nodes[0].encryptedPathKeyBundles,
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/node\[0\].publicKey must be (a )?base64/);
  });
  test('rejects node with non-array encryptedPathKeyBundles', () => {
    const node = {
      nodeIndex: 1,
      publicKey: Base64.fromUint8Array(new Uint8Array(65).fill(2)),
      encryptedPathKeyBundles: null,
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateV2FromWire(bad)).toThrow(/node\[0\].encryptedPathKeyBundles must be an array/);
  });
});

describe('deserializePathUpdateV2FromWire valid inputs', () => {
  test('round-trips a valid payload', () => {
    const payload = buildValidPayload();
    const result = deserializePathUpdateV2FromWire(payload);
    expect(result.senderLeafIndex).toBe(0);
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0].nodeIndex).toBe(1);
  });
  test('rejects an empty direct path in a two-member tree', () => {
    const payload = { ...buildValidPayload(), nodes: [] };
    expect(() => deserializePathUpdateV2FromWire(payload)).toThrow(/direct path/);
  });
});