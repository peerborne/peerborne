import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  deserializePathUpdateFromWire,
  serializePathUpdateForWire,
} from './path-update-wire.js';

function buildValidPayload() {
  const update = {
    senderLeafIndex: 3,
    senderLeafPublicKey: new Uint8Array(65).fill(1),
    nodes: [{
      nodeIndex: 4,
      publicKey: new Uint8Array(65).fill(2),
      encryptedPrivateKey: new Uint8Array([40, 50, 60]),
    }],
  };
  return serializePathUpdateForWire(update);
}

describe('deserializePathUpdateFromWire malformed inputs', () => {
  test('rejects null', () => {
    expect(() => deserializePathUpdateFromWire(null)).toThrow(/expected a plain object/);
  });
  test('rejects array', () => {
    expect(() => deserializePathUpdateFromWire([])).toThrow(/expected a plain object/);
  });
  test('rejects string', () => {
    expect(() => deserializePathUpdateFromWire('bad')).toThrow(/expected a plain object/);
  });
  test('rejects missing senderLeafIndex', () => {
    const bad = { ...buildValidPayload() };
    delete (bad as any).senderLeafIndex;
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects non-integer senderLeafIndex', () => {
    const bad = { ...buildValidPayload(), senderLeafIndex: 1.5 };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects negative senderLeafIndex', () => {
    const bad = { ...buildValidPayload(), senderLeafIndex: -1 };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects non-string senderLeafIndex', () => {
    const bad = { ...buildValidPayload(), senderLeafIndex: 'three' };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/senderLeafIndex/);
  });
  test('rejects non-string senderLeafPublicKey', () => {
    const bad = { ...buildValidPayload(), senderLeafPublicKey: 123 };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/senderLeafPublicKey/);
  });
  test('rejects non-array nodes', () => {
    const bad = { ...buildValidPayload(), nodes: { 0: {} } };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/'nodes' must be an array/);
  });
  test('rejects null nodes', () => {
    const bad = { ...buildValidPayload(), nodes: null };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/'nodes' must be an array/);
  });
  test('rejects node element that is not an object', () => {
    const bad = { ...buildValidPayload(), nodes: ['not-a-node'] as any };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/node\[0\] must be a plain object/);
  });
  test('rejects node element that is null', () => {
    const bad = { ...buildValidPayload(), nodes: [null] as any };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/node\[0\] must be a plain object/);
  });
  test('rejects node with missing nodeIndex', () => {
    const node = {
      publicKey: Base64.fromUint8Array(new Uint8Array(65).fill(2)),
      encryptedPrivateKey: Base64.fromUint8Array(new Uint8Array([40])),
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/node\[0\].nodeIndex/);
  });
  test('rejects node with negative nodeIndex', () => {
    const node = {
      nodeIndex: -1,
      publicKey: Base64.fromUint8Array(new Uint8Array(65).fill(2)),
      encryptedPrivateKey: Base64.fromUint8Array(new Uint8Array([40])),
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/node\[0\].nodeIndex/);
  });
  test('rejects node with non-string publicKey', () => {
    const node = {
      nodeIndex: 4,
      publicKey: 123,
      encryptedPrivateKey: Base64.fromUint8Array(new Uint8Array([40])),
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/node\[0\].publicKey must be a base64/);
  });
  test('rejects node with non-string encryptedPrivateKey', () => {
    const node = {
      nodeIndex: 4,
      publicKey: Base64.fromUint8Array(new Uint8Array(65).fill(2)),
      encryptedPrivateKey: null,
    };
    const bad = { ...buildValidPayload(), nodes: [node] };
    expect(() => deserializePathUpdateFromWire(bad)).toThrow(/node\[0\].encryptedPrivateKey must be a base64/);
  });
});

describe('deserializePathUpdateFromWire valid inputs', () => {
  test('round-trips a valid payload', () => {
    const payload = buildValidPayload();
    const result = deserializePathUpdateFromWire(payload);
    expect(result.senderLeafIndex).toBe(3);
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0].nodeIndex).toBe(4);
  });
  test('handles empty nodes array', () => {
    const payload = { ...buildValidPayload(), nodes: [] };
    const result = deserializePathUpdateFromWire(payload);
    expect(result.nodes).toHaveLength(0);
  });
});