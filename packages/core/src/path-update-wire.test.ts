import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import {
  deserializePathUpdateFromWire,
  serializePathUpdateForWire,
} from './path-update-wire.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

describe('path-update-wire', () => {
  test('round-trips a real PathUpdate produced by BeeKEM.update', async () => {
    // Build a 3-member group so the PathUpdate has multiple internal
    // nodes (a richer payload to round-trip).
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);

    const charlieKeys = await generateECDHKeyPair();
    await alice.addMember(charlieKeys.publicKey);

    const { pathUpdate } = await alice.update();
    expect(pathUpdate.nodes.length).toBeGreaterThan(0);

    const wire = serializePathUpdateForWire(pathUpdate);
    // JSON-safety smoke test: a SerializedPathUpdate should survive a
    // JSON.stringify / JSON.parse round-trip without losing fidelity.
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializePathUpdateFromWire(reparsed);

    expect(restored.senderLeafIndex).toBe(pathUpdate.senderLeafIndex);
    expect(restored.senderLeafPublicKey).toEqual(pathUpdate.senderLeafPublicKey);
    expect(restored.nodes.length).toBe(pathUpdate.nodes.length);
    for (let i = 0; i < pathUpdate.nodes.length; i++) {
      expect(restored.nodes[i].nodeIndex).toBe(pathUpdate.nodes[i].nodeIndex);
      expect(restored.nodes[i].publicKey).toEqual(pathUpdate.nodes[i].publicKey);
      expect(restored.nodes[i].encryptedPrivateKey).toEqual(
        pathUpdate.nodes[i].encryptedPrivateKey,
      );
    }
  });

  test('round-tripped PathUpdate is still applicable to a peer', async () => {
    // Confirm that the wire bytes don't only structurally round-trip
    // -- they also remain semantically valid: a peer that receives the
    // restored object can still process it via `processPathUpdate`.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);

    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);

    const { pathUpdate, rootSecret: aliceNewRoot } = await alice.update();
    const wire = serializePathUpdateForWire(pathUpdate);
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializePathUpdateFromWire(reparsed);

    const bobNewRoot = await bob.processPathUpdate(restored);
    expect(Buffer.from(aliceNewRoot).equals(Buffer.from(bobNewRoot))).toBe(true);
  });

  test('rejects malformed inputs with descriptive errors', () => {
    expect(() => deserializePathUpdateFromWire(null)).toThrow(
      /plain object/,
    );
    expect(() => deserializePathUpdateFromWire('hi')).toThrow(/plain object/);
    expect(() => deserializePathUpdateFromWire([])).toThrow(/plain object/);
    expect(() =>
      deserializePathUpdateFromWire({
        senderLeafPublicKey: 'AA==',
        nodes: [],
      }),
    ).toThrow(/senderLeafIndex/);
    expect(() =>
      deserializePathUpdateFromWire({
        senderLeafIndex: 0,
        senderLeafPublicKey: 42,
        nodes: [],
      }),
    ).toThrow(/senderLeafPublicKey/);
    expect(() =>
      deserializePathUpdateFromWire({
        senderLeafIndex: 0,
        senderLeafPublicKey: 'AA==',
        nodes: 'oops',
      }),
    ).toThrow(/'nodes' must be an array/);
    expect(() =>
      deserializePathUpdateFromWire({
        senderLeafIndex: 0,
        senderLeafPublicKey: 'AA==',
        nodes: [{ nodeIndex: 'not-int', publicKey: '', encryptedPrivateKey: '' }],
      }),
    ).toThrow(/node\[0\].nodeIndex/);
  });
});
