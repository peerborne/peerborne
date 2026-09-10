import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { PathUpdateV2 } from './beekem/types.js';
import {
  deserializePathUpdateFromWire,
  deserializePathUpdateV2FromWire,
  serializePathUpdateForWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';
import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function validPathUpdateV2(): PathUpdateV2 {
  return {
    version: 2,
    generation: 1,
    parentTreeHash: new Uint8Array(32).fill(1),
    numLeaves: 2,
    senderLeafIndex: 0,
    senderLeafPublicKey: new Uint8Array(65).fill(2),
    nodes: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array(65).fill(3),
        encryptedPrivateKey: new Uint8Array([4]),
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 2, ciphertext: new Uint8Array([5]) },
        ],
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array(65).fill(6) },
      { nodeIndex: 1, publicKey: new Uint8Array(65).fill(7) },
      { nodeIndex: 2, publicKey: new Uint8Array(65).fill(8) },
    ],
    treeHash: new Uint8Array(32).fill(9),
  };
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

describe('path-update-wire V2 outbound boundary', () => {
  test('round-trips a strictly validated runtime value', () => {
    const update = validPathUpdateV2();
    const wire = serializePathUpdateV2ForWire(update);

    expect(wire.version).toBe(update.version);
    expect(deserializePathUpdateV2FromWire(wire)).toEqual(update);
  });

  test.each([
    ['version', { version: 1 }],
    ['generation', { generation: 0 }],
    ['numLeaves', { numLeaves: 999_999 }],
    ['parentTreeHash', { parentTreeHash: new Uint8Array([1]) }],
    ['senderLeafPublicKey', { senderLeafPublicKey: new Uint8Array([1]) }],
    ['treeHash', { treeHash: new Uint8Array([1]) }],
  ])('rejects invalid runtime %s instead of normalizing it', (_field, patch) => {
    expect(() =>
      serializePathUpdateV2ForWire({
        ...validPathUpdateV2(),
        ...patch,
      } as PathUpdateV2),
    ).toThrow(/Invalid PathUpdateV2/);
  });

  test('uses intrinsic byte lengths instead of shadowed properties', () => {
    const shadowedKey = new Uint8Array([1]);
    Object.defineProperty(shadowedKey, 'length', { value: 65 });
    const shadowedHash = new Uint8Array([2]);
    Object.defineProperty(shadowedHash, 'byteLength', { value: 32 });

    expect(() =>
      serializePathUpdateV2ForWire({
        ...validPathUpdateV2(),
        senderLeafPublicKey: shadowedKey,
      }),
    ).toThrow(/senderLeafPublicKey.*65/);
    expect(() =>
      serializePathUpdateV2ForWire({
        ...validPathUpdateV2(),
        treeHash: shadowedHash,
      }),
    ).toThrow(/treeHash.*32/);
  });

  test('rejects typed-array lookalikes and SharedArrayBuffer-backed bytes', () => {
    expect(() =>
      serializePathUpdateV2ForWire({
        ...validPathUpdateV2(),
        parentTreeHash: {
          length: 32,
          byteLength: 32,
          buffer: new ArrayBuffer(32),
        } as unknown as Uint8Array,
      }),
    ).toThrow(/parentTreeHash.*Uint8Array/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        serializePathUpdateV2ForWire({
          ...validPathUpdateV2(),
          senderLeafPublicKey: new Uint8Array(new SharedArrayBuffer(65)),
        }),
      ).toThrow(/senderLeafPublicKey.*unshared/);
    }
  });

  test('rejects oversized nested arrays before reading their entries', () => {
    let nodeReads = 0;
    const oversizedNodes = new Array(65);
    Object.defineProperty(oversizedNodes, '0', {
      enumerable: true,
      get() {
        nodeReads++;
        throw new Error('must not read an oversized node array');
      },
    });
    expect(() =>
      serializePathUpdateV2ForWire({
        ...validPathUpdateV2(),
        nodes: oversizedNodes,
      } as PathUpdateV2),
    ).toThrow(/nodes exceeds 64 entries/);
    expect(nodeReads).toBe(0);

    let bundleReads = 0;
    const oversizedBundles = new Array(3);
    Object.defineProperty(oversizedBundles, '0', {
      enumerable: true,
      get() {
        bundleReads++;
        throw new Error('must not read an oversized bundle array');
      },
    });
    const update = validPathUpdateV2();
    update.nodes[0].encryptedPathKeyBundles = oversizedBundles;
    expect(() => serializePathUpdateV2ForWire(update)).toThrow(
      /encryptedPathKeyBundles exceeds numLeaves/,
    );
    expect(bundleReads).toBe(0);
  });

  test('rejects Base64 expansion past the shared-protocol frame cap', () => {
    const maximumCiphertextBytes = 64 * (4096 + 8) + 4096;
    const fixedCiphertextCount = 29;
    const makeUpdate = (tailLength: number): PathUpdateV2 => ({
      ...validPathUpdateV2(),
      numLeaves: 32,
      nodes: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(0),
          encryptedPathKeyBundles: [
            ...Array.from({ length: fixedCiphertextCount }, (_, index) => ({
              recipientNodeIndex: index,
              ciphertext: new Uint8Array(maximumCiphertextBytes),
            })),
            {
              recipientNodeIndex: fixedCiphertextCount,
              ciphertext: new Uint8Array(tailLength),
            },
          ],
        },
      ],
      treeNodePublicKeys: Array.from({ length: 63 }, (_, nodeIndex) => ({
        nodeIndex,
        publicKey: new Uint8Array(65),
      })),
    });

    const baselineWire = serializePathUpdateV2ForWire(makeUpdate(1));
    const baselineBytes = JSON.stringify(baselineWire).length;
    const remainingBase64Quartets = Math.floor(
      (MAX_SHARED_PROTOCOL_REQUEST_BYTES - baselineBytes) / 4,
    );
    const boundaryTailLength = 3 * (1 + remainingBase64Quartets);
    expect(boundaryTailLength).toBeLessThan(maximumCiphertextBytes);

    const boundaryWire = serializePathUpdateV2ForWire(
      makeUpdate(boundaryTailLength),
    );
    const boundaryBytes = JSON.stringify(boundaryWire).length;
    expect(boundaryBytes).toBeLessThanOrEqual(
      MAX_SHARED_PROTOCOL_REQUEST_BYTES,
    );
    expect(MAX_SHARED_PROTOCOL_REQUEST_BYTES - boundaryBytes).toBeLessThan(4);

    expect(() =>
      serializePathUpdateV2ForWire(makeUpdate(boundaryTailLength + 1)),
    ).toThrow(/PathUpdate v2 wire payload exceeds/);
  });
});
