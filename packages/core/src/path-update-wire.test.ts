import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { PathUpdateV2 } from './beekem/types.js';
import {
  deserializePathUpdateV2FromWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';

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
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 2, ciphertext: new Uint8Array([5]) },
        ],
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array(65).fill(2) },
      { nodeIndex: 1, publicKey: new Uint8Array(65).fill(3) },
      { nodeIndex: 2, publicKey: new Uint8Array(65).fill(8) },
    ],
    treeHash: new Uint8Array(32).fill(9),
  };
}

function validFourLeafPathUpdateV2(): PathUpdateV2 {
  const publicKey = (fill: number) => new Uint8Array(65).fill(fill);
  return {
    version: 2,
    generation: 7,
    parentTreeHash: new Uint8Array(32).fill(1),
    numLeaves: 4,
    senderLeafIndex: 0,
    senderLeafPublicKey: publicKey(10),
    nodes: [
      {
        nodeIndex: 1,
        publicKey: publicKey(11),
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 2, ciphertext: new Uint8Array([41]) },
        ],
      },
      {
        nodeIndex: 3,
        publicKey: publicKey(13),
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 4, ciphertext: new Uint8Array([44]) },
          { recipientNodeIndex: 6, ciphertext: new Uint8Array([46]) },
        ],
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: publicKey(10) },
      { nodeIndex: 1, publicKey: publicKey(11) },
      { nodeIndex: 2, publicKey: publicKey(12) },
      { nodeIndex: 3, publicKey: publicKey(13) },
      { nodeIndex: 4, publicKey: publicKey(14) },
      { nodeIndex: 5, publicKey: null },
      { nodeIndex: 6, publicKey: publicKey(16) },
    ],
    treeHash: new Uint8Array(32).fill(9),
  };
}

type SerializedV2 = ReturnType<typeof serializePathUpdateV2ForWire>;
const malformedMultiLeafPaths: Array<
  [string, (wire: SerializedV2) => SerializedV2['nodes']]
> = [
  ['empty', () => []],
  ['truncated before the root', (wire) => [wire.nodes[0]]],
  ['reordered', (wire) => [wire.nodes[1], wire.nodes[0]]],
  [
    'unrelated',
    (wire) => [{ ...wire.nodes[0], nodeIndex: 5 }, wire.nodes[1]],
  ],
];

describe('path-update-wire', () => {
  test('round-trips a real PathUpdateV2 produced by BeeKEM.update', async () => {
    // Build a 3-member group so the PathUpdateV2 has multiple internal
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

    const wire = serializePathUpdateV2ForWire(pathUpdate);
    // JSON-safety smoke test: a SerializedPathUpdateV2 should survive a
    // JSON.stringify / JSON.parse round-trip without losing fidelity.
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializePathUpdateV2FromWire(reparsed);

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

  test('round-tripped PathUpdateV2 is still applicable to a peer', async () => {
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
    const wire = serializePathUpdateV2ForWire(pathUpdate);
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializePathUpdateV2FromWire(reparsed);

    const bobNewRoot = await bob.processPathUpdate(restored);
    expect(Buffer.from(aliceNewRoot).equals(Buffer.from(bobNewRoot))).toBe(true);
  });

  test.each([
    ['senderLeafIndex', undefined],
    ['senderLeafPublicKey', 42],
    ['nodes', 'oops'],
  ])('rejects malformed %s', (field, value) => {
    const wire = serializePathUpdateV2ForWire(validPathUpdateV2());
    expect(() => deserializePathUpdateV2FromWire({ ...wire, [field]: value }))
      .toThrow(new RegExp(field));
  });

  test('rejects a malformed path-node index in a complete snapshot', () => {
    const wire = serializePathUpdateV2ForWire(validPathUpdateV2());
    wire.nodes[0].nodeIndex = 'not-int' as never;
    expect(() => deserializePathUpdateV2FromWire(wire)).toThrow(/nodeIndex/);
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

  test('accepts an empty direct path only for a single-leaf tree', () => {
    const senderLeafPublicKey = new Uint8Array(65).fill(12);
    const update: PathUpdateV2 = {
      ...validPathUpdateV2(),
      numLeaves: 1,
      senderLeafPublicKey,
      nodes: [],
      treeNodePublicKeys: [
        { nodeIndex: 0, publicKey: senderLeafPublicKey },
      ],
    };

    expect(
      deserializePathUpdateV2FromWire(serializePathUpdateV2ForWire(update)),
    ).toEqual(update);
  });

  test.each(malformedMultiLeafPaths)(
    'rejects a %s multi-leaf update path',
    (_name, mutate) => {
      const wire = serializePathUpdateV2ForWire(validFourLeafPathUpdateV2());
      expect(() =>
        deserializePathUpdateV2FromWire({ ...wire, nodes: mutate(wire) }),
      ).toThrow(/nodes must equal the sender direct path/);
    },
  );

  test('rejects generations outside the unsigned 32-bit wire range', () => {
    const wire = serializePathUpdateV2ForWire(validPathUpdateV2());
    expect(() =>
      deserializePathUpdateV2FromWire({
        version: 2, generation: 1, numLeaves: 2,
        parentTreeHash: "AA==", treeNodePublicKeys: [], treeHash: "AA==",
        ...wire,
        generation: 0x1_0000_0000,
      }),
    ).toThrow(/generation exceeds 2\^32-1/);
  });

  test('binds the sender and updated path keys to the full tree snapshot', () => {
    const wire = serializePathUpdateV2ForWire(validFourLeafPathUpdateV2());
    const senderMismatch = wire.treeNodePublicKeys.map((node) =>
      node.nodeIndex === 0
        ? { ...node, publicKey: wire.treeNodePublicKeys[2].publicKey }
        : node,
    );
    expect(() =>
      deserializePathUpdateV2FromWire({
        version: 2, generation: 1, numLeaves: 2,
        parentTreeHash: "AA==", treeNodePublicKeys: [], treeHash: "AA==",
        ...wire,
        treeNodePublicKeys: senderMismatch,
      }),
    ).toThrow(/senderLeafPublicKey does not match the tree snapshot/);

    const pathMismatch = wire.treeNodePublicKeys.map((node) =>
      node.nodeIndex === 3
        ? { ...node, publicKey: wire.treeNodePublicKeys[4].publicKey }
        : node,
    );
    expect(() =>
      deserializePathUpdateV2FromWire({
        version: 2, generation: 1, numLeaves: 2,
        parentTreeHash: "AA==", treeNodePublicKeys: [], treeHash: "AA==",
        ...wire,
        treeNodePublicKeys: pathMismatch,
      }),
    ).toThrow(/node\[1\].publicKey does not match the tree snapshot/);
  });

  test('requires each bundle set to equal its copath snapshot resolution', () => {
    const wire = serializePathUpdateV2ForWire(validFourLeafPathUpdateV2());
    const rootNode = wire.nodes[1];
    const missingRecipient = [
      wire.nodes[0],
      {
        ...rootNode,
        encryptedPathKeyBundles: [rootNode.encryptedPathKeyBundles[0]],
      },
    ];
    expect(() =>
      deserializePathUpdateV2FromWire({
        version: 2, generation: 1, numLeaves: 2,
        parentTreeHash: "AA==", treeNodePublicKeys: [], treeHash: "AA==",
        ...wire,
        nodes: missingRecipient,
      }),
    ).toThrow(/bundle recipients do not match its copath resolution/);

    const blankRootRecipient = [
      wire.nodes[0],
      {
        ...rootNode,
        encryptedPathKeyBundles: [
          {
            ...rootNode.encryptedPathKeyBundles[0],
            recipientNodeIndex: 5,
          },
          rootNode.encryptedPathKeyBundles[1],
        ],
      },
    ];
    expect(() =>
      deserializePathUpdateV2FromWire({
        version: 2, generation: 1, numLeaves: 2,
        parentTreeHash: "AA==", treeNodePublicKeys: [], treeHash: "AA==",
        ...wire,
        nodes: blankRootRecipient,
      }),
    ).toThrow(/bundle recipients do not match its copath resolution/);

    const invalidOutbound = validFourLeafPathUpdateV2();
    invalidOutbound.nodes[1].encryptedPathKeyBundles =
      invalidOutbound.nodes[1].encryptedPathKeyBundles.slice(0, 1);
    expect(() => serializePathUpdateV2ForWire(invalidOutbound)).toThrow(
      /bundle recipients do not match its copath resolution/,
    );
  });
});
