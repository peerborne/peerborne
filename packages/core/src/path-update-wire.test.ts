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

function validPathUpdateV1() {
  return {
    senderLeafIndex: 0,
    senderLeafPublicKey: new Uint8Array(65).fill(1),
    nodes: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array(65).fill(2),
        encryptedPrivateKey: new Uint8Array(125).fill(3),
      },
    ],
  };
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
    ).toThrow(/nodes must be an array/);
    expect(() =>
      deserializePathUpdateFromWire({
        senderLeafIndex: 0,
        senderLeafPublicKey: 'AA==',
        nodes: [{ nodeIndex: 'not-int', publicKey: '', encryptedPrivateKey: '' }],
      }),
    ).toThrow(/node\[0\].nodeIndex/);
  });

  test('rejects oversized node arrays before reading their entries', () => {
    let nodeReads = 0;
    const oversizedNodes = new Array(14);
    Object.defineProperty(oversizedNodes, '0', {
      enumerable: true,
      get() {
        nodeReads++;
        throw new Error('must not read an oversized node array');
      },
    });
    const wire = serializePathUpdateForWire(validPathUpdateV1());

    expect(() =>
      deserializePathUpdateFromWire({ ...wire, nodes: oversizedNodes }),
    ).toThrow(/nodes exceeds 13 entries/);
    expect(nodeReads).toBe(0);
  });

  test.each([
    ['unsafe sender leaf', { senderLeafIndex: Number.MAX_SAFE_INTEGER + 1 }],
    ['odd sender leaf', { senderLeafIndex: 1 }],
    ['out-of-range sender leaf', { senderLeafIndex: 16_384 }],
  ])('rejects an invalid %s index', (_label, patch) => {
    const wire = serializePathUpdateForWire(validPathUpdateV1());
    expect(() =>
      deserializePathUpdateFromWire({ ...wire, ...patch }),
    ).toThrow(/senderLeafIndex.*supported leaf/);
  });

  test.each([
    ['unsafe', Number.MAX_SAFE_INTEGER + 1],
    ['leaf', 2],
    ['out-of-range', 16_383],
  ])('rejects an %s path-node index', (_label, nodeIndex) => {
    const wire = serializePathUpdateForWire(validPathUpdateV1());
    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        nodes: [{ ...wire.nodes[0], nodeIndex }],
      }),
    ).toThrow(/node\[0\].nodeIndex.*supported internal node/);
  });

  test('rejects duplicate path-node indices', () => {
    const wire = serializePathUpdateForWire(validPathUpdateV1());
    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        nodes: [wire.nodes[0], { ...wire.nodes[0] }],
      }),
    ).toThrow(/unique supported internal node/);
  });

  test('bounds every decoded key and ciphertext field', () => {
    const wire = serializePathUpdateForWire(validPathUpdateV1());
    const shortKey = Buffer.from(new Uint8Array(64)).toString('base64');
    const oversizedCiphertext = Buffer.from(
      new Uint8Array(4097),
    ).toString('base64');

    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        senderLeafPublicKey: shortKey,
      }),
    ).toThrow(/senderLeafPublicKey.*65 bytes/);
    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        nodes: [{ ...wire.nodes[0], publicKey: shortKey }],
      }),
    ).toThrow(/node\[0\].publicKey.*65 bytes/);
    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        nodes: [
          {
            ...wire.nodes[0],
            encryptedPrivateKey: oversizedCiphertext,
          },
        ],
      }),
    ).toThrow(/encryptedPrivateKey.*0 to 4096 bytes/);
  });

  test.each([1, 124])(
    'rejects a nonempty %i-byte ciphertext below the ECIES framing minimum',
    (length) => {
      const wire = serializePathUpdateForWire(validPathUpdateV1());
      expect(() =>
        deserializePathUpdateFromWire({
          ...wire,
          nodes: [
            {
              ...wire.nodes[0],
              encryptedPrivateKey: Buffer.from(
                new Uint8Array(length),
              ).toString('base64'),
            },
          ],
        }),
      ).toThrow(/encryptedPrivateKey.*empty or 125\.\.4096 bytes/);
    },
  );

  test.each([0, 125, 4096])(
    'accepts the %i-byte ciphertext boundary',
    (length) => {
      const wire = serializePathUpdateForWire(validPathUpdateV1());
      expect(
        deserializePathUpdateFromWire({
          ...wire,
          nodes: [
            {
              ...wire.nodes[0],
              encryptedPrivateKey: Buffer.from(
                new Uint8Array(length),
              ).toString('base64'),
            },
          ],
        }).nodes[0].encryptedPrivateKey,
      ).toHaveLength(length);
    },
  );

  test('requires exact objects and canonical padded base64', () => {
    const wire = serializePathUpdateForWire(validPathUpdateV1());
    expect(() =>
      deserializePathUpdateFromWire({ ...wire, version: undefined }),
    ).toThrow(/unexpected field 'version'/);
    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        senderLeafPublicKey: wire.senderLeafPublicKey.replace(/=+$/, ''),
      }),
    ).toThrow(/canonical padded base64/);
    expect(() =>
      deserializePathUpdateFromWire({
        ...wire,
        nodes: [{ ...wire.nodes[0], unexpected: true }],
      }),
    ).toThrow(/unexpected field 'unexpected'/);
  });
});

describe('path-update-wire V1 outbound boundary', () => {
  test('validates and detaches every runtime byte field', () => {
    const update = validPathUpdateV1();
    const wire = serializePathUpdateForWire(update);
    update.senderLeafPublicKey.fill(9);
    update.nodes[0].publicKey.fill(9);
    update.nodes[0].encryptedPrivateKey.fill(9);

    const restored = deserializePathUpdateFromWire(wire);
    expect(restored.senderLeafPublicKey).toEqual(new Uint8Array(65).fill(1));
    expect(restored.nodes[0].publicKey).toEqual(new Uint8Array(65).fill(2));
    expect(restored.nodes[0].encryptedPrivateKey).toEqual(
      new Uint8Array(125).fill(3),
    );
  });

  test('bounds the largest accepted payload well below the shared request limit', () => {
    const update = {
      senderLeafIndex: 0,
      senderLeafPublicKey: new Uint8Array(65).fill(1),
      nodes: Array.from({ length: 13 }, (_, offset) => ({
        nodeIndex: 2 * offset + 1,
        publicKey: new Uint8Array(65).fill(2),
        encryptedPrivateKey: new Uint8Array(4096).fill(3),
      })),
    };
    const wire = serializePathUpdateForWire(update);
    expect(JSON.stringify(wire).length).toBeLessThan(
      MAX_SHARED_PROTOCOL_REQUEST_BYTES / 64,
    );
    expect(deserializePathUpdateFromWire(wire).nodes).toHaveLength(13);
    expect(() =>
      serializePathUpdateForWire({
        ...update,
        nodes: [
          ...update.nodes,
          {
            nodeIndex: 27,
            publicKey: new Uint8Array(65),
            encryptedPrivateKey: new Uint8Array(0),
          },
        ],
      }),
    ).toThrow(/nodes exceeds 13 entries/);
  });

  test('rejects malformed runtime byte fields instead of normalizing them', () => {
    expect(() =>
      serializePathUpdateForWire({
        ...validPathUpdateV1(),
        senderLeafPublicKey: new Uint8Array(64),
      }),
    ).toThrow(/senderLeafPublicKey.*65/);
    expect(() =>
      serializePathUpdateForWire({
        ...validPathUpdateV1(),
        nodes: [
          {
            ...validPathUpdateV1().nodes[0],
            encryptedPrivateKey: new Uint8Array(124),
          },
        ],
      }),
    ).toThrow(/encryptedPrivateKey.*empty or 125\.\.4096/);
    expect(() =>
      serializePathUpdateForWire({
        ...validPathUpdateV1(),
        senderLeafPublicKey: {
          byteLength: 65,
          buffer: new ArrayBuffer(65),
        } as unknown as Uint8Array,
      }),
    ).toThrow(/senderLeafPublicKey.*Uint8Array/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        serializePathUpdateForWire({
          ...validPathUpdateV1(),
          senderLeafPublicKey: new Uint8Array(new SharedArrayBuffer(65)),
        }),
      ).toThrow(/senderLeafPublicKey.*unshared/);
    }
  });

  test('rejects oversized arrays before consulting their entries', () => {
    let nodeReads = 0;
    const nodes = new Array(14);
    Object.defineProperty(nodes, '0', {
      enumerable: true,
      get() {
        nodeReads++;
        throw new Error('must not read an oversized node array');
      },
    });

    expect(() =>
      serializePathUpdateForWire({
        ...validPathUpdateV1(),
        nodes,
      }),
    ).toThrow(/nodes exceeds 13 entries/);
    expect(nodeReads).toBe(0);
  });

  test('requires exact own enumerable data properties', () => {
    expect(() =>
      serializePathUpdateForWire({
        ...validPathUpdateV1(),
        unexpected: undefined,
      } as unknown as ReturnType<typeof validPathUpdateV1>),
    ).toThrow(/unexpected field 'unexpected'/);

    const update = validPathUpdateV1();
    Object.defineProperty(update.nodes[0], 'publicKey', {
      enumerable: true,
      get() {
        return new Uint8Array(65);
      },
    });
    expect(() => serializePathUpdateForWire(update)).toThrow(
      /node\[0\].*enumerable data properties/,
    );
  });
});

describe('path-update-wire V2 outbound boundary', () => {
  test.each([new Uint8Array(), new Uint8Array([1])])(
    'rejects the obsolete per-node ciphertext field even when populated',
    (obsoleteCiphertext) => {
      const update = validPathUpdateV2();
      const wire = serializePathUpdateV2ForWire(update);
      Object.assign(update.nodes[0], { encryptedPrivateKey: obsoleteCiphertext });
      Object.assign(wire.nodes[0], { encryptedPrivateKey: '' });
      expect(() => serializePathUpdateV2ForWire(update)).toThrow(/field|propert/i);
      expect(() => deserializePathUpdateV2FromWire(wire)).toThrow(/field|propert/i);
    },
  );

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
