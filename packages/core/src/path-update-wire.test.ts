import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import {
  MAX_BEEKEM_TREE_LEAVES,
  PathUpdate,
  PathUpdateV2,
} from './beekem/types.js';
import {
  deserializePathUpdateFromWire,
  deserializePathUpdateV2FromWire,
  serializePathUpdateForWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';
import {
  beekemPathUpdateV1,
  beekemPathUpdateV2,
  beekemWelcomeV1,
  beekemWelcomeV2,
} from './wire-protocols.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };
// Shared handler constants from peerborne.ts. Keep this lightweight wire test
// independent of Peerborne's transport-only runtime dependencies.
const MAX_DOCUMENT_PATH_LENGTH = 4096;
const MAX_SHARED_PROTOCOL_REQUEST_BYTES = 10 * 1024 * 1024;

async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function projectLegacyPathUpdate(update: PathUpdateV2): PathUpdate {
  return {
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: update.senderLeafPublicKey,
    nodes: update.nodes.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    })),
  };
}

async function maximumGeneratedPathUpdateShape(): Promise<PathUpdateV2> {
  const numLeaves = MAX_BEEKEM_TREE_LEAVES;
  const depth = Math.log2(numLeaves);
  if (!Number.isInteger(depth)) {
    throw new Error('BeeKEM leaf cap must be a power of two');
  }
  const keyPair = await generateECDHKeyPair();
  const privateKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
  ).byteLength;
  const publicKey = new Uint8Array(65).fill(1);
  const pathNodeIndices = Array.from(
    { length: depth },
    (_, level) => 2 ** (level + 1) - 1,
  );
  const pathNodeSet = new Set(pathNodeIndices);
  const eciesOverhead = 32 + 65 + 12 + 16;
  const bundleHeaderBytes = 15;
  const bundleEntryHeaderBytes = 8;

  return {
    version: 2,
    generation: 0xffffffff,
    parentTreeHash: new Uint8Array(32).fill(2),
    numLeaves,
    senderLeafIndex: 0,
    senderLeafPublicKey: publicKey,
    nodes: pathNodeIndices.map((nodeIndex, level) => {
      const pathKeysInBundle = depth - level;
      const ciphertext = new Uint8Array(
        eciesOverhead +
          bundleHeaderBytes +
          pathKeysInBundle * (bundleEntryHeaderBytes + privateKeyBytes),
      );
      return {
        nodeIndex,
        publicKey,
        encryptedPrivateKey: new Uint8Array(
          eciesOverhead + privateKeyBytes,
        ),
        encryptedPathKeyBundles: Array.from(
          { length: 2 ** level },
          (_, offset) => ({
            recipientNodeIndex: 2 * (2 ** level + offset),
            ciphertext,
          }),
        ),
      };
    }),
    // Blank non-founder internal nodes maximize the total frame: making one
    // public adds 65 bytes to the snapshot but collapses at least two copath
    // recipients into one, eliminating a much larger encrypted bundle.
    treeNodePublicKeys: Array.from(
      { length: 2 * numLeaves - 1 },
      (_, nodeIndex) => ({
        nodeIndex,
        publicKey:
          (nodeIndex & 1) === 0 || pathNodeSet.has(nodeIndex)
            ? publicKey
            : null,
      }),
    ),
    treeHash: new Uint8Array(32).fill(3),
  };
}

describe('path-update-wire', () => {
  test('v2 protocols are explicit and distinct from frozen v1 IDs', () => {
    expect(beekemPathUpdateV2).toBe(
      '/collabswarm/beekem-pathupdate/2.0.0',
    );
    expect(beekemWelcomeV2).toBe('/collabswarm/beekem-welcome/2.0.0');
    expect(beekemPathUpdateV2).not.toBe(beekemPathUpdateV1);
    expect(beekemWelcomeV2).not.toBe(beekemWelcomeV1);
  });

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

    const wire = serializePathUpdateForWire(
      projectLegacyPathUpdate(pathUpdate),
    );
    expect(Object.keys(wire).sort()).toEqual([
      'nodes',
      'senderLeafIndex',
      'senderLeafPublicKey',
    ]);
    expect(Object.keys(wire.nodes[0]).sort()).toEqual([
      'encryptedPrivateKey',
      'nodeIndex',
      'publicKey',
    ]);
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

  test('v2 round-trip preserves parent-bound recovery fields', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    const { welcome: bobWelcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(bobWelcome, bobKeys.privateKey, bobKeys.publicKey);
    const carolKeys = await generateECDHKeyPair();
    const { pathUpdate: addCarol, welcome: carolWelcome } =
      await alice.addMember(carolKeys.publicKey);
    const carol = new BeeKEM();
    await carol.processWelcome(
      carolWelcome,
      carolKeys.privateKey,
      carolKeys.publicKey,
    );
    await bob.processPathUpdate(addCarol);

    const { pathUpdate, rootSecret } = await alice.removeMember(
      carolWelcome.leafIndex,
    );
    const restored = deserializePathUpdateV2FromWire(
      JSON.parse(JSON.stringify(serializePathUpdateV2ForWire(pathUpdate))),
    );
    expect(restored).toEqual(pathUpdate);
    expect(
      Buffer.from(await bob.processPathUpdate(restored)).equals(
        Buffer.from(rootSecret),
      ),
    ).toBe(true);
    await expect(carol.processPathUpdate(restored)).rejects.toThrow(/removed/);
  });

  test('maximum generated v2 PathUpdate fits the complete 10 MiB framed request', async () => {
    const update = await maximumGeneratedPathUpdateShape();
    const pathUpdate = serializePathUpdateV2ForWire(update);

    expect(() => deserializePathUpdateV2FromWire(pathUpdate)).not.toThrow();

    // This is the exact JSON-safe field shape prepared for the shared v2
    // handler by both shipped codecs. Include the maximum document path twice
    // (routing prefix and signed message), a 32-byte epoch ID, and the default
    // P-384 provider's 96-byte signature.
    const documentId = '\0'.repeat(MAX_DOCUMENT_PATH_LENGTH);
    const body = new TextEncoder().encode(
      JSON.stringify({
        documentId,
        pathUpdate,
        pathUpdateEpochId: Buffer.alloc(32).toString('base64'),
        signature: Buffer.alloc(96).toString('base64'),
      }),
    );
    const framedBytes =
      4 + new TextEncoder().encode(documentId).byteLength + body.byteLength;

    expect(framedBytes).toBeLessThan(MAX_SHARED_PROTOCOL_REQUEST_BYTES);
  });

  test('v1 decoder rejects every v2-only field without changing v1 serialization', () => {
    const base = {
      senderLeafIndex: 0,
      senderLeafPublicKey: 'AA==',
      nodes: [{ nodeIndex: 1, publicKey: 'AA==', encryptedPrivateKey: '' }],
    };
    for (const [field, value] of [
      ['version', 2],
      ['generation', 1],
      ['parentTreeHash', ''],
      ['numLeaves', 2],
      ['treeNodePublicKeys', []],
      ['treeHash', ''],
    ] as const) {
      expect(() =>
        deserializePathUpdateFromWire({ ...base, [field]: value }),
      ).toThrow(/v2-only/);
    }
    expect(() =>
      deserializePathUpdateFromWire({
        ...base,
        nodes: [
          { ...base.nodes[0], encryptedPathKeyBundles: [] },
        ],
      }),
    ).toThrow(/v2-only/);
  });

  test('v2 decoder rejects duplicate recipients and malformed bundle sizes', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);
    const { pathUpdate } = await alice.update();

    const duplicate = serializePathUpdateV2ForWire(pathUpdate);
    duplicate.nodes[0].encryptedPathKeyBundles.push({
      ...duplicate.nodes[0].encryptedPathKeyBundles[0],
    });
    expect(() => deserializePathUpdateV2FromWire(duplicate)).toThrow(
      /duplicate bundle recipient/,
    );

    const empty = serializePathUpdateV2ForWire(pathUpdate);
    empty.nodes[0].encryptedPathKeyBundles[0].ciphertext = '';
    expect(() => deserializePathUpdateV2FromWire(empty)).toThrow(
      /invalid size/,
    );

    const oversized = serializePathUpdateV2ForWire(pathUpdate);
    const template = oversized.nodes[0].encryptedPathKeyBundles[0];
    oversized.nodes[0].encryptedPathKeyBundles = Array.from(
      { length: pathUpdate.numLeaves + 1 },
      (_, recipientNodeIndex) => ({ ...template, recipientNodeIndex }),
    );
    expect(() => deserializePathUpdateV2FromWire(oversized)).toThrow(
      /exceeds numLeaves/,
    );
  });

  test('v2 decoder requires plain objects and exact keys at every level', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);
    const { pathUpdate } = await alice.update();
    const wire = serializePathUpdateV2ForWire(pathUpdate);

    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        numLeaves: MAX_BEEKEM_TREE_LEAVES + 1,
      }),
    ).toThrow(new RegExp(String(MAX_BEEKEM_TREE_LEAVES)));

    expect(() =>
      deserializePathUpdateV2FromWire({ ...wire, unexpected: true }),
    ).toThrow(/unexpected field 'unexpected'/);
    const { parentTreeHash: _parentTreeHash, ...missingParentTreeHash } = wire;
    expect(() =>
      deserializePathUpdateV2FromWire(missingParentTreeHash),
    ).toThrow(/parentTreeHash/);
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        parentTreeHash: Buffer.alloc(31).toString('base64'),
      }),
    ).toThrow(/parentTreeHash must decode to 32 bytes/);
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        nodes: [{ ...wire.nodes[0], unexpected: true }, ...wire.nodes.slice(1)],
      }),
    ).toThrow(/node\[0\].*unexpected field 'unexpected'/);
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        nodes: [
          {
            ...wire.nodes[0],
            encryptedPathKeyBundles: [
              {
                ...wire.nodes[0].encryptedPathKeyBundles[0],
                unexpected: true,
              },
            ],
          },
          ...wire.nodes.slice(1),
        ],
      }),
    ).toThrow(/encryptedPathKeyBundles\[0\].*unexpected field 'unexpected'/);
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        treeNodePublicKeys: [
          { ...wire.treeNodePublicKeys[0], unexpected: true },
          ...wire.treeNodePublicKeys.slice(1),
        ],
      }),
    ).toThrow(/treeNodePublicKeys\[0\].*unexpected field 'unexpected'/);

    const inherited = Object.create({ notPlain: true }) as Record<
      string,
      unknown
    >;
    Object.assign(inherited, wire);
    expect(() => deserializePathUpdateV2FromWire(inherited)).toThrow(
      /expected a plain object/,
    );

    const inheritedNode = Object.assign(
      Object.create({ inherited: true }),
      wire.nodes[0],
    );
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        nodes: [inheritedNode, ...wire.nodes.slice(1)],
      }),
    ).toThrow(/node\[0\].*expected a plain object/);
    const inheritedBundle = Object.assign(
      Object.create({ inherited: true }),
      wire.nodes[0].encryptedPathKeyBundles[0],
    );
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        nodes: [
          {
            ...wire.nodes[0],
            encryptedPathKeyBundles: [inheritedBundle],
          },
          ...wire.nodes.slice(1),
        ],
      }),
    ).toThrow(/encryptedPathKeyBundles\[0\].*expected a plain object/);
    const inheritedSnapshot = Object.assign(
      Object.create({ inherited: true }),
      wire.treeNodePublicKeys[0],
    );
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        treeNodePublicKeys: [
          inheritedSnapshot,
          ...wire.treeNodePublicKeys.slice(1),
        ],
      }),
    ).toThrow(/treeNodePublicKeys\[0\].*expected a plain object/);

    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        senderLeafPublicKey: `${wire.senderLeafPublicKey} `,
      }),
    ).toThrow(/canonical padded base64/);
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        treeHash: `${wire.treeHash}=`,
      }),
    ).toThrow(/canonical padded base64/);
    expect(() =>
      deserializePathUpdateV2FromWire({
        ...wire,
        nodes: [
          {
            ...wire.nodes[0],
            encryptedPathKeyBundles: [
              {
                ...wire.nodes[0].encryptedPathKeyBundles[0],
                ciphertext: '*',
              },
            ],
          },
          ...wire.nodes.slice(1),
        ],
      }),
    ).toThrow(/canonical padded base64/);
  });

  test('v2 snapshots Proxy and accessor inputs without invoking caller code', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);
    const { pathUpdate } = await alice.update();
    const wire = serializePathUpdateV2ForWire(pathUpdate);

    let directGets = 0;
    const proxiedWire = new Proxy(wire, {
      get() {
        directGets++;
        throw new Error('direct property access must not run');
      },
    });
    expect(deserializePathUpdateV2FromWire(proxiedWire)).toEqual(pathUpdate);
    expect(directGets).toBe(0);

    let arrayGets = 0;
    const proxiedNodes = new Proxy(wire.nodes, {
      get() {
        arrayGets++;
        throw new Error('array property access must not run');
      },
    });
    expect(
      deserializePathUpdateV2FromWire({ ...wire, nodes: proxiedNodes }),
    ).toEqual(pathUpdate);
    expect(arrayGets).toBe(0);

    let accessorCalls = 0;
    const accessorWire = { ...wire } as Record<string, unknown>;
    Object.defineProperty(accessorWire, 'generation', {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls++;
        return wire.generation;
      },
    });
    expect(() => deserializePathUpdateV2FromWire(accessorWire)).toThrow(
      /own enumerable data property/,
    );
    expect(accessorCalls).toBe(0);

    const accessorNodes = [...wire.nodes];
    Object.defineProperty(accessorNodes, '0', {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls++;
        return wire.nodes[0];
      },
    });
    expect(() =>
      deserializePathUpdateV2FromWire({ ...wire, nodes: accessorNodes }),
    ).toThrow(/own enumerable data property/);
    expect(accessorCalls).toBe(0);

    let iteratorCalls = 0;
    const iteratorNodes = [...wire.nodes];
    Object.defineProperty(iteratorNodes, Symbol.iterator, {
      configurable: true,
      value() {
        iteratorCalls++;
        throw new Error('iterator must not run');
      },
    });
    expect(() =>
      deserializePathUpdateV2FromWire({ ...wire, nodes: iteratorNodes }),
    ).toThrow(/dense array without extra properties/);
    expect(iteratorCalls).toBe(0);

    let ownKeysCalls = 0;
    const oversizedNodes = new Proxy(
      new Array(MAX_BEEKEM_TREE_LEAVES),
      {
        ownKeys() {
          ownKeysCalls++;
          throw new Error('ownKeys must not run after an oversized length');
        },
      },
    );
    expect(() =>
      deserializePathUpdateV2FromWire({ ...wire, nodes: oversizedNodes }),
    ).toThrow(/nodes exceeds 64 entries/);
    expect(ownKeysCalls).toBe(0);
  });

  test('v2 enforces aggregate decoded-byte and structural-work budgets', () => {
    const publicKey = Buffer.alloc(65, 1).toString('base64');
    const treeHash = Buffer.alloc(32, 2).toString('base64');
    const parentTreeHash = Buffer.alloc(32, 4).toString('base64');
    const largeCiphertext = Buffer.alloc(256 * 1024, 3).toString('base64');
    const numLeaves = 65;
    const treeWidth = 2 * numLeaves - 1;
    const byteHeavy = {
      version: 2,
      generation: 1,
      parentTreeHash,
      numLeaves,
      senderLeafIndex: 0,
      senderLeafPublicKey: publicKey,
      nodes: Array.from({ length: 33 }, (_, offset) => ({
        nodeIndex: 2 * offset + 1,
        publicKey,
        encryptedPrivateKey: largeCiphertext,
        encryptedPathKeyBundles: [],
      })),
      treeNodePublicKeys: Array.from({ length: treeWidth }, (_, nodeIndex) => ({
        nodeIndex,
        publicKey: null,
      })),
      treeHash,
    };
    expect(() => deserializePathUpdateV2FromWire(byteHeavy)).toThrow(
      /aggregate decoded-byte budget/,
    );

    const maxLeaves = MAX_BEEKEM_TREE_LEAVES;
    const maxTreeWidth = 2 * maxLeaves - 1;
    const firstBundles = Array.from({ length: maxLeaves }, (_, index) => ({
      recipientNodeIndex: index,
      ciphertext: 'AA==',
    }));
    const workHeavy = {
      version: 2,
      generation: 1,
      parentTreeHash,
      numLeaves: maxLeaves,
      senderLeafIndex: 0,
      senderLeafPublicKey: publicKey,
      nodes: [
        {
          nodeIndex: 1,
          publicKey,
          encryptedPrivateKey: '',
          encryptedPathKeyBundles: firstBundles,
        },
        {
          nodeIndex: 3,
          publicKey,
          encryptedPrivateKey: '',
          encryptedPathKeyBundles: new Array(maxLeaves).fill(firstBundles[0]),
        },
      ],
      treeNodePublicKeys: Array.from(
        { length: maxTreeWidth },
        (_, nodeIndex) => ({ nodeIndex, publicKey: null }),
      ),
      treeHash,
    };
    expect(() => deserializePathUpdateV2FromWire(workHeavy)).toThrow(
      /aggregate work budget/,
    );
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
    const wire = serializePathUpdateV2ForWire(pathUpdate);
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializePathUpdateV2FromWire(reparsed);

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
