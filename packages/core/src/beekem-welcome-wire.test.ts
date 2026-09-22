import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import * as TreeMath from './beekem/tree-math.js';
import {
  deserializeBeeKEMWelcomeFromWire,
  serializeBeeKEMWelcomeForWire,
  serializeBeeKEMWelcomeV2ForWire,
  deserializeBeeKEMWelcomeV2FromWire,
  snapshotBeeKEMWelcomeForProcessing,
} from './beekem-welcome-wire.js';
import { MAX_BEEKEM_TREE_LEAVES } from './beekem/types.js';
import {
  decodeWelcomeSealedPayload,
  encodeWelcomeSealedPayload,
} from './welcome-sealed-payload.js';

/**
 * Wire round-trip coverage for the BeeKEM Welcome wire shape and the
 * sealed-payload envelope. These tests cover the Path A wire change
 * introduced for #189 §5.4.5: the inviter ships the BeeKEM
 * `Welcome` inside the structured plaintext of `eciesSealed` alongside
 * the keychain delta, so the joiner can both decrypt and bootstrap
 * their local BeeKEM ratchet state.
 */

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

describe('beekem-welcome-wire', () => {
  test.each([1, 2])(
    'V%i captures runtime bytes before inspecting later descriptors',
    async (version) => {
      const alice = new BeeKEM();
      const aliceKeys = await generateECDHKeyPair();
      await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
      const bobKeys = await generateECDHKeyPair();
      const { welcome } = await alice.addMember(bobKeys.publicKey);
      const encode = () =>
        version === 1
          ? serializeBeeKEMWelcomeForWire(welcome)
          : serializeBeeKEMWelcomeV2ForWire({
              ...welcome,
              version: 2,
              generation: 1,
              numLeaves: 2,
            });
      const expected = encode();
      const pathNode = welcome.pathKeys[0];
      welcome.pathKeys[0] = new Proxy(pathNode, {
        getOwnPropertyDescriptor(target, key) {
          if (key === 'encryptedPrivateKey') pathNode.publicKey.fill(7);
          return Reflect.getOwnPropertyDescriptor(target, key);
        },
      });
      welcome.treeNodePublicKeys[0] = new Proxy(welcome.treeNodePublicKeys[0], {
        getOwnPropertyDescriptor(target, key) {
          pathNode.encryptedPrivateKey.fill(8);
          welcome.treeHash.fill(9);
          return Reflect.getOwnPropertyDescriptor(target, key);
        },
      });
      expect(encode()).toEqual(expected);
    },
  );

  test('materializes omitted blank slots in a three-leaf V2 Welcome', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    const bob = await alice.addMember(bobKeys.publicKey);
    await alice.removeMember(bob.welcome.leafIndex);
    alice.compact();
    const carolKeys = await generateECDHKeyPair();
    const { welcome, rootSecret } = await alice.addMember(carolKeys.publicKey);
    const sparseNodes = welcome.treeNodePublicKeys.filter(
      (node) => node.publicKey !== null,
    );
    expect(sparseNodes.length).toBeLessThan(welcome.treeNodePublicKeys.length);
    const wire = serializeBeeKEMWelcomeV2ForWire({
      ...welcome,
      version: 2,
      generation: 3,
      numLeaves: 3,
      treeNodePublicKeys: sparseNodes,
    });
    const decoded = deserializeBeeKEMWelcomeV2FromWire(wire);
    expect(decoded.treeNodePublicKeys).toContainEqual({
      nodeIndex: bob.welcome.leafIndex,
      publicKey: null,
    });
    const { version, generation, numLeaves, ...legacyWelcome } = decoded;
    const carol = new BeeKEM();
    await expect(
      carol.processWelcome(
        legacyWelcome,
        carolKeys.privateKey,
        carolKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        treeNodePublicKeys: wire.treeNodePublicKeys.filter(
          (node) => node.nodeIndex !== bob.welcome.leafIndex,
        ),
      }),
    ).toThrow(/complete tree/);
  });

  test('round-trips a real BeeKEMWelcome produced by BeeKEM.addMember', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);

    const wire = serializeBeeKEMWelcomeForWire(welcome);
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializeBeeKEMWelcomeFromWire(reparsed);

    expect(restored.leafIndex).toBe(welcome.leafIndex);
    expect(restored.pathKeys.length).toBe(welcome.pathKeys.length);
    for (let i = 0; i < welcome.pathKeys.length; i++) {
      expect(restored.pathKeys[i].nodeIndex).toBe(
        welcome.pathKeys[i].nodeIndex,
      );
      expect(restored.pathKeys[i].publicKey).toEqual(
        welcome.pathKeys[i].publicKey,
      );
      expect(restored.pathKeys[i].encryptedPrivateKey).toEqual(
        welcome.pathKeys[i].encryptedPrivateKey,
      );
    }
    expect(restored.treeNodePublicKeys.length).toBe(
      welcome.treeNodePublicKeys.length,
    );
    for (let i = 0; i < welcome.treeNodePublicKeys.length; i++) {
      expect(restored.treeNodePublicKeys[i].nodeIndex).toBe(
        welcome.treeNodePublicKeys[i].nodeIndex,
      );
      expect(restored.treeNodePublicKeys[i].publicKey).toEqual(
        welcome.treeNodePublicKeys[i].publicKey,
      );
    }
    expect(restored.treeHash).toEqual(welcome.treeHash);
  });

  test('round-tripped Welcome is still applicable via processWelcome', async () => {
    // Confirms the wire bytes don't only structurally round-trip --
    // they also remain semantically valid: a fresh BeeKEM can be
    // bootstrapped from the restored Welcome and converges on the
    // same root secret as the inviter.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome, rootSecret: aliceRoot } = await alice.addMember(
      bobKeys.publicKey,
    );

    const wire = serializeBeeKEMWelcomeForWire(welcome);
    const restored = deserializeBeeKEMWelcomeFromWire(
      JSON.parse(JSON.stringify(wire)),
    );

    const bob = new BeeKEM();
    const bobRoot = await bob.processWelcome(
      restored,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    expect(Buffer.from(bobRoot).equals(Buffer.from(aliceRoot))).toBe(true);
  });

  test('rejects malformed wire inputs with descriptive errors', () => {
    expect(() => deserializeBeeKEMWelcomeFromWire(null)).toThrow(
      /plain object/,
    );
    expect(() => deserializeBeeKEMWelcomeFromWire([])).toThrow(/plain object/);
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: -1,
        pathKeys: [],
        treeNodePublicKeys: [],
        treeHash: '',
      }),
    ).toThrow(/leafIndex.*non-negative/);
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 2,
        pathKeys: 'oops',
        treeNodePublicKeys: [],
        treeHash: '',
      }),
    ).toThrow(/pathKeys.*array/);
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 2,
        pathKeys: [],
        treeNodePublicKeys: [],
        treeHash: 42,
      }),
    ).toThrow(/treeHash/);
    const malformedPath = serializeBeeKEMWelcomeForWire({
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125).fill(1),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    });
    malformedPath.pathKeys[0].nodeIndex = -1;
    expect(() => deserializeBeeKEMWelcomeFromWire(malformedPath)).toThrow(
      /pathKeys\[0\]\.nodeIndex.*non-negative/,
    );
  });

  test('rejects negative zero in every legacy tree index', () => {
    const makeWelcome = () => ({
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125).fill(1),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    });

    const runtimeLeaf = makeWelcome();
    runtimeLeaf.leafIndex = -0;
    expect(() => serializeBeeKEMWelcomeForWire(runtimeLeaf)).toThrow(
      /leafIndex.*non-negative safe integer/,
    );

    const runtimePath = makeWelcome();
    runtimePath.pathKeys[0].nodeIndex = -0;
    expect(() => serializeBeeKEMWelcomeForWire(runtimePath)).toThrow(
      /pathKeys\[0\]\.nodeIndex.*non-negative safe integer/,
    );

    const runtimeTree = makeWelcome();
    runtimeTree.treeNodePublicKeys[0].nodeIndex = -0;
    expect(() => serializeBeeKEMWelcomeForWire(runtimeTree)).toThrow(
      /treeNodePublicKeys\[0\]\.nodeIndex.*non-negative safe integer/,
    );

    const wireLeaf = serializeBeeKEMWelcomeForWire(makeWelcome());
    wireLeaf.leafIndex = -0;
    expect(() => deserializeBeeKEMWelcomeFromWire(wireLeaf)).toThrow(
      /leafIndex.*non-negative safe integer/,
    );

    const wirePath = serializeBeeKEMWelcomeForWire(makeWelcome());
    wirePath.pathKeys[0].nodeIndex = -0;
    expect(() => deserializeBeeKEMWelcomeFromWire(wirePath)).toThrow(
      /pathKeys\[0\]\.nodeIndex.*non-negative safe integer/,
    );

    const wireTree = serializeBeeKEMWelcomeForWire(makeWelcome());
    wireTree.treeNodePublicKeys[0].nodeIndex = -0;
    expect(() => deserializeBeeKEMWelcomeFromWire(wireTree)).toThrow(
      /treeNodePublicKeys\[0\]\.nodeIndex.*non-negative safe integer/,
    );
  });

  test('round-trips and applies real trees across non-power-of-two growth', async () => {
    let inviter = new BeeKEM();
    const inviterKeys = await generateECDHKeyPair();
    await inviter.initialize(inviterKeys.privateKey, inviterKeys.publicKey);

    for (let leafCount = 2; leafCount <= 12; leafCount++) {
      const memberKeys = await generateECDHKeyPair();
      const { welcome, rootSecret } = await inviter.addMember(
        memberKeys.publicKey,
      );
      const restored = deserializeBeeKEMWelcomeFromWire(
        JSON.parse(JSON.stringify(serializeBeeKEMWelcomeForWire(welcome))),
      );
      const joined = new BeeKEM();
      const joinedRoot = await joined.processWelcome(
        restored,
        memberKeys.privateKey,
        memberKeys.publicKey,
      );

      expect(joined.memberCount).toBe(leafCount);
      expect(Buffer.from(joinedRoot).equals(Buffer.from(rootSecret))).toBe(
        true,
      );
      inviter = joined;
    }
  });

  test('accepts the fixed legacy topology for a six-leaf tree', () => {
    const pathKeys = [9, 7].map((nodeIndex) => ({
      nodeIndex,
      publicKey: new Uint8Array(65).fill(nodeIndex),
      encryptedPrivateKey: new Uint8Array(125).fill(nodeIndex),
    }));
    const treeNodePublicKeys = [0, 1, 2, 3, 4, 5, 6, 8].map((nodeIndex) => ({
      nodeIndex,
      publicKey:
        nodeIndex === 3 ? null : new Uint8Array(65).fill(nodeIndex + 1),
    }));

    const restored = deserializeBeeKEMWelcomeFromWire(
      serializeBeeKEMWelcomeForWire({
        leafIndex: 10,
        pathKeys,
        treeNodePublicKeys,
        treeHash: new Uint8Array(32).fill(42),
      }),
    );

    expect(restored.leafIndex).toBe(10);
    expect(restored.pathKeys.map((node) => node.nodeIndex)).toEqual([9, 7]);
    expect(restored.treeNodePublicKeys.map((node) => node.nodeIndex)).toEqual([
      0, 1, 2, 3, 4, 5, 6, 8,
    ]);
  });

  test('keeps runtime and wire legacy topology validation in lockstep', () => {
    const makeWelcome = () => ({
      leafIndex: 10,
      pathKeys: [9, 7].map((nodeIndex) => ({
        nodeIndex,
        publicKey: new Uint8Array(65).fill(nodeIndex),
        encryptedPrivateKey: new Uint8Array(125).fill(nodeIndex),
      })),
      treeNodePublicKeys: [0, 1, 2, 3, 4, 5, 6, 8].map((nodeIndex) => ({
        nodeIndex,
        publicKey:
          nodeIndex === 3 ? null : new Uint8Array(65).fill(nodeIndex + 1),
      })),
      treeHash: new Uint8Array(32).fill(42),
    });
    type StructuralWelcome = {
      pathKeys: Array<{ nodeIndex: number }>;
      treeNodePublicKeys: Array<{ nodeIndex: number }>;
    };
    const malformed: Array<{
      mutate: (welcome: StructuralWelcome) => void;
      error: RegExp;
    }> = [
      {
        mutate: (welcome) => welcome.pathKeys.pop(),
        error: /complete direct path/,
      },
      {
        mutate: (welcome) => welcome.pathKeys.reverse(),
        error: /out-of-order/,
      },
      {
        mutate: (welcome) => {
          welcome.pathKeys[1].nodeIndex = welcome.pathKeys[0].nodeIndex;
        },
        error: /duplicate|out-of-order/,
      },
      {
        mutate: (welcome) => {
          welcome.treeNodePublicKeys.push({
            nodeIndex: welcome.treeNodePublicKeys[0].nodeIndex,
          });
        },
        error: /tree width/,
      },
      {
        mutate: (welcome) => {
          welcome.treeNodePublicKeys[0].nodeIndex = 11;
        },
        error: /out-of-range/,
      },
    ];

    const source = makeWelcome();
    const runtime = snapshotBeeKEMWelcomeForProcessing(source);
    const wire = serializeBeeKEMWelcomeForWire(source);
    const decoded = deserializeBeeKEMWelcomeFromWire(wire);
    expect(runtime.numLeaves).toBe(6);
    expect(runtime.welcome).toEqual(decoded);
    expect(runtime.welcome.pathKeys[0].publicKey).not.toBe(
      source.pathKeys[0].publicKey,
    );

    for (const { mutate, error } of malformed) {
      const processingInput = makeWelcome();
      mutate(processingInput);
      expect(() => snapshotBeeKEMWelcomeForProcessing(processingInput)).toThrow(
        error,
      );

      const serializationInput = makeWelcome();
      mutate(serializationInput);
      expect(() => serializeBeeKEMWelcomeForWire(serializationInput)).toThrow(
        error,
      );

      const wireInput = serializeBeeKEMWelcomeForWire(makeWelcome());
      mutate(wireInput);
      expect(() => deserializeBeeKEMWelcomeFromWire(wireInput)).toThrow(error);
    }

    expect(() => snapshotBeeKEMWelcomeForProcessing(wire)).toThrow(
      /unshared Uint8Array/,
    );
    expect(() => deserializeBeeKEMWelcomeFromWire(source)).toThrow(
      /base64 string/,
    );
  });

  test('rejects incomplete, reordered, duplicate, and out-of-range topology', () => {
    const welcome = {
      leafIndex: 10,
      pathKeys: [9, 7].map((nodeIndex) => ({
        nodeIndex,
        publicKey: new Uint8Array(65).fill(nodeIndex),
        encryptedPrivateKey: new Uint8Array(125).fill(nodeIndex),
      })),
      treeNodePublicKeys: [0, 1, 2, 3, 4, 5, 6, 8].map((nodeIndex) => ({
        nodeIndex,
        publicKey: new Uint8Array(65).fill(nodeIndex + 1),
      })),
      treeHash: new Uint8Array(32),
    };
    const wire = serializeBeeKEMWelcomeForWire(welcome);

    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        ...wire,
        pathKeys: wire.pathKeys.slice(0, 1),
      }),
    ).toThrow(/complete direct path/);
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        ...wire,
        pathKeys: [...wire.pathKeys].reverse(),
      }),
    ).toThrow(/out-of-order/);
    expect(() =>
      serializeBeeKEMWelcomeForWire({
        ...welcome,
        treeNodePublicKeys: [
          welcome.treeNodePublicKeys[1],
          ...welcome.treeNodePublicKeys.slice(1),
        ],
      }),
    ).toThrow(/duplicate/);

    const outOfRange = JSON.parse(JSON.stringify(wire));
    outOfRange.treeNodePublicKeys[0].nodeIndex = 11;
    expect(() => deserializeBeeKEMWelcomeFromWire(outOfRange)).toThrow(
      /out-of-range/,
    );
  });

  test('round-trips and applies a real Welcome containing blanked nodes', async () => {
    let inviter = new BeeKEM();
    const inviterKeys = await generateECDHKeyPair();
    await inviter.initialize(inviterKeys.privateKey, inviterKeys.publicKey);

    for (let leafCount = 2; leafCount <= 5; leafCount++) {
      const memberKeys = await generateECDHKeyPair();
      const { welcome } = await inviter.addMember(memberKeys.publicKey);
      const joined = new BeeKEM();
      await joined.processWelcome(
        welcome,
        memberKeys.privateKey,
        memberKeys.publicKey,
      );
      inviter = joined;
    }

    await inviter.removeMember(0);
    inviter.compact();

    const memberKeys = await generateECDHKeyPair();
    const { welcome, rootSecret } = await inviter.addMember(
      memberKeys.publicKey,
    );
    const wire = serializeBeeKEMWelcomeForWire(welcome);
    expect(
      wire.treeNodePublicKeys.some((node) => node.publicKey === null),
    ).toBe(true);

    const restored = deserializeBeeKEMWelcomeFromWire(
      JSON.parse(JSON.stringify(wire)),
    );
    const withoutExplicitBlanks = deserializeBeeKEMWelcomeFromWire({
      ...JSON.parse(JSON.stringify(wire)),
      treeNodePublicKeys: wire.treeNodePublicKeys.filter(
        (node) => node.publicKey !== null,
      ),
    });
    const joined = new BeeKEM();
    const joinedFromSparseWire = new BeeKEM();
    const joinedRoot = await joined.processWelcome(
      restored,
      memberKeys.privateKey,
      memberKeys.publicKey,
    );
    const sparseRoot = await joinedFromSparseWire.processWelcome(
      withoutExplicitBlanks,
      memberKeys.privateKey,
      memberKeys.publicKey,
    );
    expect(Buffer.from(joinedRoot).equals(Buffer.from(rootSecret))).toBe(true);
    expect(Buffer.from(sparseRoot).equals(Buffer.from(joinedRoot))).toBe(true);
  });

  test('rejects over-capacity arrays before reading their elements', () => {
    let getterCalls = 0;
    const pathKeys = new Array(14);
    Object.defineProperty(pathKeys, '0', {
      enumerable: true,
      get() {
        getterCalls++;
        return null;
      },
    });

    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 2,
        pathKeys,
        treeNodePublicKeys: [],
        treeHash: '',
      }),
    ).toThrow(/pathKeys has invalid length/);
    expect(getterCalls).toBe(0);

    expect(() =>
      serializeBeeKEMWelcomeForWire({
        leafIndex: 2,
        pathKeys: pathKeys as never[],
        treeNodePublicKeys: [],
        treeHash: new Uint8Array(32),
      }),
    ).toThrow(/pathKeys has invalid length/);
    expect(getterCalls).toBe(0);
  });

  test('rejects a tree array beyond the global BeeKEM bound', () => {
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 2,
        pathKeys: [null],
        treeNodePublicKeys: new Array(2 * MAX_BEEKEM_TREE_LEAVES - 2),
        treeHash: '',
      }),
    ).toThrow(/supported tree width/);

    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 2 * MAX_BEEKEM_TREE_LEAVES,
        pathKeys: [],
        treeNodePublicKeys: [],
        treeHash: '',
      }),
    ).toThrow(/8192-leaf tree bound/);
  });

  test('rejects oversized encrypted path material before base64 decoding', () => {
    const oversizedCiphertext = Buffer.alloc(300_000).toString('base64');
    const wire = serializeBeeKEMWelcomeForWire({
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125).fill(1),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    });
    wire.pathKeys[0].encryptedPrivateKey = oversizedCiphertext;

    expect(() => deserializeBeeKEMWelcomeFromWire(wire)).toThrow(
      /encryptedPrivateKey exceeds the encoded size limit/,
    );
  });

  test('rejects non-canonical base64 and invalid fixed-width fields', () => {
    const createWire = () =>
      serializeBeeKEMWelcomeForWire({
        leafIndex: 2,
        pathKeys: [
          {
            nodeIndex: 1,
            publicKey: new Uint8Array(65),
            encryptedPrivateKey: new Uint8Array(125).fill(1),
          },
        ],
        treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
        treeHash: new Uint8Array(32),
      });

    const unpadded = createWire();
    unpadded.pathKeys[0].publicKey = unpadded.pathKeys[0].publicKey.replace(
      /=+$/,
      '',
    );
    expect(() => deserializeBeeKEMWelcomeFromWire(unpadded)).toThrow(
      /publicKey' must use canonical padded base64/,
    );

    const shortPublicKey = createWire();
    shortPublicKey.pathKeys[0].publicKey = Buffer.alloc(64).toString('base64');
    expect(() => deserializeBeeKEMWelcomeFromWire(shortPublicKey)).toThrow(
      /publicKey' must decode to 65 bytes/,
    );

    const shortTreeHash = createWire();
    shortTreeHash.treeHash = Buffer.alloc(31).toString('base64');
    expect(() => deserializeBeeKEMWelcomeFromWire(shortTreeHash)).toThrow(
      /treeHash' must decode to 32 bytes/,
    );
  });

  test('rejects oversized ciphertext before traversing the supplied topology', () => {
    const numLeaves = MAX_BEEKEM_TREE_LEAVES;
    const treeWidth = 2 * numLeaves - 1;
    const leafIndex = TreeMath.leafToNodeIndex(numLeaves - 1);
    const directPath = TreeMath.directPath(leafIndex, numLeaves);
    const excluded = new Set([leafIndex, ...directPath]);
    const publicKey = Buffer.alloc(65).toString('base64');
    const maximumCiphertext = Buffer.alloc(64 * (4096 + 8) + 4096).toString(
      'base64',
    );

    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex,
        pathKeys: directPath.map((nodeIndex) => ({
          nodeIndex,
          publicKey,
          encryptedPrivateKey: maximumCiphertext,
        })),
        treeNodePublicKeys: Array.from({ length: treeWidth }, (_, nodeIndex) =>
          excluded.has(nodeIndex) ? null : { nodeIndex, publicKey },
        ).filter((node) => node !== null),
        treeHash: Buffer.alloc(32).toString('base64'),
      }),
    ).toThrow(/encryptedPrivateKey exceeds the encoded size limit/);
  });

  test('enforces legacy ciphertext bounds on inbound and outbound data', () => {
    const welcome = {
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    };
    const wire = serializeBeeKEMWelcomeForWire(welcome);
    wire.pathKeys[0].encryptedPrivateKey = Buffer.alloc(124).toString('base64');
    expect(() => deserializeBeeKEMWelcomeFromWire(wire)).toThrow(
      /encryptedPrivateKey' must decode to 125 to 4096 bytes/,
    );
    expect(() =>
      serializeBeeKEMWelcomeForWire({
        ...welcome,
        pathKeys: [
          { ...welcome.pathKeys[0], encryptedPrivateKey: new Uint8Array(124) },
        ],
      }),
    ).toThrow(/encryptedPrivateKey.*125 to 4096 bytes/);
  });

  test('rejects sparse arrays, extra fields, and accessors without invoking them', () => {
    const sparse = serializeBeeKEMWelcomeForWire({
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125).fill(1),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    });
    sparse.pathKeys = new Array(1);
    expect(() => deserializeBeeKEMWelcomeFromWire(sparse)).toThrow(
      /dense array/,
    );

    const extra = { ...sparse, pathKeys: [], unexpected: true };
    expect(() => deserializeBeeKEMWelcomeFromWire(extra)).toThrow(
      /unexpected field/,
    );

    let getterCalls = 0;
    const accessor = serializeBeeKEMWelcomeForWire({
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125).fill(1),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    });
    Object.defineProperty(accessor, 'leafIndex', {
      enumerable: true,
      get() {
        getterCalls++;
        return 2;
      },
    });
    expect(() => deserializeBeeKEMWelcomeFromWire(accessor)).toThrow(
      /enumerable data propert/,
    );
    expect(getterCalls).toBe(0);

    const nestedAccessor = serializeBeeKEMWelcomeForWire({
      leafIndex: 2,
      pathKeys: [
        {
          nodeIndex: 1,
          publicKey: new Uint8Array(65),
          encryptedPrivateKey: new Uint8Array(125).fill(1),
        },
      ],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      treeHash: new Uint8Array(32),
    });
    Object.defineProperty(nestedAccessor.pathKeys[0], 'publicKey', {
      enumerable: true,
      get() {
        getterCalls++;
        return '';
      },
    });
    expect(() => deserializeBeeKEMWelcomeFromWire(nestedAccessor)).toThrow(
      /enumerable data propert/,
    );
    expect(getterCalls).toBe(0);
  });
});

describe('welcome-sealed-payload', () => {
  test('round-trips a payload with both keychain and BeeKEM welcome', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);

    const keychainBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = encodeWelcomeSealedPayload({
      keychainChanges: keychainBytes,
      beekemWelcome: welcome,
    });

    const decoded = decodeWelcomeSealedPayload(encoded);
    expect(decoded.keychainChanges).toEqual(keychainBytes);
    expect(decoded.beekemWelcome).not.toBeNull();
    expect(decoded.beekemWelcome!.leafIndex).toBe(welcome.leafIndex);
    expect(decoded.beekemWelcome!.treeHash).toEqual(welcome.treeHash);
  });

  test('round-trips a payload with no BeeKEM welcome', () => {
    const keychainBytes = new Uint8Array([99, 100, 101]);
    const encoded = encodeWelcomeSealedPayload({
      keychainChanges: keychainBytes,
      beekemWelcome: null,
    });

    const decoded = decodeWelcomeSealedPayload(encoded);
    expect(decoded.keychainChanges).toEqual(keychainBytes);
    expect(decoded.beekemWelcome).toBeNull();
  });

  test('throws on non-JSON plaintext', () => {
    const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    expect(() => decodeWelcomeSealedPayload(garbage)).toThrow(
      /not valid (JSON|UTF-8)/,
    );
  });

  test('throws on JSON missing the keychain field', () => {
    const bad = new TextEncoder().encode(JSON.stringify({ bk: null }));
    expect(() => decodeWelcomeSealedPayload(bad)).toThrow(/'k'/);
  });

  test('tolerates `bk` omitted (legacy/optional)', () => {
    const keychainB64 = Buffer.from(new Uint8Array([7, 7, 7])).toString(
      'base64',
    );
    const encoded = new TextEncoder().encode(
      JSON.stringify({ k: keychainB64 }),
    );
    const decoded = decodeWelcomeSealedPayload(encoded);
    expect(decoded.beekemWelcome).toBeNull();
  });

  test('names the bad field when `bk` deserialization throws', () => {
    // Module docstring promises errors that "name the bad field". A
    // malformed `bk` lets `deserializeBeeKEMWelcomeFromWire` raise
    // its own field-level message (e.g. about `leafIndex`), but the
    // envelope-level field name (`bk`) must also be present so the
    // operator can locate the problem in the envelope schema.
    const keychainB64 = Buffer.from(new Uint8Array([1, 2, 3])).toString(
      'base64',
    );
    // `bk` is a non-null object but missing the required `leafIndex`
    // field -- `deserializeBeeKEMWelcomeFromWire` throws.
    const encoded = new TextEncoder().encode(
      JSON.stringify({ k: keychainB64, bk: { notAWelcome: true } }),
    );
    expect(() => decodeWelcomeSealedPayload(encoded)).toThrow(/'bk'/);
  });
});
