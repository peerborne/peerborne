import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import * as TreeMath from './beekem/tree-math.js';
import {
  BeeKEMWelcome,
  BeeKEMWelcomeV2,
  MAX_BEEKEM_TREE_LEAVES,
} from './beekem/types.js';
import {
  deserializeBeeKEMWelcomeFromWire,
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMWelcomeForWire,
  serializeBeeKEMWelcomeV2ForWire,
} from './beekem-welcome-wire.js';
import {
  decodeWelcomeSealedPayload,
  decodeWelcomeSealedPayloadV2,
  encodeWelcomeSealedPayload,
  encodeWelcomeSealedPayloadV2,
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

function projectLegacyWelcome(welcome: BeeKEMWelcomeV2): BeeKEMWelcome {
  return {
    leafIndex: welcome.leafIndex,
    pathKeys: welcome.pathKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    })),
    treeNodePublicKeys: welcome.treeNodePublicKeys,
    treeHash: welcome.treeHash,
  };
}

describe('beekem-welcome-wire', () => {
  test('preserves the exact legacy v1 projection', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);

    const wire = serializeBeeKEMWelcomeForWire(projectLegacyWelcome(welcome));
    expect(Object.keys(wire).sort()).toEqual([
      'leafIndex',
      'pathKeys',
      'treeHash',
      'treeNodePublicKeys',
    ]);
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializeBeeKEMWelcomeFromWire(reparsed);

    expect(restored.leafIndex).toBe(welcome.leafIndex);
    expect(restored.pathKeys.length).toBe(welcome.pathKeys.length);
    for (let i = 0; i < welcome.pathKeys.length; i++) {
      expect(restored.pathKeys[i].nodeIndex).toBe(welcome.pathKeys[i].nodeIndex);
      expect(restored.pathKeys[i].publicKey).toEqual(welcome.pathKeys[i].publicKey);
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
    expect(restored.generation).toBeUndefined();
    expect(restored.numLeaves).toBeUndefined();
    expect(restored.version).toBeUndefined();
  });

  test('v2 codec requires and preserves version, generation, and numLeaves', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);

    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        numLeaves: MAX_BEEKEM_TREE_LEAVES + 1,
      }),
    ).toThrow(new RegExp(String(MAX_BEEKEM_TREE_LEAVES)));
    expect(deserializeBeeKEMWelcomeV2FromWire(wire)).toEqual(welcome);

    const legacy = serializeBeeKEMWelcomeForWire(
      projectLegacyWelcome(welcome),
    );
    expect(deserializeBeeKEMWelcomeFromWire(legacy).generation).toBeUndefined();
    expect(() => deserializeBeeKEMWelcomeV2FromWire(legacy)).toThrow(/version/);
    for (const [field, value] of [
      ['version', 2],
      ['generation', welcome.generation],
      ['numLeaves', welcome.numLeaves],
    ] as const) {
      expect(() =>
        deserializeBeeKEMWelcomeFromWire({ ...legacy, [field]: value }),
      ).toThrow(/v2-only/);
    }
    for (const generation of [-1, 1.5, 0x1_0000_0000]) {
      expect(() =>
        deserializeBeeKEMWelcomeV2FromWire({ ...wire, generation }),
      ).toThrow(/generation/);
    }
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

    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);
    const restored = deserializeBeeKEMWelcomeV2FromWire(
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

  test.each([3, 5])(
    'v2 Welcome round-trips a complete %i-member non-power-of-two tree',
    async (memberCount) => {
      const founder = new BeeKEM();
      const founderKeys = await generateECDHKeyPair();
      await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
      let finalKeys: CryptoKeyPair | undefined;
      let finalResult: Awaited<ReturnType<BeeKEM['addMember']>> | undefined;
      for (let count = 2; count <= memberCount; count++) {
        finalKeys = await generateECDHKeyPair();
        finalResult = await founder.addMember(finalKeys.publicKey);
      }
      if (!finalKeys || !finalResult) throw new Error('missing final member');

      const restored = deserializeBeeKEMWelcomeV2FromWire(
        serializeBeeKEMWelcomeV2ForWire(finalResult.welcome),
      );
      const joiner = new BeeKEM();
      expect(
        await joiner.processWelcome(
          restored,
          finalKeys.privateKey,
          finalKeys.publicKey,
        ),
      ).toEqual(finalResult.rootSecret);
    },
  );

  test('rejects malformed wire inputs with descriptive errors', () => {
    expect(() => deserializeBeeKEMWelcomeFromWire(null)).toThrow(/plain object/);
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
        leafIndex: 0,
        pathKeys: 'oops',
        treeNodePublicKeys: [],
        treeHash: '',
      }),
    ).toThrow(/pathKeys.*array/);
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 0,
        pathKeys: [],
        treeNodePublicKeys: [],
        treeHash: 42,
      }),
    ).toThrow(/treeHash/);
    expect(() =>
      deserializeBeeKEMWelcomeFromWire({
        leafIndex: 0,
        pathKeys: [{ nodeIndex: -1, publicKey: '', encryptedPrivateKey: '' }],
        treeNodePublicKeys: [],
        treeHash: '',
      }),
    ).toThrow(/pathKeys\[0\]\.nodeIndex.*non-negative/);
  });

  test('v2 rejects extra keys, malformed topology, bounds, and non-canonical base64', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);

    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({ ...wire, unexpected: true }),
    ).toThrow(/unexpected field/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: [{ ...wire.pathKeys[0], unexpected: true }],
      }),
    ).toThrow(/pathKeys\[0\].*unexpected field/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        treeNodePublicKeys: [
          { ...wire.treeNodePublicKeys[0], unexpected: true },
        ],
      }),
    ).toThrow(/treeNodePublicKeys\[0\].*unexpected field/);

    const inherited = Object.create({ inherited: true }) as Record<
      string,
      unknown
    >;
    Object.assign(inherited, wire);
    expect(() => deserializeBeeKEMWelcomeV2FromWire(inherited)).toThrow(
      /plain object/,
    );
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        treeNodePublicKeys: [
          {
            ...wire.treeNodePublicKeys[0],
            nodeIndex: wire.pathKeys[0].nodeIndex,
          },
        ],
      }),
    ).toThrow(/duplicate/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        treeNodePublicKeys: [
          {
            ...wire.treeNodePublicKeys[0],
            nodeIndex: 2 * wire.numLeaves - 1,
          },
        ],
      }),
    ).toThrow(/out-of-range/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        treeNodePublicKeys: [],
      }),
    ).toThrow(/complete tree/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: [
          { ...wire.pathKeys[0], publicKey: `${wire.pathKeys[0].publicKey} ` },
        ],
      }),
    ).toThrow(/canonical padded base64/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        treeHash: `${wire.treeHash}=`,
      }),
    ).toThrow(/canonical padded base64/);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: [
          {
            ...wire.pathKeys[0],
            encryptedPrivateKey: 'A'.repeat(400_000),
          },
        ],
      }),
    ).toThrow(/size limit/);
  });

  test('v2 rejects an omitted direct-path node with a non-blank public key', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateECDHKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    await founder.addMember(bobKeys.publicKey);
    const carolKeys = await generateECDHKeyPair();
    const { welcome: carolWelcome } = await founder.addMember(
      carolKeys.publicKey,
    );
    const carol = new BeeKEM();
    await carol.processWelcome(
      carolWelcome,
      carolKeys.privateKey,
      carolKeys.publicKey,
    );

    const daveKeys = await generateECDHKeyPair();
    const { welcome } = await carol.addMember(daveKeys.publicKey);
    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);
    const [omitted, ...remainingPath] = wire.pathKeys;
    if (omitted === undefined || remainingPath.length === 0) {
      throw new Error('test fixture requires at least two Welcome path keys');
    }

    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: remainingPath,
        treeNodePublicKeys: [
          ...wire.treeNodePublicKeys,
          { nodeIndex: omitted.nodeIndex, publicKey: omitted.publicKey },
        ],
      }),
    ).toThrow(/omitted direct-path node.*must be blank/);
  });

  test('v2 snapshots Proxy and accessor inputs without invoking caller code', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);

    let directGets = 0;
    const proxiedWire = new Proxy(wire, {
      get() {
        directGets++;
        throw new Error('direct property access must not run');
      },
    });
    expect(deserializeBeeKEMWelcomeV2FromWire(proxiedWire)).toEqual(welcome);
    expect(directGets).toBe(0);

    let arrayGets = 0;
    const proxiedPathKeys = new Proxy(wire.pathKeys, {
      get() {
        arrayGets++;
        throw new Error('array property access must not run');
      },
    });
    expect(
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: proxiedPathKeys,
      }),
    ).toEqual(welcome);
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
    expect(() => deserializeBeeKEMWelcomeV2FromWire(accessorWire)).toThrow(
      /own enumerable data property/,
    );
    expect(accessorCalls).toBe(0);

    const accessorPathKeys = [...wire.pathKeys];
    Object.defineProperty(accessorPathKeys, '0', {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls++;
        return wire.pathKeys[0];
      },
    });
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: accessorPathKeys,
      }),
    ).toThrow(/own enumerable data property/);
    expect(accessorCalls).toBe(0);

    let iteratorCalls = 0;
    const iteratorPathKeys = [...wire.pathKeys];
    Object.defineProperty(iteratorPathKeys, Symbol.iterator, {
      configurable: true,
      value() {
        iteratorCalls++;
        throw new Error('iterator must not run');
      },
    });
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: iteratorPathKeys,
      }),
    ).toThrow(/dense array without extra properties/);
    expect(iteratorCalls).toBe(0);

    let ownKeysCalls = 0;
    const oversizedPathKeys = new Proxy(new Array(65), {
      ownKeys() {
        ownKeysCalls++;
        throw new Error('ownKeys must not run after an oversized length');
      },
    });
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire({
        ...wire,
        pathKeys: oversizedPathKeys,
      }),
    ).toThrow(/pathKeys has invalid length/);
    expect(ownKeysCalls).toBe(0);
  });

  test('v2 enforces its aggregate decoded-byte budget', () => {
    const numLeaves = MAX_BEEKEM_TREE_LEAVES;
    const treeWidth = 2 * numLeaves - 1;
    const leafIndex = TreeMath.leafToNodeIndex(numLeaves - 1);
    const directPath = TreeMath.directPath(leafIndex, numLeaves);
    const covered = new Set([leafIndex, ...directPath]);
    const publicKey = Buffer.alloc(65, 1).toString('base64');
    const largeCiphertext = Buffer.alloc(260 * 1024, 2).toString('base64');
    let remainingPublicKeys = 14_000;
    const treeNodePublicKeys: Array<{
      nodeIndex: number;
      publicKey: string | null;
    }> = [];
    for (let nodeIndex = 0; nodeIndex < treeWidth; nodeIndex++) {
      if (covered.has(nodeIndex)) continue;
      treeNodePublicKeys.push({
        nodeIndex,
        publicKey: remainingPublicKeys-- > 0 ? publicKey : null,
      });
    }
    const byteHeavy = {
      version: 2,
      generation: 1,
      numLeaves,
      leafIndex,
      pathKeys: directPath.map((nodeIndex) => ({
        nodeIndex,
        publicKey,
        encryptedPrivateKey: largeCiphertext,
      })),
      treeNodePublicKeys,
      treeHash: Buffer.alloc(32, 3).toString('base64'),
    };
    expect(() => deserializeBeeKEMWelcomeV2FromWire(byteHeavy)).toThrow(
      /aggregate decoded-byte budget/,
    );
  });

  test('maximum-width public snapshot stays below the 10 MiB frame', () => {
    const numLeaves = MAX_BEEKEM_TREE_LEAVES;
    const leafIndex = TreeMath.leafToNodeIndex(numLeaves - 1);
    const directPath = TreeMath.directPath(leafIndex, numLeaves);
    const covered = new Set([leafIndex, ...directPath]);
    const publicKey = new Uint8Array(65).fill(1);
    const welcome: BeeKEMWelcomeV2 = {
      version: 2,
      generation: 1,
      numLeaves,
      leafIndex,
      pathKeys: directPath.map((nodeIndex) => ({
        nodeIndex,
        publicKey,
        encryptedPrivateKey: new Uint8Array([1]),
      })),
      treeNodePublicKeys: Array.from(
        { length: 2 * numLeaves - 1 },
        (_, nodeIndex) =>
          covered.has(nodeIndex)
            ? undefined
            : { nodeIndex, publicKey },
      ).filter(
        (entry): entry is { nodeIndex: number; publicKey: Uint8Array } =>
          entry !== undefined,
      ),
      treeHash: new Uint8Array(32).fill(2),
    };

    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);
    const encodedBytes = new TextEncoder().encode(JSON.stringify(wire));
    expect(encodedBytes.byteLength).toBeLessThan(10 * 1024 * 1024);
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
      beekemWelcome: projectLegacyWelcome(welcome),
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

  test('v2 sealed payload requires a non-null generation-bearing Welcome', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const keychainChanges = new Uint8Array([8, 9]);
    const encoded = encodeWelcomeSealedPayloadV2({
      keychainChanges,
      beekemWelcome: welcome,
    });
    expect(decodeWelcomeSealedPayloadV2(encoded)).toEqual({
      keychainChanges,
      beekemWelcome: welcome,
    });

    const k = Buffer.from(keychainChanges).toString('base64');
    expect(() =>
      decodeWelcomeSealedPayloadV2(
        new TextEncoder().encode(JSON.stringify({ k, bk: null })),
      ),
    ).toThrow(/non-null/);
    const legacyWire = serializeBeeKEMWelcomeForWire(
      projectLegacyWelcome(welcome),
    );
    expect(() =>
      decodeWelcomeSealedPayloadV2(
        new TextEncoder().encode(JSON.stringify({ k, bk: legacyWire })),
      ),
    ).toThrow(/invalid 'bk' \(BeeKEM Welcome v2\)/);

    expect(() =>
      decodeWelcomeSealedPayloadV2(
        new TextEncoder().encode(
          JSON.stringify({
            k,
            bk: serializeBeeKEMWelcomeV2ForWire(welcome),
            unexpected: true,
          }),
        ),
      ),
    ).toThrow(/unexpected field/);
    expect(() =>
      decodeWelcomeSealedPayloadV2(
        new TextEncoder().encode(
          JSON.stringify({
            k: `${k} `,
            bk: serializeBeeKEMWelcomeV2ForWire(welcome),
          }),
        ),
      ),
    ).toThrow(/canonical padded base64/);
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
    const keychainB64 = Buffer.from(new Uint8Array([7, 7, 7])).toString('base64');
    const encoded = new TextEncoder().encode(JSON.stringify({ k: keychainB64 }));
    const decoded = decodeWelcomeSealedPayload(encoded);
    expect(decoded.beekemWelcome).toBeNull();
  });

  test("names the bad field when `bk` deserialization throws", () => {
    // Module docstring promises errors that "name the bad field". A
    // malformed `bk` lets `deserializeBeeKEMWelcomeFromWire` raise
    // its own field-level message (e.g. about `leafIndex`), but the
    // envelope-level field name (`bk`) must also be present so the
    // operator can locate the problem in the envelope schema.
    const keychainB64 = Buffer.from(new Uint8Array([1, 2, 3])).toString('base64');
    // `bk` is a non-null object but missing the required `leafIndex`
    // field -- `deserializeBeeKEMWelcomeFromWire` throws.
    const encoded = new TextEncoder().encode(
      JSON.stringify({ k: keychainB64, bk: { notAWelcome: true } }),
    );
    expect(() => decodeWelcomeSealedPayload(encoded)).toThrow(/'bk'/);
  });
});
