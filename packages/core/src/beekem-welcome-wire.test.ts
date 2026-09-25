import { welcomeFixture } from './__testutils__/beekem-v2.js';
import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import * as TreeMath from './beekem/tree-math.js';
import {
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMWelcomeV2ForWire,
} from './beekem-welcome-wire.js';
import {
  decodeWelcomeSealedPayloadV2,
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

describe('beekem-welcome-wire', () => {
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
    const carol = new BeeKEM();
    await expect(
      carol.processWelcome(decoded, carolKeys.privateKey, carolKeys.publicKey),
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

  test('round-trips a real BeeKEMWelcomeV2 produced by BeeKEM.addMember', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);

    const wire = serializeBeeKEMWelcomeV2ForWire(welcome);
    const reparsed = JSON.parse(JSON.stringify(wire));
    const restored = deserializeBeeKEMWelcomeV2FromWire(reparsed);

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

  test('seals Welcomes with blank join-path parents for sequential joins', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const gappedLeafCounts: number[] = [];

    for (let numLeaves = 2; numLeaves <= 8; numLeaves++) {
      const joinerKeys = await generateECDHKeyPair();
      const { welcome, rootSecret } = await alice.addMember(
        joinerKeys.publicKey,
      );
      const restored = decodeWelcomeSealedPayloadV2(
        encodeWelcomeSealedPayloadV2({
          keychainChanges: new Uint8Array([1, 2, 3]),
          beekemWelcome: welcome,
        }),
      ).beekemWelcome;
      const directPath = TreeMath.directPath(
        restored.leafIndex,
        restored.numLeaves,
      );
      if (restored.pathKeys.length < directPath.length) {
        gappedLeafCounts.push(restored.numLeaves);
        const pathKeyIndices = new Set(
          restored.pathKeys.map((node) => node.nodeIndex),
        );
        for (const nodeIndex of directPath) {
          if (pathKeyIndices.has(nodeIndex)) continue;
          expect(restored.treeNodePublicKeys).toContainEqual({
            nodeIndex,
            publicKey: null,
          });
        }
      }

      const joiner = new BeeKEM();
      await expect(
        joiner.processWelcome(
          restored,
          joinerKeys.privateKey,
          joinerKeys.publicKey,
        ),
      ).resolves.toEqual(rootSecret);
    }

    expect(gappedLeafCounts).toEqual(expect.arrayContaining([4, 6, 7, 8]));
  });

  test.each([
    ['leafIndex', -1],
    ['pathKeys', 'oops'],
    ['treeHash', 42],
  ])('rejects malformed %s', (field, value) => {
    const wire = serializeBeeKEMWelcomeV2ForWire(welcomeFixture());
    expect(() => deserializeBeeKEMWelcomeV2FromWire({ ...wire, [field]: value }))
      .toThrow(new RegExp(field));
  });

  test('rejects a malformed path-key index in a complete Welcome', () => {
    const wire = serializeBeeKEMWelcomeV2ForWire(welcomeFixture());
    wire.pathKeys[0].nodeIndex = -1;
    expect(() => deserializeBeeKEMWelcomeV2FromWire(wire)).toThrow(/nodeIndex/);
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
    const encoded = encodeWelcomeSealedPayloadV2({
      keychainChanges: keychainBytes,
      beekemWelcome: welcome,
    });

    const decoded = decodeWelcomeSealedPayloadV2(encoded);
    expect(decoded.keychainChanges).toEqual(keychainBytes);
    expect(decoded.beekemWelcome).not.toBeNull();
    expect(decoded.beekemWelcome!.leafIndex).toBe(welcome.leafIndex);
    expect(decoded.beekemWelcome!.treeHash).toEqual(welcome.treeHash);
  });

  test('rejects a payload with no BeeKEM welcome', () => {
    const keychainBytes = new Uint8Array([99, 100, 101]);
    expect(() => encodeWelcomeSealedPayloadV2({
      keychainChanges: keychainBytes,
      beekemWelcome: null as never,
    })).toThrow(/BeeKEMWelcomeV2/);
  });

  test('throws on non-JSON plaintext', () => {
    const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    expect(() => decodeWelcomeSealedPayloadV2(garbage)).toThrow(
      /not valid (JSON|UTF-8)/,
    );
  });

  test('throws on JSON missing the keychain field', () => {
    const bad = new TextEncoder().encode(JSON.stringify({ bk: null }));
    expect(() => decodeWelcomeSealedPayloadV2(bad)).toThrow(/'k'/);
  });

  test('rejects an omitted tree', () => {
    const keychainB64 = Buffer.from(new Uint8Array([7, 7, 7])).toString('base64');
    const encoded = new TextEncoder().encode(JSON.stringify({ k: keychainB64 }));
    expect(() => decodeWelcomeSealedPayloadV2(encoded)).toThrow(/'bk'/);
  });

  test("names the bad field when `bk` deserialization throws", () => {
    // Module docstring promises errors that "name the bad field". A
    // malformed `bk` lets `deserializeBeeKEMWelcomeV2FromWire` raise
    // its own field-level message (e.g. about `leafIndex`), but the
    // envelope-level field name (`bk`) must also be present so the
    // operator can locate the problem in the envelope schema.
    const keychainB64 = Buffer.from(new Uint8Array([1, 2, 3])).toString('base64');
    // `bk` is a non-null object but missing the required `leafIndex`
    // field -- `deserializeBeeKEMWelcomeV2FromWire` throws.
    const encoded = new TextEncoder().encode(
      JSON.stringify({ k: keychainB64, bk: { notAWelcome: true } }),
    );
    expect(() => decodeWelcomeSealedPayloadV2(encoded)).toThrow(/'bk'/);
  });
});
