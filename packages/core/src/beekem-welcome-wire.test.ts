import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import {
  deserializeBeeKEMWelcomeFromWire,
  serializeBeeKEMWelcomeForWire,
} from './beekem-welcome-wire.js';
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
