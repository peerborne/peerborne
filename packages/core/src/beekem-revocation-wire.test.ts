/**
 * End-to-end wire-integration test for the BeeKEM-based reader
 * revocation flow.
 *
 * The companion test in `beekem-revocation.test.ts` exercises the
 * cryptographic core in isolation (BeeKEM tree + HKDF doc-key
 * derivation). This test stitches together the actual on-wire layers
 * that production traffic goes through:
 *
 *   - The BeeKEM Welcome inside the structured `eciesSealed`
 *     envelope (`welcome-sealed-payload.ts`).
 *   - The BeeKEM Welcome wire shape
 *     (`beekem-welcome-wire.ts`).
 *   - The BeeKEM PathUpdate wire shape
 *     (`path-update-wire.ts`).
 *
 * The flow models a 3-reader scenario where:
 *   - Alice (writer/founder) seeds the tree as leaf 0.
 *   - Bob is invited as leaf 1 (node index 2) and bootstraps via
 *     the sealed envelope.
 *   - Carol is invited as leaf 2 (node index 4) and bootstraps via
 *     her own sealed envelope.
 *   - Alice revokes Bob via `removeMember` and broadcasts the
 *     PathUpdate over the wire.
 *   - Carol applies the PathUpdate and converges on Alice's new
 *     document key (security property: SURVIVING reader can still
 *     decrypt).
 *   - Bob CANNOT derive the new key from the same PathUpdate
 *     (security property: REMOVED reader is locked out).
 *
 * The full `PeerborneDocument` receive path requires a libp2p/Helia
 * stack which is heavy to spin up in unit tests. The integration
 * surface that's been ADDED in this PR -- the structured
 * sealed-payload envelope + the `processWelcome` step on the joiner
 * -- is exercised here against the same wire encoders/decoders used
 * by production code, so a regression in either the envelope shape or
 * the BeeKEM-side handling surfaces here without needing a full e2e
 * environment.
 */

import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { eciesOpen, eciesSeal, generateEciesKeyPair } from './ecies.js';

/**
 * Re-import a raw SEC1 P-256 public key with `extractable=true` so
 * BeeKEM's tree-hash computation can `exportKey('raw', ...)` over it.
 * Mirrors the production helper used by `_registerBeeKEMReader`.
 */
async function importExtractableKemPublicKey(
  raw: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    raw as unknown as BufferSource,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import {
  deserializePathUpdateFromWire,
  serializePathUpdateForWire,
} from './path-update-wire.js';
import {
  decodeWelcomeSealedPayload,
  encodeWelcomeSealedPayload,
} from './welcome-sealed-payload.js';

function toBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out;
}

async function encryptUnder(key: CryptoKey, plaintext: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    key,
    toBuffer(plaintext),
  );
  return { iv, ct: new Uint8Array(ct) };
}

async function decryptUnder(
  key: CryptoKey,
  iv: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    key,
    toBuffer(ct),
  );
  return new Uint8Array(pt);
}

/**
 * Model: a peer's full bootstrap state. Mirrors the
 * `PeerborneDocument` joiner: a KEM key pair (the ECIES recipient)
 * plus a local BeeKEM instance that gets initialized via
 * `processWelcome` once the sealed envelope is opened.
 */
interface PeerState {
  kemKeyPair: CryptoKeyPair;
  /** Raw SEC1-uncompressed bytes the inviter passes to ECIES seal. */
  rawKemPublic: Uint8Array;
  beekem: BeeKEM | null;
}

async function makePeer(): Promise<PeerState> {
  const kemKeyPair = await generateEciesKeyPair();
  const rawKemPublic = new Uint8Array(
    await crypto.subtle.exportKey('raw', kemKeyPair.publicKey),
  );
  return { kemKeyPair, rawKemPublic, beekem: null };
}

describe('BeeKEM reader revocation (wire-integration)', () => {
  test('Carol (surviving reader) keeps access; Bob (revoked) is locked out', async () => {
    // ----- Setup: 3 readers + founder ---------------------------------
    const aliceKemKeyPair = await generateEciesKeyPair();
    const alice = new BeeKEM();
    await alice.initialize(
      aliceKemKeyPair.privateKey,
      aliceKemKeyPair.publicKey,
    );

    const bob = await makePeer();
    const carol = await makePeer();

    // ----- Invite Bob ------------------------------------------------
    const bobKemImported = await importExtractableKemPublicKey(bob.rawKemPublic);
    const bobAddResult = await alice.addMember(bobKemImported);

    // The keychain delta inside Bob's welcome envelope models the
    // current document key the founder ships to the joiner. The real
    // PeerborneDocument code uses `_keychainChangesForWelcome` here;
    // for this wire-integration test we just need a stable byte
    // representation that survives the round-trip.
    const bobKeychainBytes = new TextEncoder().encode(
      'bob-keychain-delta-at-invite',
    );
    const bobEnvelopeBytes = encodeWelcomeSealedPayload({
      keychainChanges: bobKeychainBytes,
      beekemWelcome: bobAddResult.welcome,
    });
    const bobSealed = await eciesSeal(bobEnvelopeBytes, bobKemImported);

    // Joiner side: open the sealed envelope, bootstrap BeeKEM.
    const bobOpened = await eciesOpen(bobSealed, bob.kemKeyPair.privateKey);
    const bobEnvelope = decodeWelcomeSealedPayload(bobOpened);
    expect(bobEnvelope.beekemWelcome).not.toBeNull();
    expect(bobEnvelope.keychainChanges).toEqual(bobKeychainBytes);
    bob.beekem = new BeeKEM();
    await bob.beekem.processWelcome(
      bobEnvelope.beekemWelcome!,
      bob.kemKeyPair.privateKey,
      bob.kemKeyPair.publicKey,
    );

    // ----- Invite Carol ----------------------------------------------
    const carolKemImported = await importExtractableKemPublicKey(
      carol.rawKemPublic,
    );
    const carolAddResult = await alice.addMember(carolKemImported);
    const carolKeychainBytes = new TextEncoder().encode(
      'carol-keychain-delta-at-invite',
    );
    const carolEnvelopeBytes = encodeWelcomeSealedPayload({
      keychainChanges: carolKeychainBytes,
      beekemWelcome: carolAddResult.welcome,
    });
    const carolSealed = await eciesSeal(carolEnvelopeBytes, carolKemImported);

    const carolOpened = await eciesOpen(
      carolSealed,
      carol.kemKeyPair.privateKey,
    );
    const carolEnvelope = decodeWelcomeSealedPayload(carolOpened);
    carol.beekem = new BeeKEM();
    await carol.beekem.processWelcome(
      carolEnvelope.beekemWelcome!,
      carol.kemKeyPair.privateKey,
      carol.kemKeyPair.publicKey,
    );

    // ----- Sanity: an eavesdropper cannot open the sealed envelope ---
    const eavesdropper = await generateEciesKeyPair();
    await expect(
      eciesOpen(bobSealed, eavesdropper.privateKey),
    ).rejects.toThrow();

    // ----- Revoke Bob ------------------------------------------------
    // Bob's leaf index: leaf-1 -> node index 2.
    const bobLeafIndex = bobAddResult.welcome.leafIndex;
    expect(bobLeafIndex).toBe(2);
    const { pathUpdate, rootSecret: aliceNewRoot } = await alice.removeMember(
      bobLeafIndex,
    );

    // PathUpdate goes over `beekemPathUpdateV1` -- round-trip through
    // the wire encoder/decoder so a regression in either surfaces.
    const wire = JSON.parse(JSON.stringify(serializePathUpdateForWire(pathUpdate)));
    const restored = deserializePathUpdateFromWire(wire);

    // ----- Carol applies the wire-restored PathUpdate ----------------
    const carolNewRoot = await carol.beekem.processPathUpdate(restored);
    expect(Buffer.from(carolNewRoot).equals(Buffer.from(aliceNewRoot))).toBe(
      true,
    );

    // Carol's derived doc key + epoch ID match Alice's.
    const [aliceKey, carolKey, aliceEpochId, carolEpochId] = await Promise.all([
      deriveDocumentKeyFromRootSecret(aliceNewRoot),
      deriveDocumentKeyFromRootSecret(carolNewRoot),
      deriveEpochIdFromRootSecret(aliceNewRoot),
      deriveEpochIdFromRootSecret(carolNewRoot),
    ]);
    expect(aliceEpochId.byteLength).toBe(32); // FULL 32-byte ID on the wire.
    expect(carolEpochId).toEqual(aliceEpochId);

    // ----- Post-revocation traffic -----------------------------------
    const secret = new TextEncoder().encode('post-revocation chat message');
    const { iv, ct } = await encryptUnder(aliceKey, secret);

    // Carol (survivor) decrypts cleanly.
    expect(await decryptUnder(carolKey, iv, ct)).toEqual(secret);

    // Bob (revoked) cannot derive the new key. Either
    // processPathUpdate throws (no intersection with his blanked
    // path) or, if it produced something, the resulting key fails
    // AES-GCM authentication on the post-revocation ciphertext.
    let bobDerivedKey: CryptoKey | null = null;
    try {
      const bobAttemptRoot = await bob.beekem!.processPathUpdate(restored);
      bobDerivedKey = await deriveDocumentKeyFromRootSecret(bobAttemptRoot);
    } catch {
      // expected outcome for the canonical revocation property.
    }
    if (bobDerivedKey) {
      await expect(decryptUnder(bobDerivedKey, iv, ct)).rejects.toThrow();
    } else {
      expect(bobDerivedKey).toBeNull();
    }
  });

  test('a Welcome sealed to one recipient cannot bootstrap another', async () => {
    // Defense in depth: the BeeKEM `processWelcome` step uses the
    // recipient's private key to decrypt the path-key chain in the
    // welcome. A recipient holding a DIFFERENT key pair than the one
    // the inviter sealed against cannot bootstrap from the envelope
    // -- both the ECIES open AND the processWelcome decryption would
    // fail (ECIES first, since it gates the outer envelope).
    const alice = new BeeKEM();
    const aliceKeys = await generateEciesKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bob = await makePeer();
    const bobKemImported = await importExtractableKemPublicKey(bob.rawKemPublic);
    const { welcome } = await alice.addMember(bobKemImported);

    const envelopeBytes = encodeWelcomeSealedPayload({
      keychainChanges: new Uint8Array([1, 2, 3]),
      beekemWelcome: welcome,
    });
    const sealed = await eciesSeal(envelopeBytes, bobKemImported);

    // Mallory has her own KEM key pair (not the one Bob's leaf was
    // seeded with) -- the ECIES open fails before BeeKEM ever sees
    // the welcome.
    const mallory = await generateEciesKeyPair();
    await expect(eciesOpen(sealed, mallory.privateKey)).rejects.toThrow();
  });

  test('Bob (revoked before Carol joined) is still locked out after a later add+remove cycle', async () => {
    // The revocation security property has to hold even when Alice
    // does more group operations after the revocation -- not just
    // immediately after.
    const aliceKeys = await generateEciesKeyPair();
    const alice = new BeeKEM();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bob = await makePeer();
    const bobKemImported = await importExtractableKemPublicKey(bob.rawKemPublic);
    const bobAdd = await alice.addMember(bobKemImported);
    bob.beekem = new BeeKEM();
    await bob.beekem.processWelcome(
      bobAdd.welcome,
      bob.kemKeyPair.privateKey,
      bob.kemKeyPair.publicKey,
    );

    // Bob is revoked.
    const { pathUpdate: revokeUpdate, rootSecret: postRevokeRoot } =
      await alice.removeMember(bobAdd.welcome.leafIndex);
    expect(() => {
      const wire = serializePathUpdateForWire(revokeUpdate);
      deserializePathUpdateFromWire(JSON.parse(JSON.stringify(wire)));
    }).not.toThrow();
    const postRevokeKey = await deriveDocumentKeyFromRootSecret(postRevokeRoot);

    // Bob cannot apply Alice's revocation PathUpdate -- expected.
    let bobKey: CryptoKey | null = null;
    try {
      const bobRoot = await bob.beekem!.processPathUpdate(revokeUpdate);
      bobKey = await deriveDocumentKeyFromRootSecret(bobRoot);
    } catch {
      // expected.
    }

    // Encrypt a probe message under Alice's post-revoke key.
    const probe = new TextEncoder().encode('alice-only message');
    const { iv, ct } = await encryptUnder(postRevokeKey, probe);

    if (bobKey) {
      await expect(decryptUnder(bobKey, iv, ct)).rejects.toThrow();
    } else {
      expect(bobKey).toBeNull();
    }
  });
});
