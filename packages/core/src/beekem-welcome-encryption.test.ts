import { describe, expect, test } from '@jest/globals';
import {
  eciesSeal,
  eciesOpen,
  generateEciesKeyPair,
  importEciesPublicKey,
  exportEciesPublicKey,
} from './ecies.js';

/**
 * Wire-level coverage of the BeeKEM Welcome payload encryption flow.
 *
 * The production receive path
 * (`PeerborneDocument._evaluateAndApplyBeeKEMWelcome`) requires a
 * full libp2p/Helia stack to instantiate, so this file exercises the
 * security-critical invariants of the sealed-payload design directly
 * against the `ecies` primitive that wraps the keychain delta:
 *
 *   1. The recipient with the matching ECDH private key can open
 *      the sealed payload and recover the plaintext keychain delta.
 *   2. A non-recipient peer (different ECDH key pair) sees only
 *      opaque ciphertext and cannot decrypt the payload even if it
 *      observes the full broadcast.
 *   3. A tampered sealed payload fails the AES-GCM integrity check
 *      regardless of which recipient attempts to open it.
 *
 * The "Welcome" in these tests is modeled as the bytes that would
 * appear in the `eciesSealed` field of a `CRDTSyncMessage`. The
 * surrounding signature / recipient-binding checks are covered by
 * `beekem-welcome-handler.test.ts`.
 */

describe('BeeKEM Welcome payload encryption (round-trip via ECIES)', () => {
  test('intended recipient can open the sealed Welcome and recover the keychain delta', async () => {
    const recipient = await generateEciesKeyPair();
    const keychainDelta = new TextEncoder().encode(
      'pretend-this-is-a-serialized-keychain-CRDT-delta',
    );

    // Inviter: seal the keychain delta to the recipient's public key.
    const sealed = await eciesSeal(keychainDelta, recipient.publicKey);

    // Recipient: open with their private key.
    const opened = await eciesOpen(sealed, recipient.privateKey);
    expect(new TextDecoder().decode(opened)).toBe(
      'pretend-this-is-a-serialized-keychain-CRDT-delta',
    );
  });

  test('a non-recipient peer observing the sealed Welcome cannot decrypt it', async () => {
    const intendedRecipient = await generateEciesKeyPair();
    const eavesdropper = await generateEciesKeyPair();

    const keychainDelta = new TextEncoder().encode('document-key-material');
    const sealed = await eciesSeal(
      keychainDelta,
      intendedRecipient.publicKey,
    );

    // An eavesdropper with a DIFFERENT ECDH key pair (e.g. another
    // connected libp2p peer who is not the addressed reader) cannot
    // recover the keychain delta even with full access to the
    // broadcast sealed bytes.
    await expect(
      eciesOpen(sealed, eavesdropper.privateKey),
    ).rejects.toThrow();
  });

  test('round-trip via raw-exported public key matches the design wire format', async () => {
    // The Welcome carries the recipient's KEM public key as raw
    // SEC1-uncompressed bytes (65 bytes for P-256) in the
    // `welcomeRecipientKemPublicKey` field. The inviter imports those
    // bytes and seals against the resulting CryptoKey -- mirror that
    // path here so a regression in the raw-bytes representation
    // surfaces.
    const recipient = await generateEciesKeyPair();
    const rawRecipientPub = await exportEciesPublicKey(recipient.publicKey);
    expect(rawRecipientPub.byteLength).toBe(65);

    const importedRecipientPub = await importEciesPublicKey(rawRecipientPub);
    const keychainDelta = new Uint8Array([42, 13, 7, 1, 0, 255]);
    const sealed = await eciesSeal(keychainDelta, importedRecipientPub);

    const opened = await eciesOpen(sealed, recipient.privateKey);
    expect(opened).toEqual(keychainDelta);
  });

  test('a tampered sealed Welcome (single bit flipped) is rejected by the recipient', async () => {
    // Establishes that the signed-but-tampered case (where an attacker
    // re-signs the sync message after altering the sealed bytes)
    // would still fail decryption at the recipient. Combined with the
    // writer-signature gate that covers `eciesSealed` itself, this
    // gives belt-and-braces protection: the signature catches
    // unauthorized writers, AES-GCM catches authorized writers (or
    // anyone else) altering the ciphertext.
    const recipient = await generateEciesKeyPair();
    const sealed = await eciesSeal(
      new TextEncoder().encode('keychain-payload'),
      recipient.publicKey,
    );

    const tampered = new Uint8Array(sealed);
    // Flip a bit in the ciphertext region (well past the salt /
    // ephemeral key / nonce header so we exercise the AES-GCM tag).
    tampered[tampered.byteLength - 1] ^= 0x01;
    await expect(eciesOpen(tampered, recipient.privateKey)).rejects.toThrow();
  });

  test('two recipients invited at the same epoch get distinct sealed payloads', async () => {
    // Two new readers added to the same document at the same epoch
    // produce independent sealed payloads (sender generates a fresh
    // ephemeral key + nonce per call), each only openable by its
    // intended recipient. Establishes there is no cross-decryption
    // path even when the inviter, plaintext, and epoch are identical.
    const alice = await generateEciesKeyPair();
    const bob = await generateEciesKeyPair();

    const keychainDelta = new TextEncoder().encode(
      'epoch-1-keychain-delta-shared-by-both-welcomes',
    );
    const sealedToAlice = await eciesSeal(keychainDelta, alice.publicKey);
    const sealedToBob = await eciesSeal(keychainDelta, bob.publicKey);

    // Distinct ciphertexts (different ephemeral keys / nonces).
    expect(sealedToAlice).not.toEqual(sealedToBob);

    // Each recipient opens their own payload successfully.
    expect(await eciesOpen(sealedToAlice, alice.privateKey)).toEqual(
      keychainDelta,
    );
    expect(await eciesOpen(sealedToBob, bob.privateKey)).toEqual(
      keychainDelta,
    );

    // Cross-decryption fails.
    await expect(eciesOpen(sealedToAlice, bob.privateKey)).rejects.toThrow();
    await expect(eciesOpen(sealedToBob, alice.privateKey)).rejects.toThrow();
  });
});
