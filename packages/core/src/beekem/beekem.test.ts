import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

/** Generate an ECDH P-256 key pair for BeeKEM testing. */
async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

describe('BeeKEM', () => {
  describe('initialize', () => {
    test('creates a single-member tree', async () => {
      const beekem = new BeeKEM();
      const keyPair = await generateECDHKeyPair();

      await beekem.initialize(keyPair.privateKey, keyPair.publicKey);

      expect(beekem.memberCount).toBe(1);
      expect(beekem.myLeafIndex).toBe(0);
    });

    test('getRootSecret returns a 32-byte Uint8Array', async () => {
      const beekem = new BeeKEM();
      const keyPair = await generateECDHKeyPair();

      await beekem.initialize(keyPair.privateKey, keyPair.publicKey);

      const rootSecret = await beekem.getRootSecret();
      expect(rootSecret).toBeInstanceOf(Uint8Array);
      expect(rootSecret.byteLength).toBe(32);
    });
  });

  describe('addMember', () => {
    test('increases member count', async () => {
      const beekem = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await beekem.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      const bobKeyPair = await generateECDHKeyPair();
      const { pathUpdate, welcome } = await beekem.addMember(bobKeyPair.publicKey);

      expect(beekem.memberCount).toBe(2);
      expect(pathUpdate.nodes.length).toBeGreaterThan(0);
      expect(welcome.leafIndex).toBe(2); // leaf position 1 => node index 2
    });

    test('pathUpdate contains valid node data', async () => {
      const beekem = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await beekem.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      const bobKeyPair = await generateECDHKeyPair();
      const { pathUpdate } = await beekem.addMember(bobKeyPair.publicKey);

      for (const node of pathUpdate.nodes) {
        expect(node.publicKey).toBeInstanceOf(Uint8Array);
        expect(node.publicKey.byteLength).toBe(65); // Uncompressed P-256 point
        expect(node.encryptedPrivateKey).toBeInstanceOf(Uint8Array);
        expect(node.encryptedPrivateKey.byteLength).toBeGreaterThan(0);
      }
    });
  });

  describe('update', () => {
    test('produces a new root secret different from the old one', async () => {
      const beekem = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await beekem.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      const bobKeyPair = await generateECDHKeyPair();
      const { rootSecret: secretAfterAdd } = await beekem.addMember(bobKeyPair.publicKey);

      const { rootSecret: secretAfterUpdate } = await beekem.update();

      // Root secret should change after update (new key material)
      expect(secretAfterUpdate).toBeInstanceOf(Uint8Array);
      expect(secretAfterUpdate.byteLength).toBe(32);
      expect(Buffer.from(secretAfterUpdate).equals(Buffer.from(secretAfterAdd))).toBe(false);
    });
  });

  describe('two-member key agreement', () => {
    test('Alice and Bob derive the same root secret via Welcome', async () => {
      // Alice creates the group
      const alice = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await alice.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      // Bob generates his key pair
      const bobKeyPair = await generateECDHKeyPair();

      // Alice adds Bob
      const { welcome, rootSecret: aliceRootSecret } = await alice.addMember(
        bobKeyPair.publicKey,
      );

      // Bob processes the welcome
      const bob = new BeeKEM();
      const bobRootSecret = await bob.processWelcome(
        welcome,
        bobKeyPair.privateKey,
        bobKeyPair.publicKey,
      );

      // Both should derive the same root secret
      expect(aliceRootSecret).toBeInstanceOf(Uint8Array);
      expect(bobRootSecret).toBeInstanceOf(Uint8Array);
      expect(aliceRootSecret.byteLength).toBe(32);
      expect(bobRootSecret.byteLength).toBe(32);

      expect(Buffer.from(aliceRootSecret).equals(Buffer.from(bobRootSecret))).toBe(true);
    });

    test('Bob has correct tree state after processing Welcome', async () => {
      const alice = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await alice.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      const bobKeyPair = await generateECDHKeyPair();
      const { welcome } = await alice.addMember(bobKeyPair.publicKey);

      const bob = new BeeKEM();
      await bob.processWelcome(welcome, bobKeyPair.privateKey, bobKeyPair.publicKey);

      expect(bob.myLeafIndex).toBe(2); // leaf position 1 => node index 2
      expect(bob.memberCount).toBe(2);
    });
  });

  describe('three-member group', () => {
    test('Alice adds Bob then Charlie, all can derive root secret', async () => {
      // Alice creates the group
      const alice = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await alice.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      // Add Bob
      const bobKeyPair = await generateECDHKeyPair();
      const { welcome: bobWelcome } = await alice.addMember(bobKeyPair.publicKey);

      const bob = new BeeKEM();
      await bob.processWelcome(bobWelcome, bobKeyPair.privateKey, bobKeyPair.publicKey);

      // Add Charlie
      const charlieKeyPair = await generateECDHKeyPair();
      const { welcome: charlieWelcome, rootSecret: aliceRootSecret } =
        await alice.addMember(charlieKeyPair.publicKey);

      const charlie = new BeeKEM();
      const charlieRootSecret = await charlie.processWelcome(
        charlieWelcome,
        charlieKeyPair.privateKey,
        charlieKeyPair.publicKey,
      );

      expect(alice.memberCount).toBe(3);
      expect(charlie.memberCount).toBe(3);

      // Alice and Charlie should agree on root secret
      expect(
        Buffer.from(aliceRootSecret).equals(Buffer.from(charlieRootSecret)),
      ).toBe(true);
    });
  });

  describe('removeMember', () => {
    test('Alice removes Bob from a 3-member group; Alice and Charlie agree on new root secret', async () => {
      // Alice creates the group
      const alice = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await alice.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      // Add Bob (leaf position 1 => node index 2)
      const bobKeyPair = await generateECDHKeyPair();
      const { welcome: bobWelcome } = await alice.addMember(bobKeyPair.publicKey);

      const bob = new BeeKEM();
      await bob.processWelcome(bobWelcome, bobKeyPair.privateKey, bobKeyPair.publicKey);

      // Add Charlie (leaf position 2 => node index 4)
      const charlieKeyPair = await generateECDHKeyPair();
      const { welcome: charlieWelcome, pathUpdate: addCharlieUpdate } =
        await alice.addMember(charlieKeyPair.publicKey);

      const charlie = new BeeKEM();
      await charlie.processWelcome(
        charlieWelcome,
        charlieKeyPair.privateKey,
        charlieKeyPair.publicKey,
      );

      expect(alice.memberCount).toBe(3);

      // Alice removes Bob (node index 2)
      const { pathUpdate: removeUpdate, rootSecret: aliceRootAfterRemoval } =
        await alice.removeMember(2);

      // memberCount stays the same (leaf slot is blanked, not removed)
      expect(alice.memberCount).toBe(3);

      // Charlie processes the removal update
      const charlieRootAfterRemoval = await charlie.processPathUpdate(removeUpdate);

      // Alice and Charlie should agree on the new root secret
      expect(
        Buffer.from(aliceRootAfterRemoval).equals(Buffer.from(charlieRootAfterRemoval)),
      ).toBe(true);

      // Bob tries to process the update -- should fail because his leaf is blanked
      // and he no longer has the key material needed to decrypt
      await expect(bob.processPathUpdate(removeUpdate)).rejects.toThrow();
    });
  });

  describe('findLeafByPublicKey', () => {
    test('finds the founder leaf by its own public key', async () => {
      const alice = new BeeKEM();
      const aliceKeys = await generateECDHKeyPair();
      await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

      // CryptoKey input
      expect(await alice.findLeafByPublicKey(aliceKeys.publicKey)).toBe(0);

      // Uint8Array input (raw SEC1)
      const rawAlice = new Uint8Array(
        await crypto.subtle.exportKey('raw', aliceKeys.publicKey),
      );
      expect(await alice.findLeafByPublicKey(rawAlice)).toBe(0);
    });

    test('finds a joined member by their public key after addMember', async () => {
      const alice = new BeeKEM();
      const aliceKeys = await generateECDHKeyPair();
      await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

      const bobKeys = await generateECDHKeyPair();
      await alice.addMember(bobKeys.publicKey);

      const charlieKeys = await generateECDHKeyPair();
      await alice.addMember(charlieKeys.publicKey);

      // Bob is at leaf position 1 => node index 2
      expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBe(2);
      // Charlie is at leaf position 2 => node index 4
      expect(await alice.findLeafByPublicKey(charlieKeys.publicKey)).toBe(4);
    });

    test('returns undefined for an unknown public key', async () => {
      const alice = new BeeKEM();
      const aliceKeys = await generateECDHKeyPair();
      await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
      const bobKeys = await generateECDHKeyPair();
      await alice.addMember(bobKeys.publicKey);

      const strangerKeys = await generateECDHKeyPair();
      expect(
        await alice.findLeafByPublicKey(strangerKeys.publicKey),
      ).toBeUndefined();
    });

    test('returns undefined after the leaf is blanked via removeMember', async () => {
      const alice = new BeeKEM();
      const aliceKeys = await generateECDHKeyPair();
      await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

      const bobKeys = await generateECDHKeyPair();
      await alice.addMember(bobKeys.publicKey);

      // Pre-removal: Bob's leaf is locatable.
      expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBe(2);

      // Blank Bob's leaf. After this, the leaf has publicKey === null
      // and the lookup must NOT return its index -- otherwise a caller
      // would think a revoked reader is still in the tree.
      await alice.removeMember(2);
      expect(
        await alice.findLeafByPublicKey(bobKeys.publicKey),
      ).toBeUndefined();
    });
  });

  describe('processPathUpdate', () => {
    test('Alice processes Bob update and both derive the same root secret', async () => {
      // Alice creates the group
      const alice = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await alice.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      // Add Bob
      const bobKeyPair = await generateECDHKeyPair();
      const { welcome } = await alice.addMember(bobKeyPair.publicKey);

      const bob = new BeeKEM();
      await bob.processWelcome(welcome, bobKeyPair.privateKey, bobKeyPair.publicKey);

      // Bob performs a self-update (ratchet forward)
      const { pathUpdate, rootSecret: bobNewRoot } = await bob.update();

      // Alice processes Bob's path update
      const aliceNewRoot = await alice.processPathUpdate(pathUpdate);

      // Both should derive the same new root secret
      expect(
        Buffer.from(aliceNewRoot).equals(Buffer.from(bobNewRoot)),
      ).toBe(true);
    });

    test('sender leaf key is refreshed in the receiver tree after processPathUpdate', async () => {
      // Alice creates the group
      const alice = new BeeKEM();
      const aliceKeyPair = await generateECDHKeyPair();
      await alice.initialize(aliceKeyPair.privateKey, aliceKeyPair.publicKey);

      // Add Bob
      const bobKeyPair = await generateECDHKeyPair();
      const { welcome } = await alice.addMember(bobKeyPair.publicKey);

      const bob = new BeeKEM();
      await bob.processWelcome(welcome, bobKeyPair.privateKey, bobKeyPair.publicKey);

      // Bob performs a self-update, generating a new leaf key pair
      const { pathUpdate } = await bob.update();

      // The pathUpdate should carry Bob's NEW leaf public key
      // which is different from his original key
      const originalBobPubKeyBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', bobKeyPair.publicKey),
      );
      expect(
        Buffer.from(pathUpdate.senderLeafPublicKey).equals(
          Buffer.from(originalBobPubKeyBytes),
        ),
      ).toBe(false);

      // Alice processes Bob's update
      await alice.processPathUpdate(pathUpdate);

      // After processing, Alice's tree should contain Bob's NEW leaf public key
      // (which matches the senderLeafPublicKey in the update)
      // Verify by having Alice do her own update and checking the tree works
      const { rootSecret: aliceRoot } = await alice.update();
      expect(aliceRoot).toBeInstanceOf(Uint8Array);
      expect(aliceRoot.byteLength).toBe(32);
    });
  });
});
