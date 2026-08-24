import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

describe('BeeKEM branch coverage', () => {
  describe('getRootSecret', () => {
    test('throws on empty tree (line 420)', async () => {
      const beekem = new BeeKEM();
      await expect(beekem.getRootSecret()).rejects.toThrow('Tree is empty');
    });
  });

  describe('update single-member (lines 573-574)', () => {
    test('returns empty nodes array', async () => {
      const beekem = new BeeKEM();
      const keys = await generateKeyPair();
      await beekem.initialize(keys.privateKey, keys.publicKey);
      const { pathUpdate, rootSecret } = await beekem.update();
      expect(pathUpdate.nodes).toHaveLength(0);
      expect(rootSecret).toBeInstanceOf(Uint8Array);
      expect(rootSecret.byteLength).toBe(32);
    });
  });

  describe('processWelcome', () => {
    test('tree hash mismatch throws (line 406)', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);
      const newKeys = await generateKeyPair();
      const { welcome } = await founder.addMember(newKeys.publicKey);
      const tampered = { ...welcome, treeHash: new Uint8Array(32).fill(0xff) };
      const newBee = new BeeKEM();
      await expect(
        newBee.processWelcome(tampered, newKeys.privateKey, newKeys.publicKey),
      ).rejects.toThrow('tree hash mismatch');
    });

    test('null public key entries from blanked nodes (lines 392-396, 704)', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);

      const bKeys = await generateKeyPair();
      const { welcome: bWelcome } = await founder.addMember(bKeys.publicKey);
      const bob = new BeeKEM();
      await bob.processWelcome(bWelcome, bKeys.privateKey, bKeys.publicKey);

      await founder.removeMember(2);

      const cKeys = await generateKeyPair();
      const { welcome } = await founder.addMember(cKeys.publicKey);
      const charlie = new BeeKEM();
      await charlie.processWelcome(welcome, cKeys.privateKey, cKeys.publicKey);

      const rootSecret = await charlie.getRootSecret();
      expect(rootSecret).toBeInstanceOf(Uint8Array);

      const bobLeaf = await charlie.findLeafByPublicKey(bKeys.publicKey);
      expect(bobLeaf).toBeUndefined();
    });
  });

  describe('processPathUpdate', () => {
    test('no intersection on uninitialized tree (line 228)', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);
      const bKeys = await generateKeyPair();
      const { pathUpdate } = await founder.addMember(bKeys.publicKey);
      const empty = new BeeKEM();
      await expect(empty.processPathUpdate(pathUpdate)).rejects.toThrow();
    });

    
  });

  describe('compact', () => {
    test('empty tree no-op (line 537)', () => {
      const beekem = new BeeKEM();
      expect(() => beekem.compact()).not.toThrow();
    });

    test('collects blanked leaves after removal (lines 525-546)', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);

      await founder.addMember((await generateKeyPair()).publicKey);
      await founder.addMember((await generateKeyPair()).publicKey);

      await founder.removeMember(2);
      expect(() => founder.compact()).not.toThrow();
      const rootSecret = await founder.getRootSecret();
      expect(rootSecret).toBeInstanceOf(Uint8Array);
    });
  });

  describe('key agreement', () => {
    test('last member agrees with founder at same tree size', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);

      await founder.addMember((await generateKeyPair()).publicKey);

      const cKeys = await generateKeyPair();
      const { welcome } = await founder.addMember(cKeys.publicKey);
      const charlie = new BeeKEM();
      await charlie.processWelcome(welcome, cKeys.privateKey, cKeys.publicKey);

      const fRoot = await founder.getRootSecret();
      const cRoot = await charlie.getRootSecret();
      expect(Buffer.from(fRoot).equals(Buffer.from(cRoot))).toBe(true);
    });

    test('last member agrees with founder after founder update', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);

      await founder.addMember((await generateKeyPair()).publicKey);

      const cKeys = await generateKeyPair();
      const { welcome } = await founder.addMember(cKeys.publicKey);
      const charlie = new BeeKEM();
      await charlie.processWelcome(welcome, cKeys.privateKey, cKeys.publicKey);

      const { pathUpdate, rootSecret: newRoot } = await founder.update();
      const charlieRoot = await charlie.processPathUpdate(pathUpdate);
      expect(Buffer.from(charlieRoot).equals(Buffer.from(newRoot))).toBe(true);
    });

    test('surviving last member agrees after founder removes someone', async () => {
      const founder = new BeeKEM();
      const fKeys = await generateKeyPair();
      await founder.initialize(fKeys.privateKey, fKeys.publicKey);

      await founder.addMember((await generateKeyPair()).publicKey);

      const cKeys = await generateKeyPair();
      const { welcome } = await founder.addMember(cKeys.publicKey);
      const charlie = new BeeKEM();
      await charlie.processWelcome(welcome, cKeys.privateKey, cKeys.publicKey);

      const { pathUpdate, rootSecret: founderRoot } = await founder.removeMember(2);
      const charlieRoot = await charlie.processPathUpdate(pathUpdate);
      expect(Buffer.from(charlieRoot).equals(Buffer.from(founderRoot))).toBe(true);
    });
  });
});