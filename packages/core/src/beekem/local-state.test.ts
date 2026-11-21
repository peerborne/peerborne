import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { BeeKEM } from './beekem.js';
import { generateEciesKeyPair } from '../ecies.js';
import {
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMLocalRecovery,
} from '../beekem-welcome-wire.js';

function sameSecret(actual: Uint8Array, expected: Uint8Array): void {
  expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
}

async function members() {
  const founderKeys = await generateEciesKeyPair();
  const founder = new BeeKEM();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
  const bobKeys = await generateEciesKeyPair();
  const bob = new BeeKEM();
  const addedBob = await founder.addMember(bobKeys.publicKey);
  await bob.processWelcome(
    addedBob.welcome,
    bobKeys.privateKey,
    bobKeys.publicKey,
  );
  const carolKeys = await generateEciesKeyPair();
  const addedCarol = await founder.addMember(carolKeys.publicKey);
  await bob.processPathUpdate(addedCarol.pathUpdate);
  return { founder, founderKeys, bob, bobKeys, addedCarol };
}

describe('authenticated local BeeKEM recovery', () => {
  test('restores a single-member tree with its non-extractable persistent identity', async () => {
    const keys = await generateEciesKeyPair();
    const original = new BeeKEM();
    await original.initialize(keys.privateKey, keys.publicKey);
    const state = await original.exportLocalState(keys.publicKey);
    expect(state.sealedLeafPrivateKey).toBeNull();
    const restored = new BeeKEM();
    await restored.restoreLocalState(state, keys);
    expect(restored.generation).toBe(0);
    sameSecret(await restored.getRootSecret(), await original.getRootSecret());
  });

  test('retains the accepted update digest and rejects local recovery as a network Welcome', async () => {
    const { bob, bobKeys, addedCarol } = await members();
    const state = await bob.exportLocalState(bobKeys.publicKey);
    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire(
        serializeBeeKEMLocalRecovery(state.welcome!),
      ),
    ).toThrow(/appended rightmost leaf/);
    const restored = new BeeKEM();
    await restored.restoreLocalState(state, bobKeys);
    const disposition = await restored.processPathUpdateTransactionally(
      addedCarol.pathUpdate,
      async (_root, result) => result,
    );
    expect(disposition).toBe('duplicate');
    expect(restored.generation).toBe(bob.generation);
    sameSecret(await restored.getRootSecret(), await bob.getRootSecret());
  });

  test('seals rotated local leaf keys to the persistent identity and restores them', async () => {
    const { bob, bobKeys, addedCarol } = await members();
    await bob.removeMember(addedCarol.welcome.leafIndex);
    const state = await bob.exportLocalState(bobKeys.publicKey);
    expect(state.sealedLeafPrivateKey !== null).toBe(true);
    const restored = new BeeKEM();
    await restored.restoreLocalState(state, bobKeys);
    sameSecret(await restored.getRootSecret(), await bob.getRootSecret());
    expect(restored.generation).toBe(bob.generation);
  });

  test('failed recovery leaves a fresh tree unchanged and accepts a later valid checkpoint', async () => {
    const { bob, bobKeys } = await members();
    const state = await bob.exportLocalState(bobKeys.publicKey);
    const other = await generateEciesKeyPair();
    const candidate = new BeeKEM();
    await expect(candidate.restoreLocalState(state, other)).rejects.toThrow();
    expect(candidate.memberCount).toBe(0);
    expect(candidate.generation).toBeNull();
    await candidate.restoreLocalState(state, bobKeys);
    sameSecret(await candidate.getRootSecret(), await bob.getRootSecret());
    await expect(candidate.restoreLocalState(state, bobKeys)).rejects.toThrow(
      /fresh/,
    );
    sameSecret(await candidate.getRootSecret(), await bob.getRootSecret());
  });

  test('captures caller-owned recovery bytes before waiting for cryptography', async () => {
    const { bob, bobKeys } = await members();
    const state = await bob.exportLocalState(bobKeys.publicKey);
    const restored = new BeeKEM();
    const restore = restored.restoreLocalState(state, bobKeys);
    state.leafPublicKey.fill(0);
    state.welcome!.treeHash.fill(0);
    state.welcome!.pathKeys[0].encryptedPrivateKey.fill(0);
    await restore;
    sameSecret(await restored.getRootSecret(), await bob.getRootSecret());
  });

  test('keeps a revoked leaf excluded when survivors restart and rotate again', async () => {
    const restart = async (current: BeeKEM, keys: CryptoKeyPair) => {
      const next = new BeeKEM();
      await next.restoreLocalState(
        await current.exportLocalState(keys.publicKey),
        keys,
      );
      return next;
    };
    await fc.assert(
      fc.asyncProperty(
        fc
          .integer({ min: 1, max: 4 })
          .chain((count) =>
            fc.tuple(
              fc.constant(count),
              fc.integer({ min: 0, max: count - 1 }),
            ),
          ),
        fc.boolean(),
        async ([count, removedIndex], restartBeforeRemoval) => {
          const founderKeys = await generateEciesKeyPair();
          let founder = new BeeKEM();
          await founder.initialize(
            founderKeys.privateKey,
            founderKeys.publicKey,
          );
          const readers: Array<{ tree: BeeKEM; keys: CryptoKeyPair }> = [];
          for (let index = 0; index < count; index++) {
            const keys = await generateEciesKeyPair();
            const { pathUpdate, welcome } = await founder.addMember(
              keys.publicKey,
            );
            for (const reader of readers)
              await reader.tree.processPathUpdate(pathUpdate);
            const tree = new BeeKEM();
            await tree.processWelcome(welcome, keys.privateKey, keys.publicKey);
            readers.push({ keys, tree });
          }
          if (restartBeforeRemoval)
            founder = await restart(founder, founderKeys);
          const removed = readers[removedIndex];
          const revokedGeneration = removed.tree.generation;
          const leaf = removed.tree.myLeafIndex;
          const { pathUpdate, rootSecret } = await founder.removeMember(leaf);
          const revokedRestart = await restart(removed.tree, removed.keys);
          await expect(
            revokedRestart.processPathUpdate(pathUpdate),
          ).rejects.toThrow(/local member was removed/);
          expect(revokedRestart.generation).toBe(revokedGeneration);

          const surviving: BeeKEM[] = [];
          for (const reader of readers) {
            if (reader === removed) continue;
            sameSecret(
              await reader.tree.processPathUpdate(pathUpdate),
              rootSecret,
            );
            surviving.push(await restart(reader.tree, reader.keys));
          }
          const restored = await restart(founder, founderKeys);
          sameSecret(await restored.getRootSecret(), rootSecret);
          const next = await restored.update();
          expect(
            next.pathUpdate.treeNodePublicKeys.find(
              (entry) => entry.nodeIndex === leaf,
            )?.publicKey ?? null,
          ).toBeNull();
          for (const reader of surviving) {
            sameSecret(
              await reader.processPathUpdate(next.pathUpdate),
              next.rootSecret,
            );
          }
        },
      ),
      {
        seed: 20261120,
        numRuns: 12,
        examples: [
          [[4, 1], true],
          [[1, 0], false],
        ],
      },
    );
  });
});
