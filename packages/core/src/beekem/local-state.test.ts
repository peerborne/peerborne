import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { BeeKEM, BeeKEMCompetingEpochError } from './beekem.js';
import { generateEciesKeyPair } from '../ecies.js';
import {
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMLocalRecovery,
} from '../beekem-welcome-wire.js';

function sameSecret(actual: Uint8Array, expected: Uint8Array): void {
  expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
}

async function restartTree(tree: BeeKEM, keys: CryptoKeyPair): Promise<BeeKEM> {
  const restarted = new BeeKEM();
  await restarted.restoreLocalState(
    await tree.exportLocalState(keys.publicKey),
    keys,
  );
  return restarted;
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
    expect(state.lastAppliedParentTreeHash).toBeNull();
    const restored = new BeeKEM();
    await restored.restoreLocalState(state, keys);
    expect(restored.generation).toBe(0);
    sameSecret(await restored.getRootSecret(), await original.getRootSecret());
  });

  test('continues single-member rotations at the saved generation across restarts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.boolean(), { minLength: 1, maxLength: 5 }),
        async (restartSchedule) => {
          const keys = await generateEciesKeyPair();
          let tree = new BeeKEM();
          await tree.initialize(keys.privateKey, keys.publicKey);
          for (const [index, restart] of restartSchedule.entries()) {
            const { pathUpdate, rootSecret } = await tree.update();
            const state = await tree.exportLocalState(keys.publicKey);
            expect(state.generation).toBe(index + 1);
            expect(state.welcome).toBeNull();
            expect(state.lastAppliedUpdateDigest).toBeNull();
            expect(state.lastAppliedParentTreeHash).toEqual(
              pathUpdate.parentTreeHash,
            );
            if (restart || index === restartSchedule.length - 1) {
              const fresh = new BeeKEM();
              await fresh.restoreLocalState(state, keys);
              expect(fresh.generation).toBe(state.generation);
              expect(
                (await fresh.exportLocalState(keys.publicKey))
                  .lastAppliedParentTreeHash,
              ).toEqual(state.lastAppliedParentTreeHash);
              sameSecret(await fresh.getRootSecret(), rootSecret);
              tree = fresh;
            }
          }
          const previous = await tree.exportLocalState(keys.publicKey);
          const { pathUpdate } = await tree.update();
          expect(pathUpdate.generation).toBe(previous.generation + 1);
        },
      ),
      { seed: 20261121, numRuns: 12, examples: [[[true, false, true]]] },
    );
  });

  test('leaves a fresh tree unchanged when checkpoint generation metadata disagrees', async () => {
    const keys = await generateEciesKeyPair();
    const single = new BeeKEM();
    await single.initialize(keys.privateKey, keys.publicKey);
    const state = await single.exportLocalState(keys.publicKey);
    const candidate = new BeeKEM();
    await expect(
      candidate.restoreLocalState({ ...state, generation: 0x100000000 }, keys),
    ).rejects.toThrow(/checkpoint generation/);
    await expect(
      candidate.restoreLocalState({ ...state, generation: 1 }, keys),
    ).rejects.toThrow(/parent tree hash/);

    const { bob, bobKeys } = await members();
    const shared = await bob.exportLocalState(bobKeys.publicKey);
    await expect(
      candidate.restoreLocalState(
        { ...state, lastAppliedUpdateDigest: shared.lastAppliedUpdateDigest },
        keys,
      ),
    ).rejects.toThrow(/Single-member BeeKEM state has a replay digest/);
    await expect(
      candidate.restoreLocalState(
        { ...state, lastAppliedParentTreeHash: shared.lastAppliedParentTreeHash },
        keys,
      ),
    ).rejects.toThrow(/parent tree hash/);
    await expect(
      candidate.restoreLocalState(
        { ...shared, generation: shared.generation + 1 },
        bobKeys,
      ),
    ).rejects.toThrow(/does not match its Welcome/);
    await expect(
      candidate.restoreLocalState(
        { ...shared, lastAppliedParentTreeHash: null },
        bobKeys,
      ),
    ).rejects.toThrow(/replay digest requires an accepted parent/);
    expect(candidate.generation).toBeNull();
    await candidate.restoreLocalState(shared, bobKeys);
    expect(candidate.generation).toBe(shared.generation);
  });

  test('retains the accepted update digest and rejects local recovery as a network Welcome', async () => {
    const { bob, bobKeys, addedCarol } = await members();
    const state = await bob.exportLocalState(bobKeys.publicKey);
    expect(state.lastAppliedParentTreeHash).toEqual(
      addedCarol.pathUpdate.parentTreeHash,
    );
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

  test('recognizes independent successors from the same parent across two-member restart schedules', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 15 }),
        async (restartMask) => {
          const founderKeys = await generateEciesKeyPair();
          const memberKeys = await generateEciesKeyPair();
          let founder = new BeeKEM();
          let member = new BeeKEM();
          await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
          const { welcome } = await founder.addMember(memberKeys.publicKey);
          await member.processWelcome(
            welcome,
            memberKeys.privateKey,
            memberKeys.publicKey,
          );
          if (restartMask & 1) founder = await restartTree(founder, founderKeys);
          if (restartMask & 2) member = await restartTree(member, memberKeys);

          const following = member.clone();
          const [founderEpoch, memberEpoch] = await Promise.all([
            founder.update(),
            member.update(),
          ]);
          expect(founderEpoch.pathUpdate.parentTreeHash).toEqual(
            memberEpoch.pathUpdate.parentTreeHash,
          );
          expect(founderEpoch.pathUpdate.treeHash).not.toEqual(
            memberEpoch.pathUpdate.treeHash,
          );
          if (restartMask & 4) founder = await restartTree(founder, founderKeys);
          if (restartMask & 8) member = await restartTree(member, memberKeys);

          await expect(
            founder.processPathUpdate(memberEpoch.pathUpdate),
          ).rejects.toBeInstanceOf(BeeKEMCompetingEpochError);
          await expect(
            member.processPathUpdate(founderEpoch.pathUpdate),
          ).rejects.toBeInstanceOf(BeeKEMCompetingEpochError);
          expect(founder.generation).toBe(founderEpoch.pathUpdate.generation);
          expect(member.generation).toBe(memberEpoch.pathUpdate.generation);
          sameSecret(await founder.getRootSecret(), founderEpoch.rootSecret);
          sameSecret(await member.getRootSecret(), memberEpoch.rootSecret);

          sameSecret(
            await following.processPathUpdate(founderEpoch.pathUpdate),
            founderEpoch.rootSecret,
          );
          const restartedFollower = await restartTree(following, memberKeys);
          const redelivery =
            await restartedFollower.processPathUpdateTransactionally(
              founderEpoch.pathUpdate,
              async (_root, disposition) => disposition,
            );
          expect(redelivery).toBe('duplicate');
          expect(restartedFollower.generation).toBe(
            founderEpoch.pathUpdate.generation,
          );
        },
      ),
      { seed: 20261121, numRuns: 16, examples: [[0], [15]] },
    );
  });

  test('distinguishes a second device revocation on the same leaf from self-redelivery', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        fc.boolean(),
        async (restartFirst, restartSecond) => {
          const founderKeys = await generateEciesKeyPair();
          const memberKeys = await generateEciesKeyPair();
          let first = new BeeKEM();
          await first.initialize(founderKeys.privateKey, founderKeys.publicKey);
          const { welcome } = await first.addMember(memberKeys.publicKey);
          const base = first.clone();
          let second = first.clone();
          const [firstEpoch, secondEpoch] = await Promise.all([
            first.removeMember(welcome.leafIndex),
            second.removeMember(welcome.leafIndex),
          ]);
          if (restartFirst) first = await restartTree(first, founderKeys);
          if (restartSecond) second = await restartTree(second, founderKeys);

          await expect(
            base.processPathUpdate(firstEpoch.pathUpdate),
          ).rejects.toThrow(/our own/);
          await expect(
            first.processPathUpdate(firstEpoch.pathUpdate),
          ).rejects.toThrow(/our own/);
          await expect(
            first.processPathUpdate(secondEpoch.pathUpdate),
          ).rejects.toBeInstanceOf(BeeKEMCompetingEpochError);
          await expect(
            second.processPathUpdate(firstEpoch.pathUpdate),
          ).rejects.toBeInstanceOf(BeeKEMCompetingEpochError);
          sameSecret(await first.getRootSecret(), firstEpoch.rootSecret);
          sameSecret(await second.getRootSecret(), secondEpoch.rootSecret);
        },
      ),
      { seed: 20261121, numRuns: 4, examples: [[false, false], [true, true]] },
    );
  });

  test('keeps a revoked leaf excluded when survivors restart and rotate again', async () => {
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
            founder = await restartTree(founder, founderKeys);
          const removed = readers[removedIndex];
          const revokedGeneration = removed.tree.generation;
          const leaf = removed.tree.myLeafIndex;
          const { pathUpdate, rootSecret } = await founder.removeMember(leaf);
          const revokedRestart = await restartTree(removed.tree, removed.keys);
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
            surviving.push(await restartTree(reader.tree, reader.keys));
          }
          const restored = await restartTree(founder, founderKeys);
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
