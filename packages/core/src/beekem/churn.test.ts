import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import {
  BeeKEMWelcomeV2,
  PathUpdateV2,
  TreeNode,
  WelcomeNodePublicKey,
} from './types.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function expectSameSecret(actual: Uint8Array, expected: Uint8Array): void {
  expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
}

function withDuplicateLeafPublicKey(
  entries: WelcomeNodePublicKey[],
  sourceLeafIndex: number,
  targetLeafIndex: number,
): WelcomeNodePublicKey[] {
  const sourcePublicKey = entries.find(
    entry => entry.nodeIndex === sourceLeafIndex,
  )?.publicKey;
  if (sourcePublicKey === null || sourcePublicKey === undefined) {
    throw new Error('test fixture is missing its source leaf public key');
  }
  return entries.map(entry => ({
    nodeIndex: entry.nodeIndex,
    publicKey:
      entry.nodeIndex === targetLeafIndex
        ? new Uint8Array(sourcePublicKey)
        : entry.publicKey === null
          ? null
          : new Uint8Array(entry.publicKey),
  }));
}

describe('BeeKEM multi-member churn', () => {
  test('rejects a KEM public key already used by any live leaf', async () => {
    const founder = new BeeKEM();
    const founderKeys = await keyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);

    await expect(founder.addMember(founderKeys.publicKey)).rejects.toThrow(
      /KEM public key already belongs to a live BeeKEM leaf/,
    );
    expect(founder.memberCount).toBe(1);
    expect(founder.generation).toBe(0);

    const bobKeys = await keyPair();
    await founder.addMember(bobKeys.publicKey);
    await expect(founder.addMember(bobKeys.publicKey)).rejects.toThrow(
      /KEM public key already belongs to a live BeeKEM leaf/,
    );
    expect(founder.memberCount).toBe(2);
    expect(founder.generation).toBe(1);
  });

  test('rejects a v2 Welcome containing duplicate live leaf public keys', async () => {
    const founder = new BeeKEM();
    const founderKeys = await keyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const bobKeys = await keyPair();
    await founder.addMember(bobKeys.publicKey);
    const carolKeys = await keyPair();
    const { welcome } = await founder.addMember(carolKeys.publicKey);
    const duplicateLeafWelcome: BeeKEMWelcomeV2 = {
      ...welcome,
      treeNodePublicKeys: withDuplicateLeafPublicKey(
        welcome.treeNodePublicKeys,
        0,
        2,
      ),
    };
    const carol = new BeeKEM();

    await expect(
      carol.processWelcome(
        duplicateLeafWelcome,
        carolKeys.privateKey,
        carolKeys.publicKey,
      ),
    ).rejects.toThrow(/duplicate live leaf public keys/);
    expect(carol.memberCount).toBe(0);
    expect(carol.generation).toBeNull();
  });

  test('rejects a v2 Welcome that omits a non-blank direct-path key', async () => {
    const founder = new BeeKEM();
    const founderKeys = await keyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);

    const bobKeys = await keyPair();
    const { welcome: bobWelcome } = await founder.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const carolKeys = await keyPair();
    const { pathUpdate: addCarol, welcome: carolWelcome } =
      await founder.addMember(carolKeys.publicKey);
    await bob.processPathUpdate(addCarol);
    const carol = new BeeKEM();
    await carol.processWelcome(
      carolWelcome,
      carolKeys.privateKey,
      carolKeys.publicKey,
    );

    const daveKeys = await keyPair();
    const { welcome } = await carol.addMember(daveKeys.publicKey);
    const [omitted, ...remainingPath] = welcome.pathKeys;
    if (omitted === undefined || remainingPath.length === 0) {
      throw new Error('test fixture requires at least two Welcome path keys');
    }
    const malformed: BeeKEMWelcomeV2 = {
      ...welcome,
      pathKeys: remainingPath,
      treeNodePublicKeys: [
        ...welcome.treeNodePublicKeys,
        {
          nodeIndex: omitted.nodeIndex,
          publicKey: new Uint8Array(omitted.publicKey),
        },
      ],
    };
    const dave = new BeeKEM();

    await expect(
      dave.processWelcome(
        malformed,
        daveKeys.privateKey,
        daveKeys.publicKey,
      ),
    ).rejects.toThrow(/omitted direct-path nodes must be blank/);
    expect(dave.memberCount).toBe(0);
    expect(dave.generation).toBeNull();
  });

  test('rejects a v2 PathUpdate containing duplicate live leaf public keys', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome: bobWelcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );
    const carolKeys = await keyPair();
    const { pathUpdate: addCarol } = await alice.addMember(
      carolKeys.publicKey,
    );
    await bob.processPathUpdate(addCarol);
    const { pathUpdate } = await alice.update();
    const duplicateLeafUpdate: PathUpdateV2 = {
      ...pathUpdate,
      treeNodePublicKeys: withDuplicateLeafPublicKey(
        pathUpdate.treeNodePublicKeys,
        0,
        2,
      ),
    };
    const generationBefore = bob.generation;
    const rootBefore = await bob.getRootSecret();

    await expect(
      bob.processPathUpdate(duplicateLeafUpdate),
    ).rejects.toThrow(/duplicate live leaf public keys/);
    expect(bob.generation).toBe(generationBefore);
    expectSameSecret(await bob.getRootSecret(), rootBefore);
  });

  test('Bob applies an add followed by removal in parent-bound order', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await keyPair();
    const { welcome: bobWelcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const carolKeys = await keyPair();
    const { pathUpdate: addCarol, welcome: carolWelcome } =
      await alice.addMember(carolKeys.publicKey);
    const carol = new BeeKEM();
    await carol.processWelcome(
      carolWelcome,
      carolKeys.privateKey,
      carolKeys.publicKey,
    );

    await bob.processPathUpdate(addCarol);
    const { pathUpdate: removeCarol, rootSecret: aliceRoot } =
      await alice.removeMember(carolWelcome.leafIndex);
    const bobRoot = await bob.processPathUpdate(removeCarol);
    expectSameSecret(bobRoot, aliceRoot);
    await expect(carol.processPathUpdate(removeCarol)).rejects.toThrow(
      /removed/,
    );
    await expect(bob.processPathUpdate(addCarol)).rejects.toThrow(/stale/);
  });

  test('all survivors converge through ordered add/remove churn', async () => {
    const founder = new BeeKEM();
    const founderKeys = await keyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const survivors: BeeKEM[] = [];

    while (survivors.length < 3) {
      const keys = await keyPair();
      const { pathUpdate, welcome } = await founder.addMember(keys.publicKey);
      for (const survivor of survivors) {
        await survivor.processPathUpdate(pathUpdate);
      }
      const survivor = new BeeKEM();
      await survivor.processWelcome(welcome, keys.privateKey, keys.publicKey);
      survivors.push(survivor);
    }
    const removedKeys = await keyPair();
    const { pathUpdate: missedAdd, welcome: removedWelcome } =
      await founder.addMember(removedKeys.publicKey);
    const removed = new BeeKEM();
    await removed.processWelcome(
      removedWelcome,
      removedKeys.privateKey,
      removedKeys.publicKey,
    );
    for (const survivor of survivors) {
      await survivor.processPathUpdate(missedAdd);
    }

    const { pathUpdate: removal, rootSecret } = await founder.removeMember(
      removedWelcome.leafIndex,
    );
    for (const survivor of survivors) {
      expectSameSecret(await survivor.processPathUpdate(removal), rootSecret);
    }
    await expect(removed.processPathUpdate(removal)).rejects.toThrow(/removed/);
  });

  test('rejects skipped generations instead of accepting a self-contained snapshot', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome: bobWelcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const carolKeys = await keyPair();
    const { welcome: carolWelcome } = await alice.addMember(carolKeys.publicKey);
    const { pathUpdate: removal } = await alice.removeMember(
      carolWelcome.leafIndex,
    );

    await expect(bob.processPathUpdate(removal)).rejects.toThrow(
      /Cannot skip BeeKEM generations/,
    );
    expect(bob.generation).toBe(bobWelcome.generation);
  });

  test('rejects a higher-generation stale fork that would re-include a revoked member', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome: bobWelcome } = await alice.addMember(bobKeys.publicKey);
    const bobCurrent = new BeeKEM();
    const bobStale = new BeeKEM();
    await bobCurrent.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );
    await bobStale.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const revokedKeys = await keyPair();
    const { pathUpdate: addRevoked, welcome: revokedWelcome } =
      await alice.addMember(revokedKeys.publicKey);
    await bobCurrent.processPathUpdate(addRevoked);
    await bobStale.processPathUpdate(addRevoked);
    const revoked = new BeeKEM();
    await revoked.processWelcome(
      revokedWelcome,
      revokedKeys.privateKey,
      revokedKeys.publicKey,
    );

    const { pathUpdate: authoritativeRemoval } = await alice.removeMember(
      revokedWelcome.leafIndex,
    );
    await bobCurrent.processPathUpdate(authoritativeRemoval);
    await expect(revoked.processPathUpdate(authoritativeRemoval)).rejects.toThrow(
      /removed/,
    );

    const { pathUpdate: firstForkUpdate } = await bobStale.update();
    const { pathUpdate: higherForkUpdate } = await bobStale.update();
    await revoked.processPathUpdate(firstForkUpdate);
    await revoked.processPathUpdate(higherForkUpdate);

    await expect(alice.processPathUpdate(higherForkUpdate)).rejects.toThrow(
      /parent tree hash mismatch/,
    );
  });

  test('preserves unchanged lower private-path keys across alternating senders', async () => {
    const founder = new BeeKEM();
    const founderKeys = await keyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);

    const bobKeys = await keyPair();
    const { welcome: bobWelcome } = await founder.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const carolKeys = await keyPair();
    const { pathUpdate: addCarol, welcome: carolWelcome } =
      await founder.addMember(carolKeys.publicKey);
    await bob.processPathUpdate(addCarol);
    const carol = new BeeKEM();
    await carol.processWelcome(
      carolWelcome,
      carolKeys.privateKey,
      carolKeys.publicKey,
    );

    const daveKeys = await keyPair();
    const { pathUpdate: addDave, welcome: daveWelcome } =
      await founder.addMember(daveKeys.publicKey);
    await bob.processPathUpdate(addDave);
    await carol.processPathUpdate(addDave);
    const dave = new BeeKEM();
    await dave.processWelcome(
      daveWelcome,
      daveKeys.privateKey,
      daveKeys.publicKey,
    );

    const carolUpdate = await carol.update();
    expectSameSecret(
      await bob.processPathUpdate(carolUpdate.pathUpdate),
      carolUpdate.rootSecret,
    );
    await dave.processPathUpdate(carolUpdate.pathUpdate);

    const daveUpdate = await dave.update();
    expectSameSecret(
      await bob.processPathUpdate(daveUpdate.pathUpdate),
      daveUpdate.rootSecret,
    );
  });

  test('an appended member remains live below a subtree key unknown to the inviter', async () => {
    const founder = new BeeKEM();
    const founderKeys = await keyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const members: BeeKEM[] = [founder];

    while (members.length < 7) {
      const keys = await keyPair();
      const { pathUpdate, welcome } = await founder.addMember(keys.publicKey);
      for (const member of members.slice(1)) {
        await member.processPathUpdate(pathUpdate);
      }
      const member = new BeeKEM();
      await member.processWelcome(welcome, keys.privateKey, keys.publicKey);
      members.push(member);
    }

    // Leaf 12 populates node 11. The founder learns its public key through the
    // snapshot but, being outside that subtree, does not hold its private key.
    const rightSubtreeMember = members.at(-1)!;
    const rightSubtreeUpdate = await rightSubtreeMember.update();
    for (const member of members) {
      if (member !== rightSubtreeMember) {
        await member.processPathUpdate(rightSubtreeUpdate.pathUpdate);
      }
    }

    const newcomerKeys = await keyPair();
    const { pathUpdate: addNewcomer, welcome: newcomerWelcome } =
      await founder.addMember(newcomerKeys.publicKey);
    for (const member of members.slice(1)) {
      await member.processPathUpdate(addNewcomer);
    }
    const newcomer = new BeeKEM();
    await newcomer.processWelcome(
      newcomerWelcome,
      newcomerKeys.privateKey,
      newcomerKeys.publicKey,
    );
    members.push(newcomer);

    const nextFounderUpdate = await founder.update();
    for (const member of members.slice(1)) {
      expectSameSecret(
        await member.processPathUpdate(nextFounderUpdate.pathUpdate),
        nextFounderUpdate.rootSecret,
      );
    }
  });

  test.each([3, 4, 5])(
    'every survivor in a %i-member tree converges and the removed member cannot',
    async (memberCount) => {
      const founder = new BeeKEM();
      const founderKeys = await keyPair();
      await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
      const members: Array<{
        beekem: BeeKEM;
        keys: CryptoKeyPair;
        leafIndex: number;
      }> = [{ beekem: founder, keys: founderKeys, leafIndex: 0 }];

      while (members.length < memberCount) {
        const keys = await keyPair();
        const { pathUpdate, welcome } = await founder.addMember(keys.publicKey);
        for (const member of members.slice(1)) {
          await member.beekem.processPathUpdate(pathUpdate);
        }
        const beekem = new BeeKEM();
        await beekem.processWelcome(welcome, keys.privateKey, keys.publicKey);
        members.push({ beekem, keys, leafIndex: welcome.leafIndex });
      }

      const removed = members.at(-1)!;
      const { pathUpdate, rootSecret } = await founder.removeMember(
        removed.leafIndex,
      );
      for (const survivor of members.slice(1, -1)) {
        expectSameSecret(
          await survivor.beekem.processPathUpdate(pathUpdate),
          rootSecret,
        );
      }
      await expect(removed.beekem.processPathUpdate(pathUpdate)).rejects.toThrow(
        /removed/,
      );
    },
  );

  test('duplicate delivery is idempotent and stale/conflicting generations fail closed', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);

    const { pathUpdate, rootSecret } = await alice.update();
    expectSameSecret(await bob.processPathUpdate(pathUpdate), rootSecret);
    expectSameSecret(await bob.processPathUpdate(pathUpdate), rootSecret);

    const conflicting: PathUpdateV2 = {
      ...pathUpdate,
      treeHash: new Uint8Array(pathUpdate.treeHash),
    };
    conflicting.treeHash[0] ^= 0xff;
    await expect(bob.processPathUpdate(conflicting)).rejects.toThrow(
      /Conflicting/,
    );

    const { pathUpdate: nextUpdate } = await alice.update();
    await bob.processPathUpdate(nextUpdate);
    await expect(bob.processPathUpdate(pathUpdate)).rejects.toThrow(/stale/);
  });

  test('missing and out-of-resolution bundles fail without consuming the update', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
    const { pathUpdate, rootSecret } = await alice.update();

    const missingBundle: PathUpdateV2 = {
      ...pathUpdate,
      nodes: pathUpdate.nodes.map((node, offset) => ({
        ...node,
        encryptedPathKeyBundles:
          offset === 0 ? [] : [...node.encryptedPathKeyBundles],
      })),
    };
    await expect(bob.processPathUpdate(missingBundle)).rejects.toThrow(
      /invalid copath bundle set/,
    );

    const wrongRecipient: PathUpdateV2 = {
      ...pathUpdate,
      nodes: pathUpdate.nodes.map((node, offset) => ({
        ...node,
        encryptedPathKeyBundles: node.encryptedPathKeyBundles.map(
          (bundle, bundleOffset) => ({
            ...bundle,
            recipientNodeIndex:
              offset === 0 && bundleOffset === 0
                ? pathUpdate.senderLeafIndex
                : bundle.recipientNodeIndex,
          }),
        ),
      })),
    };
    await expect(bob.processPathUpdate(wrongRecipient)).rejects.toThrow(
      /invalid copath bundle set/,
    );
    expectSameSecret(await bob.processPathUpdate(pathUpdate), rootSecret);
  });

  test('v2 tree commitments distinguish trailing blank tree slots', async () => {
    const member = new BeeKEM();
    const keys = await keyPair();
    await member.initialize(keys.privateKey, keys.publicKey);
    const internals = member as unknown as {
      _nodes: Map<number, TreeNode>;
      _computeLegacyTreeHash(
        nodes?: Map<number, TreeNode>,
      ): Promise<Uint8Array>;
      _computeTreeHashV2(
        nodes: Map<number, TreeNode>,
        numLeaves: number,
      ): Promise<Uint8Array>;
    };
    const widerTree = new Map(internals._nodes);
    widerTree.set(1, {
      type: 'internal',
      index: 1,
      publicKey: null,
    });
    widerTree.set(2, { type: 'leaf', index: 2, publicKey: null });

    const legacyNarrow = await internals._computeLegacyTreeHash(
      internals._nodes,
    );
    const legacyWide = await internals._computeLegacyTreeHash(widerTree);
    expectSameSecret(legacyWide, legacyNarrow);

    const v2Narrow = await internals._computeTreeHashV2(internals._nodes, 1);
    const v2Wide = await internals._computeTreeHashV2(widerTree, 2);
    expect(Buffer.from(v2Wide).equals(Buffer.from(v2Narrow))).toBe(false);
  });
});
