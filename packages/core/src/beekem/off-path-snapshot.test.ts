import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import { PathUpdateV2, TreeNode } from './types.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

async function rawPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

function internals(tree: BeeKEM): {
  _importTreeSnapshot(
    snapshot: PathUpdateV2['treeNodePublicKeys'],
    numLeaves: number,
  ): Promise<Map<number, TreeNode>>;
  _computeTreeHashV2(
    nodes: Map<number, TreeNode>,
    numLeaves: number,
  ): Promise<Uint8Array>;
} {
  return tree as never;
}

async function withSnapshotKey(
  tree: BeeKEM,
  update: PathUpdateV2,
  nodeIndex: number,
  publicKey: Uint8Array | null,
): Promise<PathUpdateV2> {
  const treeNodePublicKeys = update.treeNodePublicKeys.map((entry) => ({
    nodeIndex: entry.nodeIndex,
    publicKey:
      entry.nodeIndex === nodeIndex
        ? publicKey
        : entry.publicKey === null
          ? null
          : new Uint8Array(entry.publicKey),
  }));
  const nodes = await internals(tree)._importTreeSnapshot(
    treeNodePublicKeys,
    update.numLeaves,
  );
  return {
    ...update,
    treeNodePublicKeys,
    treeHash: await internals(tree)._computeTreeHashV2(
      nodes,
      update.numLeaves,
    ),
  };
}

/** Founder A(0) adds B(2), C(4), and D(6); C and D track every transition. */
async function fourMemberGroup() {
  const founderKeys = await keyPair();
  const founder = new BeeKEM();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
  await founder.addMember((await keyPair()).publicKey);

  const carolKeys = await keyPair();
  const { welcome: carolWelcome } = await founder.addMember(
    carolKeys.publicKey,
  );
  const carol = new BeeKEM();
  await carol.processWelcome(
    carolWelcome,
    carolKeys.privateKey,
    carolKeys.publicKey,
  );

  const daveKeys = await keyPair();
  const { pathUpdate: addDave, welcome: daveWelcome } =
    await founder.addMember(daveKeys.publicKey);
  await carol.processPathUpdate(addDave);
  const dave = new BeeKEM();
  await dave.processWelcome(daveWelcome, daveKeys.privateKey, daveKeys.publicKey);
  return { carol, dave, founder };
}

describe('BeeKEM v2 internal nodes outside the sender path', () => {
  test('rejects a planted public key on another subtree and keeps state', async () => {
    const { carol, dave } = await fourMemberGroup();
    const { pathUpdate } = await dave.update();
    const node1 = pathUpdate.treeNodePublicKeys.find(
      (entry) => entry.nodeIndex === 1,
    );
    expect(node1?.publicKey).not.toBeNull();
    const planted = await withSnapshotKey(
      carol,
      pathUpdate,
      1,
      await rawPublicKey((await keyPair()).publicKey),
    );
    const generation = carol.generation;
    const root = await carol.getRootSecret();

    await expect(carol.processPathUpdate(planted)).rejects.toThrow(
      /cannot change internal node 1 outside the sender path/,
    );
    expect(carol.generation).toBe(generation);
    expect(await carol.getRootSecret()).toEqual(root);

    await expect(carol.processPathUpdate(pathUpdate)).resolves.toEqual(
      await dave.getRootSecret(),
    );
  });

  test('rejects blanking an unrelated internal node', async () => {
    const { carol, dave } = await fourMemberGroup();
    const { pathUpdate } = await dave.update();
    const blanked = await withSnapshotKey(carol, pathUpdate, 1, null);

    await expect(carol.processPathUpdate(blanked)).rejects.toThrow(
      /internal node 1 outside the sender path|copath bundle set/,
    );
  });

  test('accepts honest removal and append transitions from another member', async () => {
    const { carol, dave, founder } = await fourMemberGroup();
    const removal = await dave.removeMember(0);
    await expect(carol.processPathUpdate(removal.pathUpdate)).resolves.toEqual(
      removal.rootSecret,
    );
    expect(founder.generation).toBeLessThan(carol.generation!);

    const append = await dave.addMember((await keyPair()).publicKey);
    await expect(carol.processPathUpdate(append.pathUpdate)).resolves.toEqual(
      append.rootSecret,
    );
  });
});
