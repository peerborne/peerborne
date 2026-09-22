import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import type { TreeNode, PathUpdateV2, BeeKEMWelcomeV2 } from './types.js';

const algorithm = { name: 'ECDH', namedCurve: 'P-256' };
const prime = (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n;

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(algorithm, true, ['deriveBits']);
}

async function negatedPublicKey(key: CryptoKey): Promise<CryptoKey> {
  const bytes = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  let y = 0n;
  for (let index = 33; index < 65; index++)
    y = (y << 8n) | BigInt(bytes[index]);
  let opposite = (prime - y) % prime;
  for (let index = 64; index >= 33; index--) {
    bytes[index] = Number(opposite & 0xffn);
    opposite >>= 8n;
  }
  return crypto.subtle.importKey('raw', bytes, algorithm, true, []);
}

function internals(tree: BeeKEM): {
  _nodes: Map<number, TreeNode>;
  _buildWelcome: (
    leaf: number,
    recipient: CryptoKey,
  ) => Promise<BeeKEMWelcomeV2>;
  _computeTreeHashV2: (
    nodes: Map<number, TreeNode>,
    leaves: number,
  ) => Promise<Uint8Array>;
} {
  return tree as never;
}

async function group() {
  const founderKeys = await keyPair();
  const recipientKeys = await keyPair();
  const founder = new BeeKEM();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
  const { welcome } = await founder.addMember(recipientKeys.publicKey);
  const recipient = new BeeKEM();
  await recipient.processWelcome(
    welcome,
    recipientKeys.privateKey,
    recipientKeys.publicKey,
  );
  return { founder, recipient, recipientKeys };
}

describe('exact V2 path key pairs', () => {
  test('rejects a negated Welcome path point even when the complete tree hash matches', async () => {
    const { founder, recipientKeys } = await group();
    const sender = internals(founder);
    const root = sender._nodes.get(1)!;
    sender._nodes.set(1, {
      ...root,
      publicKey: await negatedPublicKey(root.publicKey!),
    });
    const forged = await sender._buildWelcome(2, recipientKeys.publicKey);
    const recipient = new BeeKEM();
    await expect(
      recipient
        .processWelcome(
          forged,
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        )
        .then(() => undefined),
    ).rejects.toThrow(/private key does not match path node/);
    expect(recipient.memberCount).toBe(0);
    expect(recipient.myLeafIndex).toBe(-1);
  });

  test('rejects a negated PathUpdate point without replacing the current tree', async () => {
    const { founder, recipient } = await group();
    const before = await recipient.getRootSecret();
    const beforeGeneration = recipient.generation;
    const { pathUpdate } = await founder.update();
    const sender = internals(founder);
    const root = sender._nodes.get(1)!;
    const opposite = await negatedPublicKey(root.publicKey!);
    const encoded = new Uint8Array(
      await crypto.subtle.exportKey('raw', opposite),
    );
    const nodes = new Map(sender._nodes);
    nodes.set(1, { ...root, publicKey: opposite });
    const forged: PathUpdateV2 = {
      ...pathUpdate,
      nodes: pathUpdate.nodes.map((node) =>
        node.nodeIndex === 1 ? { ...node, publicKey: encoded } : node,
      ),
      treeNodePublicKeys: pathUpdate.treeNodePublicKeys.map((node) =>
        node.nodeIndex === 1 ? { ...node, publicKey: encoded } : node,
      ),
      treeHash: await sender._computeTreeHashV2(nodes, 2),
    };
    await expect(
      recipient.processPathUpdate(forged).then(() => undefined),
    ).rejects.toThrow(/private key does not match path node/);
    expect(recipient.generation).toBe(beforeGeneration);
    const after = await recipient.getRootSecret();
    expect(
      after.length === before.length &&
        after.every((byte, index) => byte === before[index]),
    ).toBe(true);
  });
});
