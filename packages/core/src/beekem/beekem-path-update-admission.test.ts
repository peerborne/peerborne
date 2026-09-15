import { describe, expect, test } from '@jest/globals';
import { eciesSeal, importEciesPublicKey } from '../ecies.js';
import { BeeKEM } from './beekem.js';
import { MAX_BEEKEM_TREE_LEAVES, PathUpdate } from './types.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

async function exportPublicKey(publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

async function twoMemberGroup() {
  const alice = new BeeKEM();
  const aliceKeys = await generateKeyPair();
  await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
  const bobKeys = await generateKeyPair();
  const { welcome } = await alice.addMember(bobKeys.publicKey);
  const bob = new BeeKEM();
  await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
  return { alice, bob, bobKeys };
}

describe('BeeKEM legacy PathUpdate admission', () => {
  test('rejects a path that does not exactly match the current sender path before mutation', async () => {
    const { alice, bob, bobKeys } = await twoMemberGroup();
    const { pathUpdate } = await bob.update();
    const unrelatedKeys = await generateKeyPair();
    const unrelatedPublicKey = await exportPublicKey(unrelatedKeys.publicKey);
    const bobOriginalPublicKey = await exportPublicKey(bobKeys.publicKey);

    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        senderLeafPublicKey: unrelatedPublicKey,
        nodes: [],
      }),
    ).rejects.toThrow(/exactly match the sender direct path/);

    await expect(
      alice.findLeafByPublicKey(unrelatedPublicKey),
    ).resolves.toBeUndefined();
    await expect(
      alice.findLeafByPublicKey(bobOriginalPublicKey),
    ).resolves.toBe(2);
  });

  test('rejects reordered, missing, and duplicate direct-path nodes', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    await founder.addMember((await generateKeyPair()).publicKey);
    const lastMemberKeys = await generateKeyPair();
    const { welcome } = await founder.addMember(lastMemberKeys.publicKey);
    const lastMember = new BeeKEM();
    await lastMember.processWelcome(
      welcome,
      lastMemberKeys.privateKey,
      lastMemberKeys.publicKey,
    );
    const { pathUpdate, rootSecret } = await founder.update();
    expect(pathUpdate.nodes).toHaveLength(2);

    const variants: PathUpdate[] = [
      { ...pathUpdate, nodes: pathUpdate.nodes.slice(1) },
      { ...pathUpdate, nodes: [...pathUpdate.nodes].reverse() },
      {
        ...pathUpdate,
        nodes: [pathUpdate.nodes[0], pathUpdate.nodes[0]],
      },
    ];
    for (const variant of variants) {
      await expect(lastMember.processPathUpdate(variant)).rejects.toThrow(
        /exactly match the sender direct path/,
      );
    }

    const receivedRoot = await lastMember.processPathUpdate(pathUpdate);
    expect(bytesEqual(receivedRoot, rootSecret)).toBe(true);
  });

  test('detaches all nested bytes before the first asynchronous operation', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate, rootSecret } = await bob.update();
    const pending = alice.processPathUpdate(pathUpdate);

    pathUpdate.senderLeafPublicKey.fill(0);
    for (const node of pathUpdate.nodes) {
      node.publicKey.fill(0);
      node.encryptedPrivateKey.fill(0);
    }

    const receivedRoot = await pending;
    expect(bytesEqual(receivedRoot, rootSecret)).toBe(true);
  });

  test('bounds direct runtime key and ciphertext fields without changing state', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate, rootSecret } = await bob.update();

    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        senderLeafPublicKey: new Uint8Array(64),
      }),
    ).rejects.toThrow(/senderLeafPublicKey.*65/);
    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        nodes: pathUpdate.nodes.map((node) => ({
          ...node,
          encryptedPrivateKey: new Uint8Array(124),
        })),
      }),
    ).rejects.toThrow(/encryptedPrivateKey.*empty or 125\.\.4096/);

    const receivedRoot = await alice.processPathUpdate(pathUpdate);
    expect(bytesEqual(receivedRoot, rootSecret)).toBe(true);
  });

  test('rejects an inactive sender leaf before cryptographic work', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate } = await bob.update();
    const internals = alice as unknown as {
      _nodes: Map<number, unknown>;
    };
    internals._nodes.set(2, {
      type: 'leaf',
      index: 2,
      publicKey: null,
    });

    await expect(alice.processPathUpdate(pathUpdate)).rejects.toThrow(
      /sender is not an active tree leaf/,
    );
    expect(internals._nodes.get(2)).toEqual({
      type: 'leaf',
      index: 2,
      publicKey: null,
    });
  });

  test('rolls back staged tree changes when cryptographic validation fails', async () => {
    const { alice, bob, bobKeys } = await twoMemberGroup();
    const originalRoot = await alice.getRootSecret();
    const bobOriginalPublicKey = await exportPublicKey(bobKeys.publicKey);
    const { pathUpdate } = await bob.update();
    const tampered: PathUpdate = {
      ...pathUpdate,
      nodes: pathUpdate.nodes.map((node) => ({
        ...node,
        publicKey: new Uint8Array(65),
      })),
    };

    await expect(alice.processPathUpdate(tampered)).rejects.toThrow();

    const rootAfterFailure = await alice.getRootSecret();
    expect(bytesEqual(rootAfterFailure, originalRoot)).toBe(true);
    await expect(
      alice.findLeafByPublicKey(pathUpdate.senderLeafPublicKey),
    ).resolves.toBeUndefined();
    await expect(
      alice.findLeafByPublicKey(bobOriginalPublicKey),
    ).resolves.toBe(2);
  });

  test('rejects a decrypted private key paired with an unrelated valid public key', async () => {
    const { alice, bob, bobKeys } = await twoMemberGroup();
    const originalRoot = await alice.getRootSecret();
    const bobOriginalPublicKey = await exportPublicKey(bobKeys.publicKey);
    const { pathUpdate, rootSecret } = await bob.update();
    const unrelatedPublicKey = await exportPublicKey(
      (await generateKeyPair()).publicKey,
    );
    const mismatched: PathUpdate = {
      ...pathUpdate,
      nodes: pathUpdate.nodes.map((node, index) => ({
        ...node,
        publicKey: index === 0 ? unrelatedPublicKey : node.publicKey,
      })),
    };

    await expect(alice.processPathUpdate(mismatched)).rejects.toThrow(
      /private key does not match the public key/,
    );

    await expect(alice.getRootSecret()).resolves.toEqual(originalRoot);
    await expect(
      alice.findLeafByPublicKey(pathUpdate.senderLeafPublicKey),
    ).resolves.toBeUndefined();
    await expect(
      alice.findLeafByPublicKey(bobOriginalPublicKey),
    ).resolves.toBe(2);

    const receivedRoot = await alice.processPathUpdate(pathUpdate);
    expect(bytesEqual(receivedRoot, rootSecret)).toBe(true);
  });

  test('rejects a mismatched ancestor key above a non-root intersection without mutation', async () => {
    let sender = new BeeKEM();
    let senderKeys = await generateKeyPair();
    await sender.initialize(senderKeys.privateKey, senderKeys.publicKey);
    for (let index = 0; index < 4; index++) {
      const nextKeys = await generateKeyPair();
      const { welcome } = await sender.addMember(nextKeys.publicKey);
      const next = new BeeKEM();
      await next.processWelcome(
        welcome,
        nextKeys.privateKey,
        nextKeys.publicKey,
      );
      sender = next;
      senderKeys = nextKeys;
    }

    const receiverKeys = await generateKeyPair();
    const { welcome } = await sender.addMember(receiverKeys.publicKey);
    const receiver = new BeeKEM();
    await receiver.processWelcome(
      welcome,
      receiverKeys.privateKey,
      receiverKeys.publicKey,
    );

    const senderInternals = sender as unknown as {
      _nodes: Map<number, { privateKey?: CryptoKey }>;
    };
    const { pathUpdate, rootSecret } = await sender.update();
    expect(pathUpdate.nodes.map(({ nodeIndex }) => nodeIndex)).toEqual([9, 7]);

    const [intersectionNode, ancestorNode] = pathUpdate.nodes;
    const ancestorPrivateKey = senderInternals._nodes.get(
      ancestorNode.nodeIndex,
    )?.privateKey;
    expect(ancestorPrivateKey).toBeDefined();
    if (!ancestorPrivateKey) throw new Error('missing ancestor private key');

    const intersectionPublicKey = await importEciesPublicKey(
      intersectionNode.publicKey,
    );
    // Make the ancestor decryptable through node 9 so rejection depends on
    // its public/private key-pair check, not an earlier ECIES failure.
    const encryptedAncestorPrivateKey = await eciesSeal(
      new Uint8Array(
        await crypto.subtle.exportKey('pkcs8', ancestorPrivateKey),
      ),
      intersectionPublicKey,
    );
    const validRewrappedUpdate: PathUpdate = {
      ...pathUpdate,
      nodes: [
        intersectionNode,
        { ...ancestorNode, encryptedPrivateKey: encryptedAncestorPrivateKey },
      ],
    };
    const mismatchedAncestorPublicKey = await exportPublicKey(
      (await generateKeyPair()).publicKey,
    );
    const tampered: PathUpdate = {
      ...validRewrappedUpdate,
      nodes: [
        intersectionNode,
        {
          ...validRewrappedUpdate.nodes[1],
          publicKey: mismatchedAncestorPublicKey,
        },
      ],
    };

    const receiverInternals = receiver as unknown as {
      _nodes: Map<number, unknown>;
    };
    const nodesBefore = receiverInternals._nodes;
    const rootBefore = await receiver.getRootSecret();

    await expect(receiver.processPathUpdate(tampered)).rejects.toThrow(
      /private key does not match the public key at node 7/,
    );

    expect(receiverInternals._nodes).toBe(nodesBefore);
    await expect(receiver.getRootSecret()).resolves.toEqual(rootBefore);
    await expect(
      receiver.findLeafByPublicKey(pathUpdate.senderLeafPublicKey),
    ).resolves.toBeUndefined();
    await expect(
      receiver.findLeafByPublicKey(senderKeys.publicKey),
    ).resolves.toBe(8);

    const receivedRoot = await receiver.processPathUpdate(validRewrappedUpdate);
    expect(bytesEqual(receivedRoot, rootSecret)).toBe(true);
  });

  test('rejects oversized or non-data runtime shapes without reading entries', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate } = await bob.update();
    let nodeReads = 0;
    const oversizedNodes = new Array(14);
    Object.defineProperty(oversizedNodes, '0', {
      enumerable: true,
      get() {
        nodeReads++;
        throw new Error('must not read an oversized array');
      },
    });

    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        nodes: oversizedNodes,
      }),
    ).rejects.toThrow(/safely detach input/);
    expect(nodeReads).toBe(0);

    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        unexpected: undefined,
      } as unknown as PathUpdate),
    ).rejects.toThrow(/unexpected.*field 'unexpected'/);
  });

  test('rejects additions at the shared tree-size ceiling before mutation', async () => {
    const beekem = new BeeKEM();
    const localKeys = await generateKeyPair();
    await beekem.initialize(localKeys.privateKey, localKeys.publicKey);
    const internals = beekem as unknown as {
      _numLeaves: number;
      _nodes: Map<number, unknown>;
    };
    internals._numLeaves = MAX_BEEKEM_TREE_LEAVES;
    const nodesBefore = internals._nodes;

    await expect(
      beekem.addMember((await generateKeyPair()).publicKey),
    ).rejects.toThrow(/limited to 8192 leaves/);
    expect(beekem.memberCount).toBe(MAX_BEEKEM_TREE_LEAVES);
    expect(internals._nodes).toBe(nodesBefore);
  });
});
