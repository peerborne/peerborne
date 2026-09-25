import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import { MAX_BEEKEM_TREE_LEAVES, PathUpdate } from './types.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };
const P256_PRIME =
  (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n;

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

async function exportPublicKey(publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

function negateP256Point(rawPublicKey: Uint8Array): Uint8Array {
  if (rawPublicKey.byteLength !== 65 || rawPublicKey[0] !== 4) {
    throw new Error('Expected an uncompressed P-256 public key');
  }
  const negated = new Uint8Array(rawPublicKey);
  let y = 0n;
  for (let index = 33; index < 65; index++) {
    y = (y << 8n) | BigInt(rawPublicKey[index]);
  }
  let negativeY = (P256_PRIME - y) % P256_PRIME;
  for (let index = 64; index >= 33; index--) {
    negated[index] = Number(negativeY & 0xffn);
    negativeY >>= 8n;
  }
  return negated;
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

  test('rejects malformed paths and accepts a root intersection', async () => {
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

  test('rejects the negated public point for a decrypted private key', async () => {
    const { alice, bob, bobKeys } = await twoMemberGroup();
    const originalRoot = await alice.getRootSecret();
    const bobOriginalPublicKey = await exportPublicKey(bobKeys.publicKey);
    const { pathUpdate } = await bob.update();
    const mismatched: PathUpdate = {
      ...pathUpdate,
      nodes: pathUpdate.nodes.map((node, index) => ({
        ...node,
        publicKey:
          index === pathUpdate.nodes.length - 1
            ? negateP256Point(node.publicKey)
            : node.publicKey,
      })),
    };

    await expect(alice.processPathUpdate(mismatched)).rejects.toThrow(
      /private key does not match the public key/,
    );
    await expect(alice.getRootSecret()).resolves.toEqual(originalRoot);
    await expect(
      alice.findLeafByPublicKey(bobOriginalPublicKey),
    ).resolves.toBe(2);
  });

  test('serializes a local update behind an in-flight remote update', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate, rootSecret: remoteRoot } = await bob.update();
    const { pathUpdate: laterPathUpdate, rootSecret: laterRemoteRoot } =
      await bob.update();
    const internals = alice as unknown as {
      _processPathUpdate(update: PathUpdate): Promise<Uint8Array>;
      _update(): Promise<{ pathUpdate: PathUpdate; rootSecret: Uint8Array }>;
    };
    const processPathUpdate = internals._processPathUpdate.bind(alice);
    let releaseProcessing!: () => void;
    const processingGate = new Promise<void>((resolve) => {
      releaseProcessing = resolve;
    });
    let processingStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      processingStarted = resolve;
    });
    internals._processPathUpdate = async (update) => {
      processingStarted();
      await processingGate;
      return processPathUpdate(update);
    };
    const update = internals._update.bind(alice);
    internals._update = jest.fn(update);

    const remoteUpdate = alice.processPathUpdate(pathUpdate);
    await started;
    const laterRemoteUpdate = alice.processPathUpdate(laterPathUpdate);
    const localUpdate = alice.update();
    await Promise.resolve();

    expect(internals._update).not.toHaveBeenCalled();
    expect(() => alice.clone()).toThrow(/during an active mutation/);
    expect(() => alice.compact()).toThrow(/during an active mutation/);
    releaseProcessing();
    await expect(remoteUpdate).resolves.toEqual(remoteRoot);
    await expect(laterRemoteUpdate).resolves.toEqual(laterRemoteRoot);
    const { rootSecret: localRoot } = await localUpdate;
    expect(internals._update).toHaveBeenCalledTimes(1);
    await expect(alice.getRootSecret()).resolves.toEqual(localRoot);
  });

  test('rejects a PathUpdate before Welcome commit and accepts a retry afterward', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const recipientKeys = await generateKeyPair();
    const { welcome, rootSecret: welcomeRoot } = await founder.addMember(
      recipientKeys.publicKey,
    );
    const { pathUpdate, rootSecret: updatedRoot } = await founder.update();
    const target = new BeeKEM();

    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let enter!: () => void;
    let release!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let paused = false;
    const digestSpy = jest
      .spyOn(crypto.subtle, 'digest')
      .mockImplementation(async (algorithm, data) => {
        if (!paused) {
          paused = true;
          enter();
          await gate;
        }
        return originalDigest(algorithm, data);
      });

    const joining = target.processWelcome(
      welcome,
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );
    try {
      await entered;
      let inputReads = 0;
      const unreadUpdate = new Proxy(pathUpdate, {
        getOwnPropertyDescriptor(target, property) {
          inputReads++;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      });
      await expect(target.processPathUpdate(unreadUpdate)).rejects.toThrow(
        /tree is not initialized/,
      );
      expect(inputReads).toBe(0);

      release();
      await expect(joining).resolves.toEqual(welcomeRoot);
      await expect(target.processPathUpdate(pathUpdate)).resolves.toEqual(
        updatedRoot,
      );
      await expect(target.getRootSecret()).resolves.toEqual(updatedRoot);
    } finally {
      release();
      await Promise.allSettled([joining]);
      digestSpy.mockRestore();
    }
  });

  test('allows initialization after an in-flight Welcome fails', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const recipientKeys = await generateKeyPair();
    const { welcome } = await founder.addMember(recipientKeys.publicKey);
    const { pathUpdate } = await founder.update();
    welcome.treeHash[0] ^= 0xff;
    const target = new BeeKEM();

    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let enter!: () => void;
    let release!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let paused = false;
    const digestSpy = jest
      .spyOn(crypto.subtle, 'digest')
      .mockImplementation(async (algorithm, data) => {
        if (!paused) {
          paused = true;
          enter();
          await gate;
        }
        return originalDigest(algorithm, data);
      });

    const joining = target.processWelcome(
      welcome,
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );
    try {
      await entered;
      await expect(target.processPathUpdate(pathUpdate)).rejects.toThrow(
        /tree is not initialized/,
      );
      release();
      await expect(joining).rejects.toThrow(/tree hash mismatch/);
      await expect(
        target.initialize(
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).resolves.toBeUndefined();
    } finally {
      release();
      await Promise.allSettled([joining]);
      digestSpy.mockRestore();
    }
  });

  test('rejects a protocol-valid multi-level v1 update without mutation', async () => {
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

    const { pathUpdate } = await sender.update();
    expect(pathUpdate.nodes.map(({ nodeIndex }) => nodeIndex)).toEqual([9, 7]);

    const receiverInternals = receiver as unknown as {
      _nodes: Map<number, unknown>;
    };
    const nodesBefore = receiverInternals._nodes;
    const rootBefore = await receiver.getRootSecret();

    await expect(receiver.processPathUpdate(pathUpdate)).rejects.toThrow(
      /legacy PathUpdate v1 cannot safely distribute ancestor keys/,
    );

    expect(receiverInternals._nodes).toBe(nodesBefore);
    await expect(receiver.getRootSecret()).resolves.toEqual(rootBefore);
    await expect(
      receiver.findLeafByPublicKey(pathUpdate.senderLeafPublicKey),
    ).resolves.toBeUndefined();
    await expect(
      receiver.findLeafByPublicKey(senderKeys.publicKey),
    ).resolves.toBe(8);
  });

  test('tries a surviving descendant resolution key after removal blanks its ancestor', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);

    const bobKeys = await generateKeyPair();
    const { welcome: bobWelcome } = await founder.addMember(
      bobKeys.publicKey,
    );
    const bob = new BeeKEM();
    await bob.processWelcome(
      bobWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const charlieKeys = await generateKeyPair();
    const { welcome: charlieWelcome, rootSecret: sharedRoot } =
      await bob.addMember(charlieKeys.publicKey);
    const charlie = new BeeKEM();
    await expect(
      charlie.processWelcome(
        charlieWelcome,
        charlieKeys.privateKey,
        charlieKeys.publicKey,
      ),
    ).resolves.toEqual(sharedRoot);
    await expect(bob.getRootSecret()).resolves.toEqual(sharedRoot);

    const { pathUpdate, rootSecret } = await charlie.removeMember(0);
    expect(pathUpdate.nodes.map(({ nodeIndex }) => nodeIndex)).toEqual([3]);
    await expect(bob.processPathUpdate(pathUpdate)).resolves.toEqual(
      rootSecret,
    );
  });

  test('does not let the removed member use stale resolution candidates', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    await founder.addMember((await generateKeyPair()).publicKey);

    const charlieKeys = await generateKeyPair();
    const { welcome, rootSecret: sharedRoot } = await founder.addMember(
      charlieKeys.publicKey,
    );
    const charlie = new BeeKEM();
    await expect(
      charlie.processWelcome(
        welcome,
        charlieKeys.privateKey,
        charlieKeys.publicKey,
      ),
    ).resolves.toEqual(sharedRoot);
    const founderRootBeforeRemoval = await founder.getRootSecret();

    const { pathUpdate } = await charlie.removeMember(0);
    await expect(founder.processPathUpdate(pathUpdate)).rejects.toThrow(
      /no local resolution key could decrypt/,
    );
    await expect(founder.getRootSecret()).resolves.toEqual(
      founderRootBeforeRemoval,
    );
  });

  test('rejects v1 emission that needs multiple resolution ciphertexts without mutation', async () => {
    let sender = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await sender.initialize(founderKeys.privateKey, founderKeys.publicKey);

    for (let position = 1; position < 9; position++) {
      const nextKeys = await generateKeyPair();
      const { welcome } = await sender.addMember(nextKeys.publicKey);
      const next = new BeeKEM();
      await next.processWelcome(
        welcome,
        nextKeys.privateKey,
        nextKeys.publicKey,
      );
      sender = next;
    }

    const senderInternals = sender as unknown as {
      _nodes: Map<number, unknown>;
    };
    const nodesBefore = senderInternals._nodes;
    const rootBefore = await sender.getRootSecret();

    await expect(sender.removeMember(0)).rejects.toThrow(
      /multiple sibling resolution nodes/,
    );

    expect(senderInternals._nodes).toBe(nodesBefore);
    await expect(sender.getRootSecret()).resolves.toEqual(rootBefore);
    await expect(
      sender.findLeafByPublicKey(founderKeys.publicKey),
    ).resolves.toBe(0);
  });

  test('rejects own and inherited v2 markers at the legacy runtime boundary', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate, rootSecret } = await bob.update();
    const internals = alice as unknown as {
      _nodes: Map<number, unknown>;
    };
    const nodesBefore = internals._nodes;
    const rootBefore = await alice.getRootSecret();
    const topLevelMarkers = [
      'version',
      'generation',
      'parentTreeHash',
      'numLeaves',
      'treeNodePublicKeys',
      'treeHash',
    ] as const;

    for (const field of topLevelMarkers) {
      const forged = { ...pathUpdate };
      Object.defineProperty(forged, field, {
        enumerable: true,
        value: field === 'version' ? 2 : 1,
      });
      await expect(alice.processPathUpdate(forged)).rejects.toMatchObject({
        cause: expect.objectContaining({
          message: expect.stringContaining(`forbidden field '${field}'`),
        }),
      });

      const prior = Object.getOwnPropertyDescriptor(Object.prototype, field);
      Object.defineProperty(Object.prototype, field, {
        configurable: true,
        value: field === 'version' ? 2 : 1,
      });
      try {
        await expect(
          alice.processPathUpdate(pathUpdate),
        ).rejects.toMatchObject({
          cause: expect.objectContaining({
            message: expect.stringContaining(`forbidden field '${field}'`),
          }),
        });
      } finally {
        if (prior === undefined) {
          delete (Object.prototype as Record<string, unknown>)[field];
        } else {
          Object.defineProperty(Object.prototype, field, prior);
        }
      }
    }

    const nodePrototype = Object.create(null) as Record<string, unknown>;
    nodePrototype.encryptedPathKeyBundles = [];
    const inheritedBundleNode = Object.assign(
      Object.create(nodePrototype) as Record<string, unknown>,
      pathUpdate.nodes[0],
    );
    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        nodes: [
          inheritedBundleNode,
          ...pathUpdate.nodes.slice(1),
        ] as unknown as PathUpdate['nodes'],
      }),
    ).rejects.toMatchObject({
      cause: expect.objectContaining({
        message: expect.stringContaining(
          "forbidden field 'encryptedPathKeyBundles'",
        ),
      }),
    });

    const ownBundleNode = { ...pathUpdate.nodes[0] };
    Object.defineProperty(ownBundleNode, 'encryptedPathKeyBundles', {
      enumerable: true,
      value: [],
    });
    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        nodes: [ownBundleNode, ...pathUpdate.nodes.slice(1)],
      }),
    ).rejects.toMatchObject({
      cause: expect.objectContaining({
        message: expect.stringContaining(
          "forbidden field 'encryptedPathKeyBundles'",
        ),
      }),
    });

    expect(internals._nodes).toBe(nodesBefore);
    await expect(alice.getRootSecret()).resolves.toEqual(rootBefore);
    await expect(alice.processPathUpdate(pathUpdate)).resolves.toEqual(
      rootSecret,
    );
  });

  test('rejects oversized or non-data runtime shapes without reading entries', async () => {
    const { alice, bob } = await twoMemberGroup();
    const { pathUpdate } = await bob.update();
    let nodeReads = 0;
    let nodeKeyEnumerations = 0;
    const oversizedNodes = new Proxy(new Array(14).fill(null), {
      ownKeys(target) {
        nodeKeyEnumerations++;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, property) {
        if (property !== 'length') nodeReads++;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        nodes: oversizedNodes,
      }),
    ).rejects.toThrow(/safely detach input/);
    expect(nodeReads).toBe(0);
    expect(nodeKeyEnumerations).toBe(0);

    await expect(
      alice.processPathUpdate({
        ...pathUpdate,
        unexpected: undefined,
      } as unknown as PathUpdate),
    ).rejects.toThrow(/unexpected.*field 'unexpected'/);
  });

  test('rejects oversized live state before inspecting update input', async () => {
    const { alice } = await twoMemberGroup();
    const internals = alice as unknown as {
      _numLeaves: number;
      _myLeafIndex: number;
    };
    internals._numLeaves = MAX_BEEKEM_TREE_LEAVES + 1;
    internals._myLeafIndex = 0;
    let inputReads = 0;
    const unreadUpdate = {} as PathUpdate;
    Object.defineProperty(unreadUpdate, 'nodes', {
      enumerable: true,
      get() {
        inputReads++;
        throw new Error('must not inspect update input');
      },
    });

    await expect(alice.processPathUpdate(unreadUpdate)).rejects.toThrow(
      /BeeKEM tree is not initialized/,
    );
    expect(inputReads).toBe(0);
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
    ).rejects.toThrow(/at most 8192 leaves are supported/);
    expect(beekem.memberCount).toBe(MAX_BEEKEM_TREE_LEAVES);
    expect(internals._nodes).toBe(nodesBefore);
  });
});
