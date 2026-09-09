import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import {
  BeeKEMWelcomeV2,
  MAX_BEEKEM_TREE_LEAVES,
  PathUpdateV2,
  TreeNode,
} from './types.js';
import { generateEciesKeyPair } from '../ecies.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => {};
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function treeFingerprint(beekem: BeeKEM): Promise<string> {
  const nodes = (
    beekem as unknown as { _nodes: Map<number, TreeNode> }
  )._nodes;
  const entries = await Promise.all(
    [...nodes.entries()]
      .sort(([left], [right]) => left - right)
      .map(async ([index, node]) => {
        const privateKey = node.privateKey;
        return {
          index,
          type: node.type,
          privateKey:
            privateKey === undefined
              ? null
              : privateKey.extractable
                ? Buffer.from(
                    await crypto.subtle.exportKey('pkcs8', privateKey),
                  ).toString('base64')
                : 'non-extractable',
          publicKey:
            node.publicKey === null
              ? null
              : Buffer.from(
                  await crypto.subtle.exportKey('raw', node.publicKey),
                ).toString('base64'),
        };
      }),
  );
  return JSON.stringify(entries);
}

function stateMetadata(beekem: BeeKEM): {
  numLeaves: number;
  myLeafIndex: number;
  generation: number | null;
  lastAppliedV2UpdateDigest: number[] | null;
} {
  const state = beekem as unknown as {
    _numLeaves: number;
    _myLeafIndex: number;
    _generation: number | null;
    _lastAppliedV2UpdateDigest: Uint8Array | null;
  };
  return {
    numLeaves: state._numLeaves,
    myLeafIndex: state._myLeafIndex,
    generation: state._generation,
    lastAppliedV2UpdateDigest:
      state._lastAppliedV2UpdateDigest === null
        ? null
        : Array.from(state._lastAppliedV2UpdateDigest),
  };
}

function overwriteBytes(bytes: Uint8Array): void {
  bytes.fill(0xee);
}

function overwritePathUpdate(
  update: Awaited<ReturnType<BeeKEM['addMember']>>['pathUpdate'],
): void {
  overwriteBytes(update.parentTreeHash);
  overwriteBytes(update.senderLeafPublicKey);
  overwriteBytes(update.treeHash);
  for (const node of update.nodes) {
    overwriteBytes(node.publicKey);
    overwriteBytes(node.encryptedPrivateKey);
    for (const bundle of node.encryptedPathKeyBundles) {
      overwriteBytes(bundle.ciphertext);
    }
  }
  for (const node of update.treeNodePublicKeys) {
    if (node.publicKey !== null) overwriteBytes(node.publicKey);
  }
}

function overwriteWelcome(
  welcome: Awaited<ReturnType<BeeKEM['addMember']>>['welcome'],
): void {
  overwriteBytes(welcome.treeHash);
  for (const pathKey of welcome.pathKeys) {
    overwriteBytes(pathKey.publicKey);
    overwriteBytes(pathKey.encryptedPrivateKey);
  }
  for (const node of welcome.treeNodePublicKeys) {
    if (node.publicKey !== null) overwriteBytes(node.publicKey);
  }
}

function clonePathUpdate(update: PathUpdateV2): PathUpdateV2 {
  return {
    version: 2,
    generation: update.generation,
    parentTreeHash: new Uint8Array(update.parentTreeHash),
    numLeaves: update.numLeaves,
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: new Uint8Array(update.senderLeafPublicKey),
    nodes: update.nodes.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: new Uint8Array(node.publicKey),
      encryptedPrivateKey: new Uint8Array(node.encryptedPrivateKey),
      encryptedPathKeyBundles: node.encryptedPathKeyBundles.map((bundle) => ({
        recipientNodeIndex: bundle.recipientNodeIndex,
        ciphertext: new Uint8Array(bundle.ciphertext),
      })),
    })),
    treeNodePublicKeys: update.treeNodePublicKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null ? null : new Uint8Array(node.publicKey),
    })),
    treeHash: new Uint8Array(update.treeHash),
  };
}

function cloneWelcome(welcome: BeeKEMWelcomeV2): BeeKEMWelcomeV2 {
  return {
    version: 2,
    generation: welcome.generation,
    numLeaves: welcome.numLeaves,
    leafIndex: welcome.leafIndex,
    pathKeys: welcome.pathKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: new Uint8Array(node.publicKey),
      encryptedPrivateKey: new Uint8Array(node.encryptedPrivateKey),
    })),
    treeNodePublicKeys: welcome.treeNodePublicKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null ? null : new Uint8Array(node.publicKey),
    })),
    treeHash: new Uint8Array(welcome.treeHash),
  };
}

describe('BeeKEM transactional state changes', () => {
  test('single-member root derivation supports the canonical non-extractable key', async () => {
    const keys = await generateEciesKeyPair();
    expect(keys.privateKey.extractable).toBe(false);
    const member = new BeeKEM();
    await member.initialize(keys.privateKey, keys.publicKey);
    const first = await member.getRootSecret();
    const second = await member.getRootSecret();
    expect(first).toHaveLength(32);
    expect(second).toEqual(first);
  });

  test('addMember restores the prior tree when Welcome construction fails', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const beforeRoot = await alice.getRootSecret();
    const bobKeys = await keyPair();
    const mutable = alice as unknown as { _buildWelcome: () => Promise<never> };
    mutable._buildWelcome = async () => {
      throw new Error('injected Welcome failure');
    };

    await expect(alice.addMember(bobKeys.publicKey)).rejects.toThrow(/injected/);
    expect(alice.memberCount).toBe(1);
    expect(alice.generation).toBe(0);
    expect(await alice.getRootSecret()).toEqual(beforeRoot);
    expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBeUndefined();
  });

  test('transactional add restores exact keys and never reuses rejected output', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const before = {
      generation: alice.generation,
      rootSecret: await alice.getRootSecret(),
      tree: await treeFingerprint(alice),
      metadata: stateMetadata(alice),
    };
    let rejected: Awaited<ReturnType<BeeKEM['addMember']>> | undefined;

    await expect(
      alice.addMemberTransactionally(bobKeys.publicKey, async (result) => {
        rejected = result;
        throw new Error('injected local epoch install failure');
      }),
    ).rejects.toThrow(/epoch install/);

    expect(alice.memberCount).toBe(1);
    expect(alice.generation).toBe(before.generation);
    expect(await alice.getRootSecret()).toEqual(before.rootSecret);
    expect(await treeFingerprint(alice)).toBe(before.tree);
    expect(stateMetadata(alice)).toEqual(before.metadata);
    expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBeUndefined();
    if (rejected === undefined) throw new Error('transaction callback did not run');

    const rejectedGeneration = rejected.pathUpdate.generation;
    overwritePathUpdate(rejected.pathUpdate);
    overwriteWelcome(rejected.welcome);
    overwriteBytes(rejected.rootSecret);
    expect(await alice.getRootSecret()).toEqual(before.rootSecret);
    expect(await treeFingerprint(alice)).toBe(before.tree);
    expect(stateMetadata(alice)).toEqual(before.metadata);

    const retry = await alice.addMember(bobKeys.publicKey);
    expect(retry.pathUpdate.generation).toBe(rejectedGeneration);
    expect(retry.pathUpdate.senderLeafPublicKey).not.toEqual(
      rejected.pathUpdate.senderLeafPublicKey,
    );
    expect(retry.welcome.treeHash).not.toEqual(rejected.welcome.treeHash);
    expect(retry.rootSecret).not.toEqual(rejected.rootSecret);
  });

  test('addMember enforces the lifetime leaf cap before mutating state', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const beforeTree = await treeFingerprint(alice);
    const beforeGeneration = alice.generation;
    const internals = alice as unknown as { _numLeaves: number };
    internals._numLeaves = MAX_BEEKEM_TREE_LEAVES;
    const bobKeys = await keyPair();

    await expect(alice.addMember(bobKeys.publicKey)).rejects.toThrow(
      /lifetime leaf limit/,
    );

    expect(internals._numLeaves).toBe(MAX_BEEKEM_TREE_LEAVES);
    expect(alice.generation).toBe(beforeGeneration);
    expect(await treeFingerprint(alice)).toBe(beforeTree);
    expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBeUndefined();
  });

  test('removeMember and update restore pre-crypto mutations', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const beforeRoot = await alice.getRootSecret();
    const beforeGeneration = alice.generation;
    const mutable = alice as unknown as { _updatePath: () => Promise<never> };
    mutable._updatePath = async () => {
      throw new Error('injected path failure');
    };

    await expect(alice.removeMember(welcome.leafIndex)).rejects.toThrow(
      /injected/,
    );
    expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBe(
      welcome.leafIndex,
    );
    expect(alice.generation).toBe(beforeGeneration);
    expect(await alice.getRootSecret()).toEqual(beforeRoot);
    await expect(alice.update()).rejects.toThrow(/injected/);
    expect(alice.generation).toBe(beforeGeneration);
    expect(await alice.getRootSecret()).toEqual(beforeRoot);
  });

  test('transactional remove restores exact keys and never reuses rejected output', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const before = {
      generation: alice.generation,
      rootSecret: await alice.getRootSecret(),
      tree: await treeFingerprint(alice),
      metadata: stateMetadata(alice),
    };
    let rejected: Awaited<ReturnType<BeeKEM['removeMember']>> | undefined;

    await expect(
      alice.removeMemberTransactionally(welcome.leafIndex, async (result) => {
        rejected = result;
        throw new Error('injected local epoch install failure');
      }),
    ).rejects.toThrow(/epoch install/);

    expect(alice.memberCount).toBe(2);
    expect(alice.generation).toBe(before.generation);
    expect(await alice.getRootSecret()).toEqual(before.rootSecret);
    expect(await treeFingerprint(alice)).toBe(before.tree);
    expect(stateMetadata(alice)).toEqual(before.metadata);
    expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBe(
      welcome.leafIndex,
    );
    if (rejected === undefined) throw new Error('transaction callback did not run');

    const rejectedGeneration = rejected.pathUpdate.generation;
    overwritePathUpdate(rejected.pathUpdate);
    overwriteBytes(rejected.rootSecret);
    expect(await alice.getRootSecret()).toEqual(before.rootSecret);
    expect(await treeFingerprint(alice)).toBe(before.tree);
    expect(stateMetadata(alice)).toEqual(before.metadata);

    const retry = await alice.removeMember(welcome.leafIndex);
    expect(retry.pathUpdate.generation).toBe(rejectedGeneration);
    expect(retry.pathUpdate.senderLeafPublicKey).not.toEqual(
      rejected.pathUpdate.senderLeafPublicKey,
    );
    expect(retry.rootSecret).not.toEqual(rejected.rootSecret);
    expect(await alice.findLeafByPublicKey(bobKeys.publicKey)).toBeUndefined();
  });

  test('processWelcome preserves existing state after validation failure', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
    const beforeRoot = await bob.getRootSecret();
    const before = [bob.memberCount, bob.myLeafIndex, bob.generation];
    const badHash = new Uint8Array(welcome.treeHash);
    badHash[0] ^= 0xff;

    await expect(
      bob.processWelcome(
        { ...welcome, generation: welcome.generation + 1, treeHash: badHash },
        bobKeys.privateKey,
        bobKeys.publicKey,
      ),
    ).rejects.toThrow(/tree hash mismatch/);
    expect([bob.memberCount, bob.myLeafIndex, bob.generation]).toEqual(before);
    expect(await bob.getRootSecret()).toEqual(beforeRoot);
  });

  test('processWelcome rejects replay and v1 downgrade without mutating state', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
    const beforeRoot = await bob.getRootSecret();
    const beforeTree = await treeFingerprint(bob);

    await expect(
      bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey),
    ).rejects.toThrow(/non-increasing/);
    const {
      version: _version,
      generation: _generation,
      numLeaves: _numLeaves,
      ...legacyWelcome
    } = welcome;
    await expect(
      bob.processWelcome(
        legacyWelcome,
        bobKeys.privateKey,
        bobKeys.publicKey,
      ),
    ).rejects.toThrow(/legacy Welcome/);
    expect(bob.generation).toBe(welcome.generation);
    expect(await bob.getRootSecret()).toEqual(beforeRoot);
    expect(await treeFingerprint(bob)).toBe(beforeTree);
  });

  test('processWelcome rejects a decrypted path key that mismatches its public key', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const wrongPathKeys = await keyPair();
    const internals = alice as unknown as {
      _encryptNodeKey(
        privateKey: CryptoKey,
        publicKey: CryptoKey,
      ): Promise<Uint8Array>;
    };
    const malformed = {
      ...welcome,
      pathKeys: [
        {
          ...welcome.pathKeys[0],
          encryptedPrivateKey: await internals._encryptNodeKey(
            wrongPathKeys.privateKey,
            bobKeys.publicKey,
          ),
        },
      ],
    };
    const bob = new BeeKEM();
    await expect(
      bob.processWelcome(malformed, bobKeys.privateKey, bobKeys.publicKey),
    ).rejects.toThrow(/does not match path node/);
    expect(bob.memberCount).toBe(0);
    expect(bob.generation).toBeNull();
  });

  test('processWelcome validates a non-extractable recipient key without exporting it', async () => {
    const aliceKeys = await generateEciesKeyPair();
    const alice = new BeeKEM();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateEciesKeyPair();
    const wrongKeys = await generateEciesKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();

    expect(bobKeys.privateKey.extractable).toBe(false);
    await expect(
      bob.processWelcome(
        welcome,
        bobKeys.privateKey,
        wrongKeys.publicKey,
      ),
    ).rejects.toThrow(/recipient private key does not match public key/);
    expect(bob.memberCount).toBe(0);
    expect(bob.generation).toBeNull();

    expect(
      await bob.processWelcome(
        welcome,
        bobKeys.privateKey,
        bobKeys.publicKey,
      ),
    ).toEqual(await alice.getRootSecret());
  });

  test.each(['epoch mismatch', 'keychain failure'])(
    'transactional PathUpdate commit rolls back on %s',
    async (failure) => {
      const alice = new BeeKEM();
      const aliceKeys = await keyPair();
      await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
      const bobKeys = await keyPair();
      const { welcome } = await alice.addMember(bobKeys.publicKey);
      const bob = new BeeKEM();
      await bob.processWelcome(
        welcome,
        bobKeys.privateKey,
        bobKeys.publicKey,
      );
      const firstUpdate = await alice.update();
      await bob.processPathUpdate(firstUpdate.pathUpdate);
      const { pathUpdate, rootSecret } = await alice.update();
      const before = {
        generation: bob.generation,
        memberCount: bob.memberCount,
        rootSecret: await bob.getRootSecret(),
        tree: await treeFingerprint(bob),
        metadata: stateMetadata(bob),
      };

      await expect(
        bob.processPathUpdateTransactionally(pathUpdate, async () => {
          throw new Error(failure);
        }),
      ).rejects.toThrow(failure);
      expect(bob.generation).toBe(before.generation);
      expect(bob.memberCount).toBe(before.memberCount);
      expect(await bob.getRootSecret()).toEqual(before.rootSecret);
      expect(await treeFingerprint(bob)).toBe(before.tree);
      expect(stateMetadata(bob)).toEqual(before.metadata);

      expect(await bob.processPathUpdate(pathUpdate)).toEqual(rootSecret);
    },
  );

  test('processPathUpdate applies and fingerprints one snapshot across an awaited digest', async () => {
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
    await bob.processPathUpdate(addCarol);
    const carol = new BeeKEM();
    await carol.processWelcome(
      carolWelcome,
      carolKeys.privateKey,
      carolKeys.publicKey,
    );

    const forkA = await alice.update();
    const forkB = await bob.update();
    const mutableA = clonePathUpdate(forkA.pathUpdate);
    const digestCaptured = deferred();
    const releaseDigest = deferred();
    const internals = carol as unknown as {
      _computePathUpdateDigest(update: PathUpdateV2): Promise<Uint8Array>;
    };
    const computeDigest = internals._computePathUpdateDigest.bind(carol);
    let firstDigest = true;
    internals._computePathUpdateDigest = async (update) => {
      const digest = await computeDigest(update);
      if (firstDigest) {
        firstDigest = false;
        digestCaptured.resolve();
        await releaseDigest.promise;
      }
      return digest;
    };

    const applying = carol.processPathUpdate(mutableA);
    await digestCaptured.promise;
    Object.assign(mutableA, clonePathUpdate(forkB.pathUpdate));
    releaseDigest.resolve();

    await expect(applying).resolves.toEqual(forkA.rootSecret);
    await expect(
      carol.processPathUpdate(forkA.pathUpdate),
    ).resolves.toEqual(forkA.rootSecret);
    await expect(carol.processPathUpdate(forkB.pathUpdate)).rejects.toThrow(
      /Conflicting BeeKEM update/,
    );
    expect(await carol.getRootSecret()).toEqual(forkA.rootSecret);
  });

  test('processWelcome consumes one snapshot across its awaited tree digest', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome, rootSecret } = await alice.addMember(bobKeys.publicKey);
    const mutableWelcome = cloneWelcome(welcome);
    const digestCaptured = deferred();
    const releaseDigest = deferred();
    const bob = new BeeKEM();
    const internals = bob as unknown as {
      _computeTreeHashV2(
        nodes: Map<number, TreeNode>,
        numLeaves: number,
      ): Promise<Uint8Array>;
    };
    const computeTreeHash = internals._computeTreeHashV2.bind(bob);
    let firstDigest = true;
    internals._computeTreeHashV2 = async (nodes, numLeaves) => {
      const digest = await computeTreeHash(nodes, numLeaves);
      if (firstDigest) {
        firstDigest = false;
        digestCaptured.resolve();
        await releaseDigest.promise;
      }
      return digest;
    };

    const joining = bob.processWelcome(
      mutableWelcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );
    await digestCaptured.promise;
    overwriteWelcome(mutableWelcome);
    releaseDigest.resolve();

    await expect(joining).resolves.toEqual(rootSecret);
    expect(await bob.getRootSecret()).toEqual(rootSecret);
    expect(bob.generation).toBe(welcome.generation);
  });

  test('runtime PathUpdate snapshot rejects accessors, byte-view proxies, and shared backing', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
    const { pathUpdate } = await alice.update();
    const before = stateMetadata(bob);
    const beforeTree = await treeFingerprint(bob);

    let getterCalls = 0;
    const accessor = clonePathUpdate(pathUpdate);
    Object.defineProperty(accessor, 'generation', {
      enumerable: true,
      get() {
        getterCalls++;
        return pathUpdate.generation;
      },
    });
    await expect(bob.processPathUpdate(accessor)).rejects.toThrow(
      /data properties/,
    );
    expect(getterCalls).toBe(0);

    let byteProxyReads = 0;
    const proxiedBytes = clonePathUpdate(pathUpdate);
    proxiedBytes.treeHash = new Proxy(proxiedBytes.treeHash, {
      get(target, property, receiver) {
        byteProxyReads++;
        return Reflect.get(target, property, receiver);
      },
    });
    await expect(bob.processPathUpdate(proxiedBytes)).rejects.toThrow(
      /non-plain object/,
    );
    expect(byteProxyReads).toBe(0);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedBytes = clonePathUpdate(pathUpdate);
      sharedBytes.nodes[0].publicKey = new Uint8Array(
        new SharedArrayBuffer(65),
      );
      await expect(bob.processPathUpdate(sharedBytes)).rejects.toThrow(
        /invalid length or backing buffer/,
      );
    }

    expect(stateMetadata(bob)).toEqual(before);
    expect(await treeFingerprint(bob)).toBe(beforeTree);
  });

  test('runtime snapshot budget admits the maximum-width v2 public tree', async () => {
    const publicKey = new Uint8Array(65).fill(1);
    const maximumWidthUpdate: PathUpdateV2 = {
      version: 2,
      generation: 1,
      parentTreeHash: new Uint8Array(32).fill(2),
      numLeaves: MAX_BEEKEM_TREE_LEAVES,
      senderLeafIndex: 0,
      senderLeafPublicKey: publicKey,
      nodes: [],
      treeNodePublicKeys: Array.from(
        { length: 2 * MAX_BEEKEM_TREE_LEAVES - 1 },
        (_, nodeIndex) => ({ nodeIndex, publicKey }),
      ),
      treeHash: new Uint8Array(32).fill(3),
    };

    await expect(
      new BeeKEM().processPathUpdate(maximumWidthUpdate),
    ).rejects.toThrow(/without generation-bearing parent state/);
  });

  test('runtime Welcome snapshot rejects accessors, byte-view proxies, and shared backing', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);

    let getterCalls = 0;
    const accessor = cloneWelcome(welcome);
    Object.defineProperty(accessor, 'leafIndex', {
      enumerable: true,
      get() {
        getterCalls++;
        return welcome.leafIndex;
      },
    });
    const accessorReceiver = new BeeKEM();
    await expect(
      accessorReceiver.processWelcome(
        accessor,
        bobKeys.privateKey,
        bobKeys.publicKey,
      ),
    ).rejects.toThrow(/data properties/);
    expect(getterCalls).toBe(0);
    expect(accessorReceiver.memberCount).toBe(0);

    let byteProxyReads = 0;
    const proxiedBytes = cloneWelcome(welcome);
    proxiedBytes.pathKeys[0].encryptedPrivateKey = new Proxy(
      proxiedBytes.pathKeys[0].encryptedPrivateKey,
      {
        get(target, property, receiver) {
          byteProxyReads++;
          return Reflect.get(target, property, receiver);
        },
      },
    );
    const proxyReceiver = new BeeKEM();
    await expect(
      proxyReceiver.processWelcome(
        proxiedBytes,
        bobKeys.privateKey,
        bobKeys.publicKey,
      ),
    ).rejects.toThrow(/non-plain object/);
    expect(byteProxyReads).toBe(0);
    expect(proxyReceiver.memberCount).toBe(0);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedBytes = cloneWelcome(welcome);
      sharedBytes.treeHash = new Uint8Array(new SharedArrayBuffer(32));
      const sharedReceiver = new BeeKEM();
      await expect(
        sharedReceiver.processWelcome(
          sharedBytes,
          bobKeys.privateKey,
          bobKeys.publicKey,
        ),
      ).rejects.toThrow(/invalid length or backing buffer/);
      expect(sharedReceiver.memberCount).toBe(0);
    }
  });

  test('transactional PathUpdate rejects a legacy downgrade before mutation', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
    const { pathUpdate } = await alice.update();
    const {
      version: _version,
      generation: _generation,
      numLeaves: _numLeaves,
      treeNodePublicKeys: _treeNodePublicKeys,
      treeHash: _treeHash,
      ...legacyPathUpdate
    } = pathUpdate;
    const before = {
      generation: bob.generation,
      memberCount: bob.memberCount,
      rootSecret: await bob.getRootSecret(),
      tree: await treeFingerprint(bob),
    };
    let commitCalled = false;

    await expect(
      bob.processPathUpdateTransactionally(legacyPathUpdate, async () => {
        commitCalled = true;
      }),
    ).rejects.toThrow(/legacy BeeKEM PathUpdate/);

    expect(commitCalled).toBe(false);
    expect(bob.generation).toBe(before.generation);
    expect(bob.memberCount).toBe(before.memberCount);
    expect(await bob.getRootSecret()).toEqual(before.rootSecret);
    expect(await treeFingerprint(bob)).toBe(before.tree);
  });

  test('v2 PathUpdate cannot jump the append-only leaf topology', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
    const { pathUpdate } = await alice.update();
    const jump = clonePathUpdate(pathUpdate);
    jump.numLeaves = 4;
    jump.treeNodePublicKeys.push(
      { nodeIndex: 3, publicKey: null },
      { nodeIndex: 4, publicKey: null },
      { nodeIndex: 5, publicKey: null },
      { nodeIndex: 6, publicKey: null },
    );
    const before = stateMetadata(bob);
    const beforeTree = await treeFingerprint(bob);

    await expect(bob.processPathUpdate(jump)).rejects.toThrow(
      /leaf count must remain 2 or append exactly one leaf/,
    );
    const shrink = clonePathUpdate(pathUpdate);
    shrink.numLeaves = 1;
    shrink.nodes = [];
    shrink.treeNodePublicKeys = [shrink.treeNodePublicKeys[0]];
    await expect(bob.processPathUpdate(shrink)).rejects.toThrow(
      /leaf count must remain 2 or append exactly one leaf/,
    );
    expect(stateMetadata(bob)).toEqual(before);
    expect(await treeFingerprint(bob)).toBe(beforeTree);
  });

  test('v2 PathUpdate enforces the exact leaf-level add, remove, and update rules', async () => {
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

    const rewrittenExisting = clonePathUpdate(addCarol);
    const unrelatedKeys = await keyPair();
    rewrittenExisting.treeNodePublicKeys[2].publicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', unrelatedKeys.publicKey),
    );
    await expect(bob.processPathUpdate(rewrittenExisting)).rejects.toThrow(
      /cannot rewrite another live leaf public key/,
    );

    const blankAppend = clonePathUpdate(addCarol);
    blankAppend.treeNodePublicKeys[4].publicKey = null;
    await expect(bob.processPathUpdate(blankAppend)).rejects.toThrow(
      /append must add one live rightmost leaf/,
    );

    const addAndRemove = clonePathUpdate(addCarol);
    addAndRemove.treeNodePublicKeys[2].publicKey = null;
    await expect(bob.processPathUpdate(addAndRemove)).rejects.toThrow(
      /append cannot remove an existing live leaf/,
    );
    await bob.processPathUpdate(addCarol);

    const ordinaryUpdate = await alice.update();
    const removesTwo = clonePathUpdate(ordinaryUpdate.pathUpdate);
    removesTwo.treeNodePublicKeys[2].publicKey = null;
    removesTwo.treeNodePublicKeys[4].publicKey = null;
    await expect(bob.processPathUpdate(removesTwo)).rejects.toThrow(
      /cannot remove more than one live leaf/,
    );
    await bob.processPathUpdate(ordinaryUpdate.pathUpdate);

    const removal = await alice.removeMember(carolWelcome.leafIndex);
    await bob.processPathUpdate(removal.pathUpdate);
    const postRemovalUpdate = await alice.update();
    const reactivatesBlank = clonePathUpdate(postRemovalUpdate.pathUpdate);
    reactivatesBlank.treeNodePublicKeys[carolWelcome.leafIndex].publicKey =
      new Uint8Array(65).fill(7);
    await expect(bob.processPathUpdate(reactivatesBlank)).rejects.toThrow(
      /cannot reactivate an append-only blank leaf/,
    );
  });

  test('concurrent updates serialize into distinct generations', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);

    const [first, second] = await Promise.all([
      alice.update(),
      alice.update(),
    ]);
    expect([first.pathUpdate.generation, second.pathUpdate.generation]).toEqual([
      2, 3,
    ]);
    await bob.processPathUpdate(first.pathUpdate);
    expect(await bob.processPathUpdate(second.pathUpdate)).toEqual(
      second.rootSecret,
    );
  });

  test('processWelcome accepts the canonical non-extractable recipient key', async () => {
    const aliceKeys = await generateEciesKeyPair();
    const alice = new BeeKEM();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateEciesKeyPair();
    expect(bobKeys.privateKey.extractable).toBe(false);
    const { welcome, rootSecret } = await alice.addMember(
      bobKeys.publicKey,
    );
    const bob = new BeeKEM();
    expect(
      await bob.processWelcome(
        welcome,
        bobKeys.privateKey,
        bobKeys.publicKey,
      ),
    ).toEqual(rootSecret);
  });
});
