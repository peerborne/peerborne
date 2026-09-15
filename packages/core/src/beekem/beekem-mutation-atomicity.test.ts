import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

async function twoMemberGroup(): Promise<{
  alice: BeeKEM;
  aliceKeys: CryptoKeyPair;
  bob: BeeKEM;
  bobKeys: CryptoKeyPair;
}> {
  const alice = new BeeKEM();
  const aliceKeys = await generateKeyPair();
  await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
  const bobKeys = await generateKeyPair();
  const { welcome } = await alice.addMember(bobKeys.publicKey);
  const bob = new BeeKEM();
  await bob.processWelcome(
    welcome,
    bobKeys.privateKey,
    bobKeys.publicKey,
  );
  return { alice, aliceKeys, bob, bobKeys };
}

function nodesOf(beekem: BeeKEM): Map<number, unknown> {
  return (beekem as unknown as { _nodes: Map<number, unknown> })._nodes;
}

describe('BeeKEM mutation atomicity', () => {
  test('reserves a remote update before inspecting Proxy descriptors', async () => {
    const { alice, bob } = await twoMemberGroup();
    const older = await bob.update();
    const latest = await bob.update();
    let nestedOutcome:
      | Promise<
          | { kind: 'fulfilled'; value: Uint8Array }
          | { kind: 'rejected'; error: unknown }
        >
      | undefined;
    const proxied = new Proxy(older.pathUpdate, {
      getOwnPropertyDescriptor(target, property) {
        nestedOutcome ??= alice.processPathUpdate(latest.pathUpdate).then(
          (value) => ({ kind: 'fulfilled' as const, value }),
          (error: unknown) => ({ kind: 'rejected' as const, error }),
        );
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    await expect(alice.processPathUpdate(proxied)).resolves.toEqual(
      older.rootSecret,
    );
    expect(nestedOutcome).toBeDefined();
    const nested = await nestedOutcome!;
    expect(nested.kind).toBe('rejected');
    if (nested.kind === 'rejected') {
      expect(nested.error).toEqual(
        expect.objectContaining({
          message: expect.stringMatching(/during another BeeKEM mutation/),
        }),
      );
    }
    await expect(alice.getRootSecret()).resolves.toEqual(older.rootSecret);

    await expect(
      alice.processPathUpdate(latest.pathUpdate),
    ).resolves.toEqual(latest.rootSecret);
  });

  test('keeps the live tree unchanged while member onboarding is in flight', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const originalNodes = nodesOf(alice);
    const originalRoot = await alice.getRootSecret();
    const bobKeys = await generateKeyPair();
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let digestCalls = 0;
    let entered!: () => void;
    let release!: () => void;
    const paused = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const digestSpy = jest
      .spyOn(crypto.subtle, 'digest')
      .mockImplementation(async (algorithm, data) => {
        digestCalls++;
        if (digestCalls === 2) {
          entered();
          await gate;
        }
        return originalDigest(algorithm, data);
      });

    const onboarding = alice.addMember(bobKeys.publicKey);
    try {
      await paused;
      expect(alice.memberCount).toBe(1);
      expect(nodesOf(alice)).toBe(originalNodes);
      await expect(
        alice.findLeafByPublicKey(bobKeys.publicKey),
      ).resolves.toBeUndefined();
      await expect(alice.getRootSecret()).resolves.toEqual(originalRoot);
      release();
      await expect(onboarding).resolves.toEqual(
        expect.objectContaining({
          rootSecret: expect.any(Uint8Array),
        }),
      );
    } finally {
      release();
      await onboarding.catch(() => undefined);
      digestSpy.mockRestore();
    }
    expect(alice.memberCount).toBe(2);
    await expect(
      alice.findLeafByPublicKey(bobKeys.publicKey),
    ).resolves.toBe(2);
  });

  test('does not strand the local leaf when update key export fails', async () => {
    const { alice, aliceKeys, bob } = await twoMemberGroup();
    const originalNodes = nodesOf(alice);
    const originalRoot = await alice.getRootSecret();
    const exportSpy = jest.spyOn(crypto.subtle, 'exportKey');
    exportSpy.mockImplementationOnce(async () => {
      throw new Error('injected update export failure');
    });

    try {
      await expect(alice.update()).rejects.toThrow(
        'injected update export failure',
      );
    } finally {
      exportSpy.mockRestore();
    }

    expect(nodesOf(alice)).toBe(originalNodes);
    await expect(alice.getRootSecret()).resolves.toEqual(originalRoot);
    await expect(
      alice.findLeafByPublicKey(aliceKeys.publicKey),
    ).resolves.toBe(0);

    const peerUpdate = await bob.update();
    await expect(
      alice.processPathUpdate(peerUpdate.pathUpdate),
    ).resolves.toEqual(peerUpdate.rootSecret);
  });

  test('does not blank a member when removal key generation fails', async () => {
    const { alice, bobKeys } = await twoMemberGroup();
    const originalNodes = nodesOf(alice);
    const originalRoot = await alice.getRootSecret();
    const generateSpy = jest.spyOn(crypto.subtle, 'generateKey');
    generateSpy.mockImplementationOnce(async () => {
      throw new Error('injected removal key-generation failure');
    });

    try {
      await expect(alice.removeMember(2)).rejects.toThrow(
        'injected removal key-generation failure',
      );
    } finally {
      generateSpy.mockRestore();
    }

    expect(nodesOf(alice)).toBe(originalNodes);
    await expect(alice.getRootSecret()).resolves.toEqual(originalRoot);
    await expect(
      alice.findLeafByPublicKey(bobKeys.publicKey),
    ).resolves.toBe(2);

    await expect(alice.removeMember(2)).resolves.toEqual(
      expect.objectContaining({ rootSecret: expect.any(Uint8Array) }),
    );
    await expect(
      alice.findLeafByPublicKey(bobKeys.publicKey),
    ).resolves.toBeUndefined();
  });

  test('rejects invalid, inactive, and local removal targets without mutation', async () => {
    const { alice, bobKeys } = await twoMemberGroup();
    const originalNodes = nodesOf(alice);
    const originalRoot = await alice.getRootSecret();

    for (const target of [
      -1,
      1,
      2.5,
      3,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 1,
    ]) {
      await expect(alice.removeMember(target)).rejects.toThrow(
        /target must identify a leaf in the current tree/,
      );
      expect(nodesOf(alice)).toBe(originalNodes);
      await expect(alice.getRootSecret()).resolves.toEqual(originalRoot);
    }
    await expect(alice.removeMember(0)).rejects.toThrow(
      /cannot remove the local member/,
    );
    expect(nodesOf(alice)).toBe(originalNodes);

    await alice.removeMember(2);
    const removedNodes = nodesOf(alice);
    const removedRoot = await alice.getRootSecret();
    await expect(alice.removeMember(2)).rejects.toThrow(
      /target is not an active tree leaf/,
    );
    expect(nodesOf(alice)).toBe(removedNodes);
    await expect(alice.getRootSecret()).resolves.toEqual(removedRoot);
    await expect(
      alice.findLeafByPublicKey(bobKeys.publicKey),
    ).resolves.toBeUndefined();
  });

  test('leaves a fresh tree eligible for Welcome after local mutations reject', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const recipientKeys = await generateKeyPair();
    const { welcome, rootSecret } = await founder.addMember(
      recipientKeys.publicKey,
    );
    const target = new BeeKEM();
    const pristineNodes = nodesOf(target);

    await expect(target.update()).rejects.toThrow(
      /Cannot update: BeeKEM tree state is invalid/,
    );
    await expect(target.removeMember(0)).rejects.toThrow(
      /Cannot remove member: BeeKEM tree state is invalid/,
    );
    await expect(target.addMember(recipientKeys.publicKey)).rejects.toThrow(
      /Cannot add member: BeeKEM tree state is invalid/,
    );
    expect(nodesOf(target)).toBe(pristineNodes);
    expect(target.memberCount).toBe(0);
    expect(target.myLeafIndex).toBe(-1);

    await expect(
      target.processWelcome(
        welcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
  });
});
