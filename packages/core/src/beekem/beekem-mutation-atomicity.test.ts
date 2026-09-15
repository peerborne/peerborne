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
    expect(nested).toEqual({ kind: 'fulfilled', value: latest.rootSecret });
    await expect(alice.getRootSecret()).resolves.toEqual(latest.rootSecret);
  });

  test('reentrant forbidden-marker checks preserve mutation call order', async () => {
    const { alice, bob } = await twoMemberGroup();
    const update = await bob.update();
    let nestedOutcome:
      | Promise<
          | { kind: 'fulfilled'; value: Uint8Array }
          | { kind: 'rejected'; error: unknown }
        >
      | undefined;
    const proxied = new Proxy(update.pathUpdate, {
      has(target, property) {
        if (property === 'version') {
          nestedOutcome ??= alice.processPathUpdate(update.pathUpdate).then(
            (value) => ({ kind: 'fulfilled' as const, value }),
            (error: unknown) => ({ kind: 'rejected' as const, error }),
          );
          return true;
        }
        return Reflect.has(target, property);
      },
    });

    await expect(alice.processPathUpdate(proxied)).rejects.toMatchObject({
      cause: expect.objectContaining({
        message: expect.stringContaining("forbidden field 'version'"),
      }),
    });
    expect(nestedOutcome).toBeDefined();
    await expect(nestedOutcome!).resolves.toEqual({
      kind: 'fulfilled',
      value: update.rootSecret,
    });
    await expect(alice.getRootSecret()).resolves.toEqual(update.rootSecret);
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

  test('rejects ECDH-incompatible founder keys without initializing', async () => {
    const target = new BeeKEM();
    const founderKeys = (await crypto.subtle.generateKey(
      ECDH_ALGO,
      false,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const unrelatedKeys = await generateKeyPair();
    const pristineNodes = nodesOf(target);

    await expect(
      target.initialize(founderKeys.privateKey, unrelatedKeys.publicKey),
    ).rejects.toThrow(
      /founder leaf 0 public and private keys are not ECDH-compatible/,
    );
    expect(nodesOf(target)).toBe(pristineNodes);
    expect(target.memberCount).toBe(0);
    expect(target.myLeafIndex).toBe(-1);

    await expect(
      target.initialize(founderKeys.privateKey, founderKeys.publicKey),
    ).resolves.toBeUndefined();
    await expect(
      target.findLeafByPublicKey(founderKeys.publicKey),
    ).resolves.toBe(0);
  });

  test('does not commit a Welcome ahead of an earlier initialization', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const recipientKeys = await generateKeyPair();
    const { welcome } = await founder.addMember(recipientKeys.publicKey);
    const initializationKeys = await generateKeyPair();
    const target = new BeeKEM();
    const internals = target as unknown as {
      _registerWelcomeCandidate(
        revision: bigint,
        staged: BeeKEM,
        rootSecret: Uint8Array,
      ): Promise<Uint8Array>;
    };

    let initializationEntered!: () => void;
    let releaseInitialization!: () => void;
    const entered = new Promise<void>((resolve) => {
      initializationEntered = resolve;
    });
    const initializationGate = new Promise<void>((resolve) => {
      releaseInitialization = resolve;
    });
    let candidateReady!: () => void;
    const ready = new Promise<void>((resolve) => {
      candidateReady = resolve;
    });
    const originalRegister = internals._registerWelcomeCandidate.bind(target);
    internals._registerWelcomeCandidate = (revision, staged, rootSecret) => {
      candidateReady();
      return originalRegister(revision, staged, rootSecret);
    };

    const originalGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle);
    let generateCalls = 0;
    const generateSpy = jest
      .spyOn(crypto.subtle, 'generateKey')
      .mockImplementation(async (algorithm, extractable, keyUsages) => {
        generateCalls++;
        if (generateCalls === 1) {
          initializationEntered();
          await initializationGate;
        }
        return originalGenerateKey(algorithm, extractable, keyUsages);
      });

    const initialization = target.initialize(
      initializationKeys.privateKey,
      initializationKeys.publicKey,
    );
    let joining:
      | Promise<
          | { kind: 'fulfilled'; value: Uint8Array }
          | { kind: 'rejected'; error: unknown }
        >
      | undefined;
    try {
      await entered;
      let joiningSettled = false;
      joining = target.processWelcome(
        welcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ).then(
        (value) => {
          joiningSettled = true;
          return { kind: 'fulfilled' as const, value };
        },
        (error: unknown) => {
          joiningSettled = true;
          return { kind: 'rejected' as const, error };
        },
      );
      await ready;
      await Promise.resolve();
      expect(joiningSettled).toBe(false);

      releaseInitialization();
      await expect(initialization).resolves.toBeUndefined();
      await expect(joining).resolves.toEqual({
        kind: 'rejected',
        error: expect.objectContaining({
          message: expect.stringMatching(/superseded|receiver state changed/),
        }),
      });
    } finally {
      releaseInitialization();
      await Promise.allSettled(
        joining === undefined ? [initialization] : [initialization, joining],
      );
      generateSpy.mockRestore();
    }

    await expect(
      target.findLeafByPublicKey(initializationKeys.publicKey),
    ).resolves.toBe(0);
    await expect(
      target.findLeafByPublicKey(recipientKeys.publicKey),
    ).resolves.toBeUndefined();
  });

  test('releases a staged Welcome when an earlier initialization fails', async () => {
    const founder = new BeeKEM();
    const founderKeys = await generateKeyPair();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const recipientKeys = await generateKeyPair();
    const { welcome, rootSecret } = await founder.addMember(
      recipientKeys.publicKey,
    );
    const initializationKeys = await generateKeyPair();
    const unrelatedKeys = await generateKeyPair();
    const target = new BeeKEM();
    const internals = target as unknown as {
      _registerWelcomeCandidate(
        revision: bigint,
        staged: BeeKEM,
        rootSecret: Uint8Array,
      ): Promise<Uint8Array>;
    };

    let initializationEntered!: () => void;
    let releaseInitialization!: () => void;
    const entered = new Promise<void>((resolve) => {
      initializationEntered = resolve;
    });
    const initializationGate = new Promise<void>((resolve) => {
      releaseInitialization = resolve;
    });
    let candidateReady!: () => void;
    const ready = new Promise<void>((resolve) => {
      candidateReady = resolve;
    });
    const originalRegister = internals._registerWelcomeCandidate.bind(target);
    internals._registerWelcomeCandidate = (revision, staged, candidateRoot) => {
      candidateReady();
      return originalRegister(revision, staged, candidateRoot);
    };

    const originalGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle);
    let generateCalls = 0;
    const generateSpy = jest
      .spyOn(crypto.subtle, 'generateKey')
      .mockImplementation(async (algorithm, extractable, keyUsages) => {
        generateCalls++;
        if (generateCalls === 1) {
          initializationEntered();
          await initializationGate;
        }
        return originalGenerateKey(algorithm, extractable, keyUsages);
      });

    const initialization = target.initialize(
      initializationKeys.privateKey,
      unrelatedKeys.publicKey,
    );
    let joining: Promise<Uint8Array> | undefined;
    try {
      await entered;
      let joiningSettled = false;
      joining = target.processWelcome(
        welcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      );
      void joining.then(
        () => {
          joiningSettled = true;
        },
        () => {
          joiningSettled = true;
        },
      );
      await ready;
      await Promise.resolve();
      expect(joiningSettled).toBe(false);

      releaseInitialization();
      await expect(initialization).rejects.toThrow(/not ECDH-compatible/);
      await expect(joining).resolves.toEqual(rootSecret);
    } finally {
      releaseInitialization();
      await Promise.allSettled(
        joining === undefined ? [initialization] : [initialization, joining],
      );
      generateSpy.mockRestore();
    }

    await expect(target.getRootSecret()).resolves.toEqual(rootSecret);
    await expect(
      target.findLeafByPublicKey(recipientKeys.publicKey),
    ).resolves.toBe(2);
  });
});
