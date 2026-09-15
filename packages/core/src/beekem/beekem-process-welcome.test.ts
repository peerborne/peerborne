import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import {
  BeeKEMWelcome,
  MAX_BEEKEM_TREE_LEAVES,
} from './types.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function copyWelcome(welcome: BeeKEMWelcome): BeeKEMWelcome {
  return {
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

async function createTwoMemberWelcome(
  recipientKeyPair?: CryptoKeyPair,
): Promise<{
  welcome: BeeKEMWelcome;
  recipientKeys: CryptoKeyPair;
  rootSecret: Uint8Array;
}> {
  const founder = new BeeKEM();
  const founderKeys = await generateKeyPair();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
  const recipientKeys = recipientKeyPair ?? (await generateKeyPair());
  const { welcome, rootSecret } = await founder.addMember(
    recipientKeys.publicKey,
  );
  return { welcome, recipientKeys, rootSecret };
}

async function createInitializedTarget(): Promise<{
  target: BeeKEM;
  keys: CryptoKeyPair;
  rootSecret: Uint8Array;
}> {
  const target = new BeeKEM();
  const keys = await generateKeyPair();
  await target.initialize(keys.privateKey, keys.publicKey);
  return { target, keys, rootSecret: await target.getRootSecret() };
}

async function expectTargetUnchanged(
  target: BeeKEM,
  keys: CryptoKeyPair,
  rootSecret: Uint8Array,
): Promise<void> {
  expect(target.memberCount).toBe(1);
  expect(target.myLeafIndex).toBe(0);
  expect(await target.findLeafByPublicKey(keys.publicKey)).toBe(0);
  expect(await target.getRootSecret()).toEqual(rootSecret);
}

async function expectTargetPristine(target: BeeKEM): Promise<void> {
  expect(target.memberCount).toBe(0);
  expect(target.myLeafIndex).toBe(-1);
  expect(
    (target as unknown as { _nodes: Map<number, unknown> })._nodes.size,
  ).toBe(0);
  await expect(target.getRootSecret()).rejects.toThrow('Tree is empty');
}

function pauseNextDigest(): {
  entered: Promise<void>;
  release: () => void;
  restore: () => void;
} {
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
  const spy = jest
    .spyOn(crypto.subtle, 'digest')
    .mockImplementation(async (algorithm, data) => {
      if (!paused) {
        paused = true;
        enter();
        await gate;
      }
      return originalDigest(algorithm, data);
    });
  return { entered, release, restore: () => spy.mockRestore() };
}

describe('BeeKEM.processWelcome runtime boundary', () => {
  test('rejects huge leaf indices and over-bound trees without changing state', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        { ...copyWelcome(welcome), leafIndex: Number.MAX_SAFE_INTEGER },
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/rightmost leaf/);
    await expectTargetPristine(target);

    let getterCalls = 0;
    const oversizedTree = new Array(2 * MAX_BEEKEM_TREE_LEAVES - 2);
    Object.defineProperty(oversizedTree, '0', {
      enumerable: true,
      get() {
        getterCalls++;
        return null;
      },
    });
    await expect(
      target.processWelcome(
        {
          ...copyWelcome(welcome),
          treeNodePublicKeys: oversizedTree,
        },
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/supported tree width/);
    expect(getterCalls).toBe(0);
    await expectTargetPristine(target);
  });

  test('rejects accessors without invoking them or changing state', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const target = new BeeKEM();
    const accessorWelcome = copyWelcome(welcome);
    const encryptedPrivateKey =
      accessorWelcome.pathKeys[0].encryptedPrivateKey;
    let getterCalls = 0;
    Object.defineProperty(accessorWelcome.pathKeys[0], 'encryptedPrivateKey', {
      enumerable: true,
      get() {
        getterCalls++;
        return encryptedPrivateKey;
      },
    });

    await expect(
      target.processWelcome(
        accessorWelcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/own enumerable data property/);
    expect(getterCalls).toBe(0);
    await expectTargetPristine(target);
  });

  test('uses a detached snapshot when caller-owned input changes in flight', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const mutableWelcome = copyWelcome(welcome);
    const pathNode = mutableWelcome.pathKeys[0];
    const treeNode = mutableWelcome.treeNodePublicKeys[0];

    const target = new BeeKEM();
    const processing = target.processWelcome(
      mutableWelcome,
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    mutableWelcome.leafIndex = Number.MAX_SAFE_INTEGER;
    pathNode.nodeIndex = 0;
    pathNode.publicKey.fill(0);
    pathNode.encryptedPrivateKey.fill(0);
    treeNode.nodeIndex = 1;
    treeNode.publicKey?.fill(0);
    mutableWelcome.pathKeys.length = 0;
    mutableWelcome.treeNodePublicKeys.length = 0;
    mutableWelcome.treeHash.fill(0);

    await expect(processing).resolves.toEqual(rootSecret);
    expect(target.memberCount).toBe(2);
    expect(target.myLeafIndex).toBe(2);
  });

  test('rejects a Welcome on an initialized receiver without running crypto', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const { target, keys, rootSecret } = await createInitializedTarget();
    const importSpy = jest.spyOn(crypto.subtle, 'importKey');

    try {
      await expect(
        target.processWelcome(
          copyWelcome(welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow(/non-fresh BeeKEM tree/);
      expect(importSpy).not.toHaveBeenCalled();
    } finally {
      importSpy.mockRestore();
    }
    await expectTargetUnchanged(target, keys, rootSecret);
  });

  test('prevents an older concurrent Welcome from overwriting the latest attempt', async () => {
    const recipientKeys = await generateKeyPair();
    const older = await createTwoMemberWelcome(recipientKeys);
    const latest = await createTwoMemberWelcome(recipientKeys);
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const olderProcessing = target.processWelcome(
      copyWelcome(older.welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );
    const olderOutcome = olderProcessing.then(
      (value) => ({ kind: 'fulfilled' as const, value }),
      (error: unknown) => ({ kind: 'rejected' as const, error }),
    );

    let outcome!: Awaited<typeof olderOutcome>;
    try {
      await digest.entered;
      await expect(
        target.processWelcome(
          copyWelcome(latest.welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).resolves.toEqual(latest.rootSecret);
      digest.release();
      outcome = await olderOutcome;
    } finally {
      digest.release();
      digest.restore();
    }

    expect(outcome.kind).toBe('rejected');
    if (outcome.kind === 'rejected') {
      expect(outcome.error).toEqual(
        expect.objectContaining({
          message: expect.stringMatching(/superseded/),
        }),
      );
    }
    expect(await target.getRootSecret()).toEqual(latest.rootSecret);
    expect(await target.getRootSecret()).not.toEqual(older.rootSecret);
  });

  test('does not overwrite initialization that occurs while a Welcome is in flight', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const initializedKeys = await generateKeyPair();
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const processing = target.processWelcome(
      copyWelcome(welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );
    const outcome = processing.then(
      (value) => ({ kind: 'fulfilled' as const, value }),
      (error: unknown) => ({ kind: 'rejected' as const, error }),
    );

    let initializedRoot!: Uint8Array;
    let settled!: Awaited<typeof outcome>;
    try {
      await digest.entered;
      await target.initialize(
        initializedKeys.privateKey,
        initializedKeys.publicKey,
      );
      initializedRoot = await target.getRootSecret();
      digest.release();
      settled = await outcome;
    } finally {
      digest.release();
      digest.restore();
    }

    expect(settled.kind).toBe('rejected');
    if (settled.kind === 'rejected') {
      expect(settled.error).toEqual(
        expect.objectContaining({
          message: expect.stringMatching(/receiver state changed/),
        }),
      );
    }
    await expectTargetUnchanged(target, initializedKeys, initializedRoot);
  });

  test('snapshots Proxy-backed records without property reads', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const detached = copyWelcome(welcome);
    let propertyReads = 0;
    const guardReads = <T extends object>(value: T): T =>
      new Proxy(value, {
        get() {
          propertyReads++;
          throw new Error('Welcome property was read through a Proxy');
        },
      });
    const pathKeys = guardReads(
      detached.pathKeys.map((node) => guardReads(node)),
    );
    const treeNodePublicKeys = guardReads(
      detached.treeNodePublicKeys.map((node) => guardReads(node)),
    );
    const proxied = guardReads({
      leafIndex: detached.leafIndex,
      pathKeys,
      treeNodePublicKeys,
      treeHash: detached.treeHash,
    });
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        proxied,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
    expect(propertyReads).toBe(0);
  });

  test('rejects shared and Proxy-wrapped byte views without reading properties', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const target = new BeeKEM();

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedWelcome = copyWelcome(welcome);
      const source = sharedWelcome.pathKeys[0].publicKey;
      const shared = new Uint8Array(new SharedArrayBuffer(source.byteLength));
      shared.set(source);
      sharedWelcome.pathKeys[0].publicKey = shared;
      await expect(
        target.processWelcome(
          sharedWelcome,
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow(/unshared Uint8Array/);
      await expectTargetPristine(target);
    }

    const proxiedWelcome = copyWelcome(welcome);
    let propertyReads = 0;
    proxiedWelcome.pathKeys[0].publicKey = new Proxy(
      proxiedWelcome.pathKeys[0].publicKey,
      {
        get() {
          propertyReads++;
          throw new Error('byte property was read through a Proxy');
        },
      },
    );
    await expect(
      target.processWelcome(
        proxiedWelcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/unshared Uint8Array/);
    expect(propertyReads).toBe(0);
    await expectTargetPristine(target);
    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
  });

  test('leaves a fresh receiver retryable after malformed key, ciphertext, and hash input', async () => {
    const { welcome, recipientKeys, rootSecret: invitedRoot } =
      await createTwoMemberWelcome();
    const invalidPublicKey = copyWelcome(welcome);
    invalidPublicKey.pathKeys[0].publicKey.fill(0);
    const invalidCiphertext = copyWelcome(welcome);
    invalidCiphertext.pathKeys[0].encryptedPrivateKey[
      invalidCiphertext.pathKeys[0].encryptedPrivateKey.length - 1
    ] ^= 0xff;
    const invalidHash = copyWelcome(welcome);
    invalidHash.treeHash[0] ^= 0xff;

    for (const failingWelcome of [
      invalidPublicKey,
      invalidCiphertext,
      invalidHash,
    ]) {
      const target = new BeeKEM();
      await expect(
        target.processWelcome(
          failingWelcome,
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow();
      await expectTargetPristine(target);

      await expect(
        target.processWelcome(
          copyWelcome(welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).resolves.toEqual(invitedRoot);
    }
  });

  test.each([
    'importKey',
    'deriveBits',
    'deriveKey',
    'decrypt',
    'exportKey',
    'digest',
  ] as const)(
    'leaves a fresh receiver retryable when subtle.%s rejects',
    async (methodName) => {
      const { welcome, recipientKeys, rootSecret } =
        await createTwoMemberWelcome();
      const target = new BeeKEM();
      const spy = jest.spyOn(crypto.subtle, methodName);
      spy.mockImplementationOnce(async () => {
        throw new Error(`injected ${methodName} failure`);
      });

      try {
        await expect(
          target.processWelcome(
            copyWelcome(welcome),
            recipientKeys.privateKey,
            recipientKeys.publicKey,
          ),
        ).rejects.toThrow(`injected ${methodName} failure`);
      } finally {
        spy.mockRestore();
      }
      await expectTargetPristine(target);
      await expect(
        target.processWelcome(
          copyWelcome(welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).resolves.toEqual(rootSecret);
    },
  );

  test('does not commit when root-secret hashing fails after tree verification', async () => {
    const { welcome, recipientKeys, rootSecret: invitedRoot } =
      await createTwoMemberWelcome();
    const target = new BeeKEM();
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let digestCalls = 0;
    const digestSpy = jest
      .spyOn(crypto.subtle, 'digest')
      .mockImplementation(async (algorithm, data) => {
        digestCalls++;
        if (digestCalls === 2) {
          throw new Error('injected root-secret hash failure');
        }
        return originalDigest(algorithm, data);
      });

    try {
      await expect(
        target.processWelcome(
          copyWelcome(welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow('injected root-secret hash failure');
    } finally {
      digestSpy.mockRestore();
    }
    expect(digestCalls).toBe(2);
    await expectTargetPristine(target);
    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(invitedRoot);
  });

  test('rejects v2 markers rather than silently ignoring transition metadata', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const target = new BeeKEM();
    const markedWelcome = {
      ...copyWelcome(welcome),
      version: 2,
      generation: 1,
      numLeaves: 2,
    } as BeeKEMWelcome;

    await expect(
      target.processWelcome(
        markedWelcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/unexpected field 'version'/);
    await expectTargetPristine(target);
  });
});
