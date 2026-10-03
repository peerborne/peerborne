import { afterEach, describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import { BeeKEMWelcomeV2, MAX_BEEKEM_TREE_LEAVES } from './types.js';

afterEach(() => jest.restoreAllMocks());

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function copyWelcome(welcome: BeeKEMWelcomeV2): BeeKEMWelcomeV2 {
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

async function createTwoMemberWelcome(
  recipientKeyPair?: CryptoKeyPair,
): Promise<{
  welcome: BeeKEMWelcomeV2;
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
  expect(target.generation).toBe(0);
  expect(await target.findLeafByPublicKey(keys.publicKey)).toBe(0);
  expect(await target.getRootSecret()).toEqual(rootSecret);
}

async function expectTargetPristine(target: BeeKEM): Promise<void> {
  expect(target.memberCount).toBe(0);
  expect(target.myLeafIndex).toBe(-1);
  expect(target.generation).toBeNull();
  expect(
    (target as unknown as { _nodes: Map<number, unknown> })._nodes.size,
  ).toBe(0);
  await expect(target.getRootSecret()).rejects.toThrow('Tree is empty');
}

function pauseNextDigest(): {
  entered: Promise<void>;
  release: () => void;
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
  jest
    .spyOn(crypto.subtle, 'digest')
    .mockImplementation(async (algorithm, data) => {
      if (!paused) {
        paused = true;
        enter();
        await gate;
      }
      return originalDigest(algorithm, data);
    });
  return { entered, release };
}

describe('BeeKEM V2 Welcome transitions', () => {
  test('rejects a Welcome on an initialized receiver without running crypto', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const { target, keys, rootSecret } = await createInitializedTarget();
    const importSpy = jest.spyOn(crypto.subtle, 'importKey');
    const generateSpy = jest.spyOn(crypto.subtle, 'generateKey');

    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/non-fresh BeeKEM tree/);
    expect(importSpy).not.toHaveBeenCalled();
    expect(generateSpy).not.toHaveBeenCalled();
    await expectTargetUnchanged(target, keys, rootSecret);
  });

  test('applies concurrent Welcomes in call order and rejects the later one', async () => {
    const recipientKeys = await generateKeyPair();
    const first = await createTwoMemberWelcome(recipientKeys);
    const second = await createTwoMemberWelcome(recipientKeys);
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const firstProcessing = target.processWelcome(
      copyWelcome(first.welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    try {
      await digest.entered;
      const secondProcessing = target.processWelcome(
        copyWelcome(second.welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      );
      digest.release();
      await expect(firstProcessing).resolves.toEqual(first.rootSecret);
      await expect(secondProcessing).rejects.toThrow(/non-fresh BeeKEM tree/);
    } finally {
      digest.release();
    }

    expect(await target.getRootSecret()).toEqual(first.rootSecret);
    expect(await target.getRootSecret()).not.toEqual(second.rootSecret);
  });

  test('reserves a reentrant Welcome behind the outer call before inspecting Proxy descriptors', async () => {
    const recipientKeys = await generateKeyPair();
    const outer = await createTwoMemberWelcome(recipientKeys);
    const nested = await createTwoMemberWelcome(recipientKeys);
    const target = new BeeKEM();
    let nestedProcessing: Promise<Uint8Array> | undefined;
    const reentrantWelcome = new Proxy(copyWelcome(outer.welcome), {
      getOwnPropertyDescriptor(source, property) {
        nestedProcessing ??= target.processWelcome(
          copyWelcome(nested.welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        );
        return Reflect.getOwnPropertyDescriptor(source, property);
      },
    });

    const outerProcessing = target.processWelcome(
      reentrantWelcome,
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    expect(nestedProcessing).toBeDefined();
    await expect(outerProcessing).resolves.toEqual(outer.rootSecret);
    await expect(nestedProcessing).rejects.toThrow(/non-fresh BeeKEM tree/);
    expect(await target.getRootSecret()).toEqual(outer.rootSecret);
  });

  test('orders an initialization requested during an in-flight Welcome after it', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const initializedKeys = await generateKeyPair();
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const processing = target.processWelcome(
      copyWelcome(welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    let initializing!: Promise<void>;
    try {
      await digest.entered;
      initializing = target.initialize(
        initializedKeys.privateKey,
        initializedKeys.publicKey,
      );
      expect(target.memberCount).toBe(0);
      digest.release();
      await expect(processing).resolves.toEqual(rootSecret);
      await initializing;
    } finally {
      digest.release();
    }

    const reference = new BeeKEM();
    await reference.initialize(
      initializedKeys.privateKey,
      initializedKeys.publicKey,
    );
    await expectTargetUnchanged(
      target,
      initializedKeys,
      await reference.getRootSecret(),
    );
  });

  test('queues local mutations behind an in-flight Welcome', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const processing = target.processWelcome(
      copyWelcome(welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    let updating!: ReturnType<BeeKEM['update']>;
    try {
      await digest.entered;
      updating = target.update();
      expect(target.memberCount).toBe(0);
      expect(target.generation).toBeNull();
      digest.release();
      await expect(processing).resolves.toEqual(rootSecret);
    } finally {
      digest.release();
    }

    const { pathUpdate } = await updating;
    expect(pathUpdate.senderLeafIndex).toBe(welcome.leafIndex);
    expect(pathUpdate.generation).toBe(welcome.generation + 1);
    expect(target.generation).toBe(welcome.generation + 1);
  });

  test('wipes exported root key material and stays fresh when root hashing fails', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const target = new BeeKEM();
    const exportedRoots: ArrayBuffer[] = [];
    const originalExport = crypto.subtle.exportKey.bind(crypto.subtle);
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    jest
      .spyOn(crypto.subtle, 'exportKey')
      .mockImplementation((async (format: KeyFormat, key: CryptoKey) => {
        const exported = await originalExport(format as 'pkcs8', key);
        if (format === 'pkcs8') exportedRoots.push(exported);
        return exported;
      }) as never);
    jest
      .spyOn(crypto.subtle, 'digest')
      .mockImplementation(async (algorithm, data) => {
        if (exportedRoots.includes(data as ArrayBuffer)) {
          throw new Error('injected root-secret hash failure');
        }
        return originalDigest(algorithm, data);
      });

    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow('injected root-secret hash failure');
    expect(exportedRoots).toHaveLength(1);
    expect(new Uint8Array(exportedRoots[0]).every((byte) => byte === 0)).toBe(
      true,
    );
    expect(target.memberCount).toBe(0);
    expect(target.generation).toBeNull();

    jest.mocked(crypto.subtle.digest).mockRestore();
    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
    expect(exportedRoots).toHaveLength(2);
    expect(new Uint8Array(exportedRoots[1]).every((byte) => byte === 0)).toBe(
      true,
    );
  });

  test('wipes the first ECDH probe result when the second derivation rejects', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const target = new BeeKEM();
    const derived = new Uint8Array(32).fill(0xa5);
    jest
      .spyOn(crypto.subtle, 'deriveBits')
      .mockResolvedValueOnce(derived.buffer)
      .mockRejectedValueOnce(new Error('derivation unavailable'));

    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow('derivation unavailable');
    expect(derived).toEqual(new Uint8Array(32));
    expect(target.memberCount).toBe(0);
    expect(target.generation).toBeNull();
  });

  test('rejects out-of-bound trees without reading entries or changing state', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const target = new BeeKEM();
    let getterCalls = 0;
    const withGetter = (length: number): unknown[] => {
      const entries = new Array(length).fill(null);
      Object.defineProperty(entries, '0', {
        enumerable: true,
        get() {
          getterCalls++;
          return null;
        },
      });
      return entries;
    };

    for (const [patch, expected] of [
      [{ leafIndex: Number.MAX_SAFE_INTEGER }, /leaf index/],
      [{ numLeaves: MAX_BEEKEM_TREE_LEAVES + 1 }, /numLeaves/],
      [
        { treeNodePublicKeys: withGetter(2 * MAX_BEEKEM_TREE_LEAVES) },
        /invalid array/,
      ],
      [{ pathKeys: withGetter(65) }, /own data elements/],
    ] as const) {
      await expect(
        target.processWelcome(
          { ...copyWelcome(welcome), ...patch } as BeeKEMWelcomeV2,
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow(expected);
      await expectTargetPristine(target);
    }
    expect(getterCalls).toBe(0);
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
    const proxied = guardReads({
      ...detached,
      pathKeys: guardReads(detached.pathKeys.map((node) => guardReads(node))),
      treeNodePublicKeys: guardReads(
        detached.treeNodePublicKeys.map((node) => guardReads(node)),
      ),
    });

    await expect(
      new BeeKEM().processWelcome(
        proxied,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
    expect(propertyReads).toBe(0);
  });

  test('leaves a fresh receiver retryable after malformed key, ciphertext, and hash input', async () => {
    const { welcome, recipientKeys, rootSecret } =
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
      ).resolves.toEqual(rootSecret);
    }
  });

  test.each([
    'generateKey',
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

      await expect(
        target.processWelcome(
          copyWelcome(welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow(`injected ${methodName} failure`);
      spy.mockRestore();
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
});
