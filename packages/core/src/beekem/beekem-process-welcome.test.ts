import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';
import {
  BeeKEMWelcome,
  MAX_BEEKEM_TREE_LEAVES,
} from './types.js';
import { generateEciesKeyPair } from '../ecies.js';
import { MAX_V1_PATH_NODES } from './path-update-limits.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };
const P256_PRIME =
  (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n;

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
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

async function createFourMemberWelcome(
  recipientKeyPair?: CryptoKeyPair,
): Promise<{
  welcome: BeeKEMWelcome;
  recipientKeys: CryptoKeyPair;
  rootSecret: Uint8Array;
}> {
  const founder = new BeeKEM();
  const founderKeys = await generateKeyPair();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
  await founder.addMember((await generateKeyPair()).publicKey);

  const thirdMemberKeys = await generateKeyPair();
  const { welcome: thirdMemberWelcome } = await founder.addMember(
    thirdMemberKeys.publicKey,
  );
  const thirdMember = new BeeKEM();
  await thirdMember.processWelcome(
    thirdMemberWelcome,
    thirdMemberKeys.privateKey,
    thirdMemberKeys.publicKey,
  );

  const recipientKeys = recipientKeyPair ?? (await generateKeyPair());
  const { welcome, rootSecret } = await thirdMember.addMember(
    recipientKeys.publicKey,
  );
  return { welcome, recipientKeys, rootSecret };
}

async function computeWelcomeTreeHash(
  welcome: BeeKEMWelcome,
  recipientPublicKey: CryptoKey,
): Promise<Uint8Array> {
  const publicKeys = new Map<number, Uint8Array | null>();
  publicKeys.set(
    welcome.leafIndex,
    new Uint8Array(await crypto.subtle.exportKey('raw', recipientPublicKey)),
  );
  for (const pathKey of welcome.pathKeys) {
    publicKeys.set(pathKey.nodeIndex, pathKey.publicKey);
  }
  for (const node of welcome.treeNodePublicKeys) {
    publicKeys.set(node.nodeIndex, node.publicKey);
  }

  const parts: Uint8Array[] = [];
  for (const [nodeIndex, publicKey] of [...publicKeys].sort(
    ([left], [right]) => left - right,
  )) {
    if (publicKey === null) continue;
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, nodeIndex, false);
    parts.push(indexBytes, publicKey);
  }
  const byteLength = parts.reduce((total, part) => total + part.byteLength, 0);
  const encoded = new Uint8Array(byteLength);
  let offset = 0;
  for (const part of parts) {
    encoded.set(part, offset);
    offset += part.byteLength;
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoded));
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
    ).rejects.toThrow(/even non-negative safe integer/);
    await expectTargetPristine(target);

    await expect(
      target.processWelcome(
        {
          ...copyWelcome(welcome),
          leafIndex: 2 * MAX_BEEKEM_TREE_LEAVES,
        },
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/supported \d+-leaf tree bound/);
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

    const oversizedPath = new Array(MAX_V1_PATH_NODES + 1);
    Object.defineProperty(oversizedPath, '0', {
      enumerable: true,
      get() {
        getterCalls++;
        return null;
      },
    });
    await expect(
      target.processWelcome(
        { ...copyWelcome(welcome), pathKeys: oversizedPath },
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(/pathKeys has invalid length/);
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
    ).rejects.toThrow(/enumerable data propert/);
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

  test('accepts omitted blank nodes in a sparse legacy Welcome', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const sparseWelcome = copyWelcome(welcome);
    sparseWelcome.treeNodePublicKeys[0].publicKey = null;
    sparseWelcome.treeHash = await computeWelcomeTreeHash(
      sparseWelcome,
      recipientKeys.publicKey,
    );
    sparseWelcome.treeNodePublicKeys.length = 0;
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        sparseWelcome,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
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

  test('keeps an in-flight valid Welcome eligible when a later attempt is malformed', async () => {
    const recipientKeys = await generateKeyPair();
    const valid = await createTwoMemberWelcome(recipientKeys);
    const malformed = copyWelcome(valid.welcome);
    malformed.leafIndex = Number.MAX_SAFE_INTEGER;
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const validProcessing = target.processWelcome(
      copyWelcome(valid.welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    try {
      await digest.entered;
      await expect(
        target.processWelcome(
          malformed,
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow(/leafIndex/);
      digest.release();
      await expect(validProcessing).resolves.toEqual(valid.rootSecret);
    } finally {
      digest.release();
      digest.restore();
    }

    expect(await target.getRootSecret()).toEqual(valid.rootSecret);
  });

  test('commits a staged valid candidate after a later pending attempt fails', async () => {
    const recipientKeys = await generateKeyPair();
    const valid = await createTwoMemberWelcome(recipientKeys);
    const target = new BeeKEM();
    const internals = target as unknown as {
      _processWelcomeAttempt(
        revision: bigint,
        welcome: BeeKEMWelcome,
        privateKey: CryptoKey,
        publicKey: CryptoKey,
        receiverGeneration: bigint,
      ): Promise<Uint8Array>;
      _registerWelcomeCandidate(
        revision: bigint,
        staged: BeeKEM,
        rootSecret: Uint8Array,
        receiverGeneration: bigint,
      ): Promise<Uint8Array>;
      _pendingWelcomeAttempts: Set<bigint>;
      _stagedWelcomeCandidates: Map<bigint, unknown>;
    };
    const originalProcessAttempt =
      internals._processWelcomeAttempt.bind(target);
    const originalRegisterCandidate =
      internals._registerWelcomeCandidate.bind(target);
    let releaseLater!: () => void;
    const laterGate = new Promise<void>((resolve) => {
      releaseLater = resolve;
    });
    let markCandidateRegistered!: () => void;
    const candidateRegistered = new Promise<void>((resolve) => {
      markCandidateRegistered = resolve;
    });
    internals._processWelcomeAttempt = async (revision, ...args) => {
      if (revision === 2n) {
        await laterGate;
        throw new Error('injected delayed later failure');
      }
      return originalProcessAttempt(revision, ...args);
    };
    internals._registerWelcomeCandidate = (
      revision,
      staged,
      rootSecret,
      receiverGeneration,
    ) => {
      markCandidateRegistered();
      return originalRegisterCandidate(
        revision,
        staged,
        rootSecret,
        receiverGeneration,
      );
    };

    const earlier = target.processWelcome(
      copyWelcome(valid.welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );
    const later = target.processWelcome(
      copyWelcome(valid.welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    try {
      await candidateRegistered;
      expect(internals._stagedWelcomeCandidates.size).toBe(1);
      await expectTargetPristine(target);

      releaseLater();
      await expect(later).rejects.toThrow('injected delayed later failure');
      await expect(earlier).resolves.toEqual(valid.rootSecret);
    } finally {
      releaseLater();
      await Promise.allSettled([earlier, later]);
      internals._processWelcomeAttempt = originalProcessAttempt;
      internals._registerWelcomeCandidate = originalRegisterCandidate;
    }
    expect(await target.getRootSecret()).toEqual(valid.rootSecret);
    expect(internals._pendingWelcomeAttempts.size).toBe(0);
    expect(internals._stagedWelcomeCandidates.size).toBe(0);
  });

  test('reserves reentrant attempts before inspecting Proxy descriptors', async () => {
    const recipientKeys = await generateKeyPair();
    const older = await createTwoMemberWelcome(recipientKeys);
    const latest = await createTwoMemberWelcome(recipientKeys);
    const target = new BeeKEM();
    let latestProcessing: Promise<Uint8Array> | undefined;
    const reentrantWelcome = new Proxy(copyWelcome(older.welcome), {
      getOwnPropertyDescriptor(source, property) {
        latestProcessing ??= target.processWelcome(
          copyWelcome(latest.welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        );
        return Reflect.getOwnPropertyDescriptor(source, property);
      },
    });

    const olderProcessing = target.processWelcome(
      reentrantWelcome,
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );
    const olderOutcome = olderProcessing.then(
      (value) => ({ kind: 'fulfilled' as const, value }),
      (error: unknown) => ({ kind: 'rejected' as const, error }),
    );

    expect(latestProcessing).toBeDefined();
    await expect(latestProcessing).resolves.toEqual(latest.rootSecret);
    const outcome = await olderOutcome;
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

  test('permanently supersedes a paused Welcome across repeated initialization', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const firstInitializedKeys = await generateKeyPair();
    const latestInitializedKeys = await generateKeyPair();
    const target = new BeeKEM();
    const internals = target as unknown as { _receiverGeneration: bigint };
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

    let latestRoot!: Uint8Array;
    let settled!: Awaited<typeof outcome>;
    try {
      await digest.entered;
      await target.initialize(
        firstInitializedKeys.privateKey,
        firstInitializedKeys.publicKey,
      );
      await target.initialize(
        latestInitializedKeys.privateKey,
        latestInitializedKeys.publicKey,
      );
      expect(internals._receiverGeneration).toBe(2n);
      latestRoot = await target.getRootSecret();
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
    expect(internals._receiverGeneration).toBe(2n);
    await expectTargetUnchanged(target, latestInitializedKeys, latestRoot);
  });

  test('rejects every tree mutation while a fresh receiver is processing a Welcome', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const otherMemberKeys = await generateKeyPair();
    const senderLeafPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', otherMemberKeys.publicKey),
    );
    const target = new BeeKEM();
    const digest = pauseNextDigest();
    const processing = target.processWelcome(
      copyWelcome(welcome),
      recipientKeys.privateKey,
      recipientKeys.publicKey,
    );

    let completedRoot!: Uint8Array;
    try {
      await digest.entered;
      await expect(target.addMember(otherMemberKeys.publicKey)).rejects.toThrow(
        /tree is not initialized/,
      );
      await expect(target.removeMember(0)).rejects.toThrow(
        /tree is not initialized/,
      );
      await expect(target.update()).rejects.toThrow(/tree is not initialized/);
      await expect(
        target.processPathUpdate({
          senderLeafIndex: 0,
          senderLeafPublicKey,
          nodes: [],
        }),
      ).rejects.toThrow(/tree is not initialized/);
      await expectTargetPristine(target);

      digest.release();
      completedRoot = await processing;
    } finally {
      digest.release();
      digest.restore();
    }

    expect(completedRoot).toEqual(rootSecret);
    expect(await target.getRootSecret()).toEqual(rootSecret);
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

  test('rejects inherited v2 markers at the legacy runtime boundary', async () => {
    const { welcome, recipientKeys } = await createTwoMemberWelcome();
    const target = new BeeKEM();
    Object.defineProperty(Object.prototype, 'generation', {
      configurable: true,
      value: 1,
    });

    try {
      await expect(
        target.processWelcome(
          copyWelcome(welcome),
          recipientKeys.privateKey,
          recipientKeys.publicKey,
        ),
      ).rejects.toThrow(/unexpected field 'generation'/);
    } finally {
      delete (Object.prototype as { generation?: unknown }).generation;
    }
    await expectTargetPristine(target);
  });

  test.each([124, 4097])(
    'rejects a %i-byte legacy path ciphertext before cryptography',
    async (ciphertextBytes) => {
      const { welcome, recipientKeys } = await createTwoMemberWelcome();
      const forged = copyWelcome(welcome);
      forged.pathKeys[0].encryptedPrivateKey = new Uint8Array(
        ciphertextBytes,
      );
      const target = new BeeKEM();
      const generateSpy = jest.spyOn(crypto.subtle, 'generateKey');

      try {
        await expect(
          target.processWelcome(
            forged,
            recipientKeys.privateKey,
            recipientKeys.publicKey,
          ),
        ).rejects.toThrow(/encryptedPrivateKey.*125 to 4096 bytes/);
        expect(generateSpy).not.toHaveBeenCalled();
      } finally {
        generateSpy.mockRestore();
      }
      await expectTargetPristine(target);
    },
  );

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

  test('rejects a valid recipient public key paired with another private key', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createTwoMemberWelcome();
    const mismatchedKeys = await generateKeyPair();
    const forged = copyWelcome(welcome);
    forged.treeHash = await computeWelcomeTreeHash(
      forged,
      mismatchedKeys.publicKey,
    );
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        forged,
        recipientKeys.privateKey,
        mismatchedKeys.publicKey,
      ),
    ).rejects.toThrow(
      /recipient leaf 2 public and private keys are not ECDH-compatible/,
    );
    await expectTargetPristine(target);
    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
  });

  test('rejects a mismatched advertised key at a higher decrypted path node', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createFourMemberWelcome();
    expect(welcome.pathKeys).toHaveLength(2);
    const forged = copyWelcome(welcome);
    const mismatchedKeys = await generateKeyPair();
    const mismatchedNode = forged.pathKeys[1];
    mismatchedNode.publicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', mismatchedKeys.publicKey),
    );
    forged.treeHash = await computeWelcomeTreeHash(
      forged,
      recipientKeys.publicKey,
    );
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        forged,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(
      new RegExp(
        `path node ${mismatchedNode.nodeIndex} public and private keys do not match`,
      ),
    );
    await expectTargetPristine(target);
    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
  });

  test('rejects a negated advertised point at a decrypted path node', async () => {
    const { welcome, recipientKeys, rootSecret } =
      await createFourMemberWelcome();
    expect(welcome.pathKeys).toHaveLength(2);
    const forged = copyWelcome(welcome);
    const forgedNode = forged.pathKeys[1];
    forgedNode.publicKey = negateP256Point(forgedNode.publicKey);
    forged.treeHash = await computeWelcomeTreeHash(
      forged,
      recipientKeys.publicKey,
    );
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        forged,
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).rejects.toThrow(
      new RegExp(
        `path node ${forgedNode.nodeIndex} public and private keys do not match`,
      ),
    );
    await expectTargetPristine(target);
    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
  });

  test('accepts a recipient private key that cannot be exported', async () => {
    const recipientKeys = await generateEciesKeyPair();
    expect(recipientKeys.privateKey.extractable).toBe(false);
    const { welcome, rootSecret } = await createTwoMemberWelcome(recipientKeys);
    const target = new BeeKEM();

    await expect(
      target.processWelcome(
        copyWelcome(welcome),
        recipientKeys.privateKey,
        recipientKeys.publicKey,
      ),
    ).resolves.toEqual(rootSecret);
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
