import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem.js';

const algorithm = { name: 'ECDH', namedCurve: 'P-256' };
const keys = () => crypto.subtle.generateKey(algorithm, true, ['deriveBits']);

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function group() {
  const alice = new BeeKEM();
  const aliceKeys = await keys();
  await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
  const bobKeys = await keys();
  const { welcome } = await alice.addMember(bobKeys.publicKey);
  const bob = new BeeKEM();
  await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
  return { alice, bob };
}

describe('BeeKEM transition publication', () => {
  test('reserves the caller before a snapshot trap queues a newer update', async () => {
    const { alice, bob } = await group();
    const older = await bob.update();
    const newer = await bob.update();
    let nested: Promise<boolean> | undefined;
    const input = new Proxy(older.pathUpdate, {
      getOwnPropertyDescriptor(target, property) {
        nested ??= alice.processPathUpdate(newer.pathUpdate).then(
          (root) => Buffer.from(root).equals(Buffer.from(newer.rootSecret)),
          () => false,
        );
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    const first = await alice.processPathUpdate(input);
    expect(Buffer.from(first).equals(Buffer.from(older.rootSecret))).toBe(true);
    expect(nested).toBeDefined();
    expect(await nested).toBe(true);
    expect(alice.generation).toBe(newer.pathUpdate.generation);
  });

  test('keeps the live tree unchanged until the transaction callback commits', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await keys();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await keys();
    const rootBefore = await alice.getRootSecret();
    const ready = deferred();
    const release = deferred();
    const pending = alice.addMemberTransactionally(
      bobKeys.publicKey,
      async () => {
        ready.resolve();
        await release.promise;
      },
    );
    try {
      await ready.promise;
      expect(alice.memberCount).toBe(1);
      expect(alice.generation).toBe(0);
      expect(
        await alice.findLeafByPublicKey(bobKeys.publicKey),
      ).toBeUndefined();
      expect(
        Buffer.from(await alice.getRootSecret()).equals(
          Buffer.from(rootBefore),
        ),
      ).toBe(true);
    } finally {
      release.resolve();
      await pending;
    }
    expect(alice.memberCount).toBe(2);
    expect(alice.generation).toBe(1);
  });

  test('failed input capture does not let a successor bypass an active transaction', async () => {
    const { alice, bob } = await group();
    const carolKeys = await keys();
    const ready = deferred();
    const release = deferred();
    const pending = alice.addMemberTransactionally(
      carolKeys.publicKey,
      async () => {
        ready.resolve();
        await release.promise;
      },
    );
    await ready.promise;
    const update = await bob.update();
    const invalid = new Proxy(update.pathUpdate, {
      ownKeys() {
        throw new Error('injected capture failure');
      },
    });
    const rejected = alice.processPathUpdate(invalid).then(
      () => false,
      () => true,
    );
    let settled = false;
    const successor = alice.update().then(() => {
      settled = true;
    });
    try {
      await Promise.resolve();
      await Promise.resolve();
      expect(settled).toBe(false);
    } finally {
      release.resolve();
      await pending;
      await successor;
    }
    expect(await rejected).toBe(true);
    expect(alice.generation).toBe(3);
  });
});
