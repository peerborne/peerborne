import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { CID } from 'multiformats/cid';
import {
  aclActor,
  documentFixture,
  publishACLChange,
  publishedMessage,
  receiveEncrypted,
  shuffled,
  signedMessage,
  signingIdentity,
} from './fixtures.mjs';

const KINDS = ['writer', 'reader'];

const aclOf = (fixture, kind) =>
  kind === 'writer' ? fixture.document._writers : fixture.document._readers;

async function members(acl) {
  const keys = await acl.users();
  const raw = await Promise.all(
    keys.map((key) => crypto.subtle.exportKey('raw', key)),
  );
  return raw.map((bytes) => Buffer.from(bytes).toString('base64')).sort();
}

const heldCount = (fixture) => fixture.document._heldACL?.size ?? 0;

// Browser WebCrypto settles exportKey by queuing a task, not a microtask.
function exportKeyAsTask(t) {
  const exportKey = crypto.subtle.exportKey;
  crypto.subtle.exportKey = (...args) =>
    new Promise((resolve, reject) =>
      setTimeout(
        () => exportKey.apply(crypto.subtle, args).then(resolve, reject),
        0,
      ),
    );
  t.after(() => {
    delete crypto.subtle.exportKey;
  });
}

const microtasks = async (count) => {
  for (let index = 0; index < count; index++) await undefined;
};

function isHeld(fixture, cid) {
  return (
    !fixture.document._hashes.has(cid) &&
    fixture.document._heldACL?.has(cid) === true &&
    fixture.document._isWaiting(cid)
  );
}

/**
 * Scenarios for ACL changes that arrive before the ACL history they depend
 * on. `orphan(acl, publicKey, actor)` returns a well-formed ACL change for
 * `acl`, made under its bound `actor`, that adds `publicKey` and depends on
 * history no replica holds.
 */
export function aclDependencyScenarios({ adapter, orphan, write }) {
  async function fixture(t, fixtures, options) {
    const created = await documentFixture({ adapter, ...options });
    fixtures.push(created);
    return created;
  }

  async function join(t, fixtures, source, identity, index, options = {}) {
    const target = await fixture(t, fixtures, {
      index,
      identity,
      path: source.document.documentPath,
      open: false,
      ...options,
    });
    target.document._writers.merge(source.document._writers.current());
    target.document._readers.merge(source.document._readers.current());
    target.document._keychain.merge(source.document._keychain.history());
    await target.document._keychain.keys();
    assert.equal(
      await target.document.sync(await publishedMessage(source)),
      true,
    );
    await target.document.open();
    return target;
  }

  async function founded(t, path, extraMembers, options = {}) {
    const fixtures = [];
    t.after(() => Promise.all(fixtures.map((created) => created.close())));
    const identity = await signingIdentity();
    const founder = await fixture(t, fixtures, {
      index: 1,
      identity,
      path,
      ...options,
    });
    for (const publicKey of extraMembers) {
      await founder.document._writers.add(publicKey);
      await founder.document._readers.add(publicKey);
    }
    await founder.document.change(write('founded', 0));
    return { fixtures, founder };
  }

  for (const kind of KINDS) {
    test(`${adapter}: a ${kind} ACL change missing its history never reaches the live ACL`, async (t) => {
      const [mallory, stranger] = await Promise.all([
        signingIdentity(),
        signingIdentity(),
      ]);
      const { fixtures, founder: victor } = await founded(
        t,
        `/acl-dependencies-orphan-${kind}`,
        [mallory.publicKey],
      );
      const attacker = await join(t, fixtures, victor, mallory, 3);
      const before = await members(aclOf(victor, kind));

      const actor = await aclActor(attacker, kind);
      await publishACLChange(attacker, kind, (acl) =>
        orphan(acl, stranger.publicKey, actor),
      );
      const orphanCid = attacker.document._lastSyncMessage.changeId;
      assert.equal(
        await receiveEncrypted(victor, attacker.stats.lastFrame),
        true,
      );

      assert.equal(isHeld(victor, orphanCid), true);
      assert.deepEqual(await members(aclOf(victor, kind)), before);
      assert.equal(await aclOf(victor, kind).check(stranger.publicKey), false);
      assert.ok(aclOf(victor, kind).current());
      await victor.document.change(write('victor', 1));
      await attacker.document.change(write('mallory', 1));
      assert.equal(
        await receiveEncrypted(victor, attacker.stats.lastFrame),
        true,
      );
      assert.equal(isHeld(victor, orphanCid), true);

      await victor.document.removeWriter(mallory.publicKey);
      assert.equal(
        await victor.document._writers.check(mallory.publicKey),
        false,
      );
      await attacker.document.change(write('mallory', 2));
      assert.equal(
        await receiveEncrypted(victor, attacker.stats.lastFrame),
        false,
      );

      const restored = await fixture(t, fixtures, {
        index: 4,
        identity: victor.identity,
        path: victor.document.documentPath,
        open: false,
      });
      await restored.document.restorePlaintextCheckpoint(
        await victor.document.exportPlaintextCheckpoint(),
      );
      assert.equal(restored.document._hashes.has(orphanCid), false);
      assert.deepEqual(
        await members(restored.document._writers),
        await members(victor.document._writers),
      );
      assert.deepEqual(
        await members(aclOf(restored, kind)),
        await members(aclOf(victor, kind)),
      );
    });

    test(`${adapter}: ${kind} ACL nodes delivered in any order converge and are recorded`, async (t) => {
      const keys = await Promise.all(
        Array.from({ length: 4 }, () => signingIdentity()),
      );
      const { fixtures, founder } = await founded(
        t,
        `/acl-dependencies-order-${kind}`,
        [],
      );
      const orders = [
        (nodes) => [...nodes].reverse(),
        (nodes) => shuffled(nodes, 7),
        (nodes) => shuffled(nodes, 11),
      ];
      const replicas = [];
      for (let index = 0; index < orders.length; index++) {
        replicas.push(
          await join(t, fixtures, founder, founder.identity, index + 2),
        );
      }

      const acl = aclOf(founder, kind);
      const operations = [
        (acl) => acl.add(keys[0].publicKey),
        (acl) => acl.add(keys[1].publicKey),
        (acl) => acl.remove(keys[0].publicKey),
        (acl) => acl.add(keys[2].publicKey),
        (acl) => acl.add(keys[3].publicKey),
        (acl) => acl.remove(keys[2].publicKey),
      ];
      const nodes = [];
      for (const operation of operations) {
        await publishACLChange(founder, kind, operation);
        const message = await publishedMessage(founder);
        nodes.push(
          await signedMessage(founder, {
            changeId: message.changeId,
            changes: { kind, change: message.changes.change },
          }),
        );
      }

      const expected = await members(acl);
      const base = await members(aclOf(replicas[0], kind));
      for (const [index, replica] of replicas.entries()) {
        const order = orders[index](nodes);
        for (const node of order.slice(0, -1)) {
          assert.equal(await replica.document.sync(node), true);
        }
        if (index === 0) {
          assert.equal(heldCount(replica), nodes.length - 1);
          for (const node of order.slice(0, -1)) {
            assert.equal(isHeld(replica, node.changeId), true);
          }
          assert.deepEqual(await members(aclOf(replica, kind)), base);
        }
        assert.equal(await replica.document.sync(order.at(-1)), true);
        assert.deepEqual(await members(aclOf(replica, kind)), expected);
        assert.equal(heldCount(replica), 0);
        for (const node of nodes) {
          assert.equal(replica.document._hashes.has(node.changeId), true);
          assert.equal(replica.document._isWaiting(node.changeId), false);
        }
      }
    });

    test(`${adapter}: a full ${kind} ACL tree applies causal ancestors first`, async (t) => {
      const keys = await Promise.all(
        Array.from({ length: 3 }, () => signingIdentity()),
      );
      const { fixtures, founder } = await founded(
        t,
        `/acl-dependencies-tree-${kind}`,
        [],
      );
      const replica = await join(t, fixtures, founder, founder.identity, 2);
      const acl = aclOf(founder, kind);
      for (const key of keys) {
        await publishACLChange(founder, kind, (acl) => acl.add(key.publicKey));
      }
      await publishACLChange(founder, kind, (acl) =>
        acl.remove(keys[1].publicKey),
      );
      const message = await publishedMessage(founder);
      let held = 0;
      const hold = replica.document._holdACLChange.bind(replica.document);
      replica.document._holdACLChange = (...args) => {
        held++;
        return hold(...args);
      };

      assert.equal(await replica.document.sync(message), true);

      assert.equal(held, 0);
      assert.deepEqual(await members(aclOf(replica, kind)), await members(acl));
      assert.equal(replica.document._hashes.has(message.changeId), true);
    });
  }

  // The founder adds a writer and then removes it. The removal depends on
  // the addition.
  async function revocation(fixture, revoked) {
    await publishACLChange(fixture, 'writer', (acl) =>
      acl.add(revoked.publicKey),
    );
    const addition = await publishedMessage(fixture);
    await publishACLChange(fixture, 'writer', (acl) =>
      acl.remove(revoked.publicKey),
    );
    return { addition, removal: await publishedMessage(fixture) };
  }

  test(`${adapter}: a fetched writer removal applies when its addition arrives during the hold`, async (t) => {
    const blockstore = new MemoryBlockstore();
    const revoked = await signingIdentity();
    const { fixtures, founder } = await founded(
      t,
      '/acl-dependencies-fetched-removal',
      [],
      { blockstore },
    );
    const replica = await join(t, fixtures, founder, founder.identity, 2, {
      blockstore,
    });
    const { addition, removal } = await revocation(founder, revoked);
    await founder.document.change(write('later', 1));
    const head = await publishedMessage(founder);
    // Both ACL nodes are deferred leaves, the removal first.
    const frame = await signedMessage(founder, {
      changeId: head.changeId,
      changes: {
        kind: head.changes.kind,
        change: head.changes.change,
        children: {
          [removal.changeId]: { kind: 'writer' },
          [addition.changeId]: { kind: 'writer' },
        },
      },
    });
    exportKeyAsTask(t);

    assert.equal(await replica.document.sync(frame), true);

    assert.equal(
      await replica.document._writers.check(revoked.publicKey),
      false,
    );
    assert.equal(heldCount(replica), 0);
    for (const { changeId } of [addition, removal, head]) {
      assert.equal(replica.document._hashes.has(changeId), true);
    }
  });

  test(`${adapter}: concurrent merges of a removal and its addition never leave the removal held`, async (t) => {
    const revoked = await signingIdentity();
    const { fixtures, founder } = await founded(
      t,
      '/acl-dependencies-concurrent-removal',
      [],
    );
    const offsets = [0, 1, 2, 3, 5, 8, 13, 'task'];
    const replicas = [];
    for (const [index] of offsets.entries()) {
      replicas.push(
        await join(t, fixtures, founder, founder.identity, index + 2),
      );
    }
    const { addition, removal } = await revocation(founder, revoked);
    const signer = await replicas[0].document._serializeFrameSigner(
      founder.identity.publicKey,
    );

    for (const [index, offset] of offsets.entries()) {
      const { document } = replicas[index];
      if (offset === 'task') exportKeyAsTask(t);
      await Promise.all([
        document._mergeRemoteACL(
          'writer',
          removal.changeId,
          removal.changes.change,
          signer,
        ),
        (offset === 'task'
          ? new Promise((resolve) => setImmediate(resolve))
          : microtasks(offset)
        ).then(() =>
          document._mergeRemoteACL(
            'writer',
            addition.changeId,
            addition.changes.change,
            signer,
          ),
        ),
      ]);

      assert.equal(heldCount(replicas[index]), 0, `offset ${offset}`);
      assert.equal(await document._writers.check(revoked.publicKey), false);
    }
  });

  test(`${adapter}: a load's writer set is not established from incomplete writer blocks`, async (t) => {
    const revoked = await signingIdentity();
    const { founder } = await founded(t, '/acl-dependencies-load-writers', []);
    const { addition } = await revocation(founder, revoked);
    const message = await publishedMessage(founder);
    const blocks = new Map();
    const collect = (cid, node) => {
      if (node.kind === 'writer') blocks.set(cid, undefined);
      for (const [child, value] of Object.entries(node.children ?? {}))
        collect(child, value);
    };
    collect(message.changeId, message.changes);
    for (const cid of blocks.keys())
      blocks.set(cid, await founder.document._readBlock(CID.parse(cid)));
    const writers = async (prefetched) =>
      Promise.all(
        (
          await founder.document._writersEstablishedByLoadResponse(
            message,
            prefetched,
          )
        ).map((key) => crypto.subtle.exportKey('raw', key)),
      );

    assert.equal((await writers(blocks)).length, 1);
    blocks.delete(addition.changeId);
    assert.deepEqual(await writers(blocks), []);
  });
}
