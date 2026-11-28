import assert from 'node:assert/strict';
import test from 'node:test';
import {
  aclChangeAuthorPayload,
  deriveACLActorDigest,
  encodeCRDTChangeAuthor,
} from '@peerborne/core';
import {
  aclActor,
  documentFixture,
  publishACLChange,
  publishedMessage,
  receiveEncrypted,
  signingIdentity,
} from './fixtures.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const frame = (fixture) => fixture.stats.lastFrame.slice();
const bindingError = { name: 'CRDTActorBindingError' };

async function members(acl) {
  const keys = await acl.users();
  const raw = await Promise.all(
    keys.map((key) => crypto.subtle.exportKey('raw', key)),
  );
  return raw.map((bytes) => Buffer.from(bytes).toString('base64')).sort();
}

/** `bare` ACL changes carrying an envelope `fixture` signs for `registration`. */
async function authorAs(fixture, kind, bare, registration) {
  const { document } = fixture;
  const acl = kind === 'writer' ? document._writers : document._readers;
  const signature = await document._authProvider.sign(
    aclChangeAuthorPayload(
      document.documentPath,
      kind,
      registration,
      document._changesSerializer.serializeChanges(bare),
    ),
    document._userKey,
  );
  return acl.actorBinding.attach(
    bare,
    encodeCRDTChangeAuthor({ ...registration, signature }),
  );
}

/**
 * ACL changes are bound to their signers like document changes. `squat`
 * (state, victim, publicKey) returns bare writer ACL changes that add
 * `publicKey` at the position `victim` occupies: the ACL `state` from before
 * `victim`, extended under the victim's actor.
 */
export function aclActorBindingScenarios({ adapter, squat, write }) {
  async function fixture(fixtures, options) {
    const created = await documentFixture({ adapter, ...options });
    fixtures.push(created);
    return created;
  }

  async function join(fixtures, source, identity, index) {
    const target = await fixture(fixtures, {
      index,
      identity,
      path: source.document.documentPath,
      open: false,
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

  // Victor founds the document; Pat and Mallory are writers and readers.
  async function network(t, path) {
    const fixtures = [];
    t.after(() => Promise.all(fixtures.map((created) => created.close())));
    const [victor, pat, mallory] = await Promise.all([
      signingIdentity(),
      signingIdentity(),
      signingIdentity(),
    ]);
    const v = await fixture(fixtures, { index: 1, identity: victor, path });
    for (const { publicKey } of [pat, mallory]) {
      await v.document._writers.add(publicKey);
      await v.document._readers.add(publicKey);
    }
    await v.document.change(write('founded', 0));
    const p = await join(fixtures, v, pat, 2);
    const m = await join(fixtures, v, mallory, 3);
    return { fixtures, v, p, m };
  }

  // Victor adds Walter through a published writer node.
  async function addWalter(v) {
    const walter = await signingIdentity();
    await publishACLChange(v, 'writer', (acl) => acl.add(walter.publicKey));
    const message = await publishedMessage(v);
    const [prefix, bare] = v.document._writers.actorBinding.detach(
      message.changes.change,
    );
    return { walter, frame: frame(v), prefix, bare };
  }

  test(`${adapter}: a writer cannot write another signer's ACL actor at its next position`, async (t) => {
    const { v, p, m } = await network(t, `/${adapter}-acl-squat`);
    const before = m.document._writers.current();
    const intruder = await signingIdentity();
    const victim = await addWalter(v);
    assert.equal(await receiveEncrypted(m, victim.frame), true);
    const squatted = await squat(before, victim.bare, intruder.publicKey);
    await aclActor(m, 'writer');
    const own = m.document._aclActors.get('writer').registration;

    // Mallory's own registration derives a different actor.
    await m.document._makeChangeOnce(
      await authorAs(m, 'writer', squatted, own),
      'writer',
    );
    await assert.rejects(receiveEncrypted(p, frame(m)), bindingError);
    // Victor's envelope does not sign Mallory's bytes.
    await m.document._makeChangeOnce(
      v.document._writers.actorBinding.attach(squatted, victim.prefix),
      'writer',
    );
    await assert.rejects(receiveEncrypted(p, frame(m)), bindingError);
    // Relayed below a change of Mallory's own, the squat is skipped.
    await m.document.change(write('mallory', 1));
    assert.equal(await receiveEncrypted(p, frame(m)), true);
    assert.equal(await receiveEncrypted(p, victim.frame), true);
    assert.equal(await receiveEncrypted(v, frame(m)), true);

    for (const replica of [v, p, m]) {
      assert.equal(
        await replica.document._writers.check(victim.walter.publicKey),
        true,
      );
      assert.equal(
        await replica.document._writers.check(intruder.publicKey),
        false,
      );
    }
    assert.deepEqual(
      await members(p.document._writers),
      await members(v.document._writers),
    );
  });

  test(`${adapter}: a signed ACL change is refused in the other ACL and as a document change`, async (t) => {
    const { v, p, m } = await network(t, `/${adapter}-acl-replay`);
    const victim = await addWalter(v);
    const enveloped = v.document._writers.actorBinding.attach(
      victim.bare,
      victim.prefix,
    );
    const readersBefore = await members(p.document._readers);

    await m.document._makeChangeOnce(enveloped, 'reader');
    await m.document._makeChangeOnce(enveloped, 'document');
    await m.document.change(write('mallory', 1));
    assert.equal(await receiveEncrypted(p, frame(m)), true);

    assert.deepEqual(await members(p.document._readers), readersBefore);
    assert.equal(
      await p.document._readers.check(victim.walter.publicKey),
      false,
    );
    assert.equal(
      await p.document._writers.check(victim.walter.publicKey),
      false,
    );
    assert.equal(await receiveEncrypted(p, victim.frame), true);
    assert.equal(
      await p.document._writers.check(victim.walter.publicKey),
      true,
    );
  });

  test(`${adapter}: an ACL change without an authored envelope is refused`, async (t) => {
    const { p, m } = await network(t, `/${adapter}-acl-unauthored`);
    const intruder = await signingIdentity();
    const before = await members(p.document._writers);
    const bare = (await m.document._writers.prepareAdd(intruder.publicKey))
      .changes;

    await m.document._makeChangeOnce(bare, 'writer');
    await assert.rejects(receiveEncrypted(p, frame(m)), bindingError);
    await m.document.change(write('mallory', 1));
    assert.equal(await receiveEncrypted(p, frame(m)), true);

    assert.deepEqual(await members(p.document._writers), before);
  });

  test(`${adapter}: a failed ACL publication moves the next change to a fresh actor`, async (t) => {
    const { v, p } = await network(t, `/${adapter}-acl-retry`);
    const walter = await signingIdentity();
    await v.document._bindACLActor('writer');
    const first = v.document._aclActors.get('writer').actor;
    v.setPublish(async () => {
      throw new Error('offline');
    });
    await assert.rejects(
      v.document._publishPreparedWriterChange(
        await v.document._prepareWriterAdd(walter.publicKey),
        'test',
      ),
    );
    v.setPublish(async () => {});

    await v.document._publishPreparedWriterChange(
      await v.document._prepareWriterAdd(walter.publicKey),
      'test',
    );

    assert.notEqual(v.document._aclActors.get('writer').actor, first);
    assert.equal(await receiveEncrypted(p, frame(v)), true);
    assert.equal(await p.document._writers.check(walter.publicKey), true);
  });

  test(`${adapter}: a restored replica remembers ACL bindings and refuses a colliding registration`, async (t) => {
    const { fixtures, v, m } = await network(t, `/${adapter}-acl-restore`);
    const intruder = await signingIdentity();
    const before = m.document._writers.current();
    const victim = await addWalter(v);
    const actor = v.document._aclActors.get('writer').actor;
    const restored = await fixture(fixtures, {
      index: 4,
      identity: v.identity,
      path: v.document.documentPath,
      open: false,
    });
    await restored.document.restorePlaintextCheckpoint(
      await v.document.exportPlaintextCheckpoint(),
    );
    assert.equal(
      restored.document._aclActorBindings.writer.get(actor).signer,
      v.document._aclActors.get('writer').registration.signer,
    );

    // Pretend Mallory found a nonce that derives Victor's actor.
    await aclActor(m, 'writer');
    const registration = m.document._aclActors.get('writer').registration;
    const digest = hex(
      await deriveACLActorDigest(
        m.document.documentPath,
        'writer',
        registration,
      ),
    );
    const colliding = await authorAs(
      m,
      'writer',
      await squat(before, victim.bare, intruder.publicKey),
      registration,
    );
    const collide = (target) => {
      const binding = target.document._writers.actorBinding;
      const derive = binding.actorFromDigest;
      binding.actorFromDigest = (bytes) =>
        hex(bytes) === digest ? actor : derive(bytes);
    };
    const fresh = await fixture(fixtures, {
      index: 5,
      identity: v.identity,
      path: v.document.documentPath,
      open: false,
    });
    collide(restored);
    collide(fresh);

    await assert.rejects(
      restored.document._verifyACLChange(
        'writer',
        restored.document._writers,
        colliding,
      ),
      /already bound/,
    );
    await fresh.document._verifyACLChange(
      'writer',
      fresh.document._writers,
      colliding,
    );
    await restored.document._bindACLActor('writer');
    assert.notEqual(restored.document._aclActors.get('writer').actor, actor);
  });
}
