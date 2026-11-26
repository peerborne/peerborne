import assert from 'node:assert/strict';
import test from 'node:test';
import {
  documentFixture,
  project,
  receiveEncrypted,
  replicaOf,
  signingIdentity,
} from '../../../verification/fixtures.mjs';

const options = { adapter: 'automerge' };

// The local writer ACL commits only after publication resolves. This drives
// the staged-addition path that addWriter() uses after its onboarding checks.
async function addWriter(fixture, member) {
  const { document } = fixture;
  await document._publishPreparedWriterChange(
    await document._prepareWriterAdd(member),
    'addWriter',
  );
}

test('a removal after a retried writer publication converges on both devices', async (t) => {
  const founder = await documentFixture({ ...options, index: 1 });
  await founder.document.change((doc) => {
    doc.log = [];
  });
  const device = await replicaOf(founder, 2, options);
  t.after(() => Promise.all([founder.close(), device.close()]));
  const { publicKey: member } = await signingIdentity();

  let rejected;
  founder.setPublish(async (_topic, bytes) => {
    rejected = bytes.slice();
    assert.equal(await receiveEncrypted(device, bytes), true);
    throw new Error('publication rejected after delivery');
  });
  await assert.rejects(addWriter(founder, member), /rejected after delivery/);
  founder.setPublish(async () => {});
  assert.equal(await founder.document._writers.check(member), false);
  assert.equal(await device.document._writers.check(member), true);

  await addWriter(founder, member);
  const retried = founder.stats.lastFrame;
  await founder.document._readers.add(member);
  await founder.document.removeWriter(member);
  const removal = founder.stats.lastFrame;
  await founder.document.change((doc) => {
    doc.log.push('after removal');
  });
  const edit = founder.stats.lastFrame;

  for (const frame of [retried, removal, edit])
    assert.equal(await receiveEncrypted(device, frame), true);
  assert.equal(await receiveEncrypted(founder, rejected), true);

  for (const fixture of [founder, device]) {
    assert.equal(await fixture.document._writers.check(member), false);
    assert.equal((await fixture.document._writers.users()).length, 1);
  }
  assert.deepEqual(project(device), project(founder));

  await addWriter(founder, member);
  assert.equal(await receiveEncrypted(device, founder.stats.lastFrame), true);
  for (const fixture of [founder, device])
    assert.equal(await fixture.document._writers.check(member), true);
});
