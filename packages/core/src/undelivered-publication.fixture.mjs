import assert from 'node:assert/strict';
import test from 'node:test';
import { NoDeliveryPeersError } from '@peerborne/core';
import {
  documentFixture,
  project,
  receiveEncrypted,
  replicaOf,
} from '../../../verification/fixtures.mjs';

const path = '/undelivered-publication';
const peerId = (id) => ({ toString: () => id });
const relay = peerId('12D3KooWRelaySubscribedToTheTopic');
const member = peerId('12D3KooWMemberDevice');

for (const adapter of ['automerge', 'yjs']) {
  const setter = (key, value) =>
    adapter === 'automerge'
      ? (doc) => {
          doc.root ??= {};
          doc.root[key] = value;
        }
      : (doc) => doc.getMap('root').set(key, value);
  const root = (fixture) =>
    adapter === 'automerge'
      ? (project(fixture).root ?? {})
      : fixture.document.document.getMap('root').toJSON();

  test(`${adapter}: a change whose frame reaches no member is kept and reported until a member is sent one`, async () => {
    const fixture = await documentFixture({ adapter, path });
    const { document } = fixture;
    const reports = [];
    const states = [];
    document.subscribeDeliveryFailures('test', (failure) =>
      reports.push(failure),
    );
    document.subscribeDeliveryState('test', (failure) => states.push(failure));
    let recipients = [];
    fixture.setPublish(async () => ({ recipients }));

    await document.change(setter('a', 1));
    assert.deepEqual(root(fixture), { a: 1 });
    assert.equal(reports.length, 1);
    assert.ok(reports[0].error instanceof NoDeliveryPeersError);
    assert.equal(reports[0].changeId, document._lastSyncMessage.changeId);
    assert.equal(document.deliveryFailure, reports[0]);
    assert.deepEqual(states, [reports[0]]);

    await document.requestSync();
    assert.equal(reports.length, 1);

    recipients = [peerId(document.swarm.heliaNode.libp2p.peerId.toString())];
    await document.change(setter('b', 2));
    recipients = [relay];
    await document.change(setter('c', 3));
    assert.equal(reports.length, 3);
    assert.equal(document.deliveryFailure, reports[2]);

    document._noteMemberPeer(member.toString());
    recipients = [relay, member];
    await document.change(setter('d', 4));
    assert.equal(reports.length, 3);
    assert.equal(document.deliveryFailure, undefined);
    assert.deepEqual(states, [...reports, undefined]);
    assert.deepEqual(root(fixture), { a: 1, b: 2, c: 3, d: 4 });

    recipients = [relay];
    await document.change(setter('e', 5));
    fixture.setPublish(async () => undefined);
    await document.change(setter('f', 6));
    assert.equal(reports.length, 4);
    assert.equal(document.deliveryFailure, undefined);
    await fixture.close();
  });

  test(`${adapter}: a writer's frame that names the undelivered change clears it`, async () => {
    const writer = await documentFixture({ adapter, path, index: 1 });
    const replica = await replicaOf(writer, 2, { adapter });
    writer.setPublish(async () => ({ recipients: [] }));
    await writer.document.change(setter('a', 1));
    const undelivered = writer.document.deliveryFailure;
    assert.ok(undelivered.error instanceof NoDeliveryPeersError);
    assert.equal(await receiveEncrypted(replica, writer.stats.lastFrame), true);

    await replica.document.change(setter('b', 2));
    assert.equal(await receiveEncrypted(writer, replica.stats.lastFrame), true);
    assert.equal(writer.document.deliveryFailure, undefined);
    assert.deepEqual(root(writer), { a: 1, b: 2 });
    await Promise.all([writer.close(), replica.close()]);
  });

  test(`${adapter}: founding a document with no peer reports its founder change`, async () => {
    const fixture = await documentFixture({ adapter, path, open: false });
    fixture.setPublish(async () => ({ recipients: [] }));
    await fixture.document.create();
    assert.ok(
      fixture.document.deliveryFailure.error instanceof NoDeliveryPeersError,
    );
    await fixture.close();
  });
}
