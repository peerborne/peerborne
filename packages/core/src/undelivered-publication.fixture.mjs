import assert from 'node:assert/strict';
import test from 'node:test';
import { NoDeliveryPeersError } from '@peerborne/core';
import { documentFixture, project } from '../../../verification/fixtures.mjs';

const path = '/undelivered-publication';
const peer = { toString: () => '12D3KooWRemoteSubscriber' };

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

  test(`${adapter}: a change published to no peer is kept and reported until a later frame reaches one`, async () => {
    const fixture = await documentFixture({ adapter, path });
    const { document } = fixture;
    const reports = [];
    document.subscribeDeliveryFailures('test', (failure) =>
      reports.push(failure),
    );
    let recipients = [];
    fixture.setPublish(async () => ({ recipients }));

    await document.change(setter('a', 1));
    assert.deepEqual(root(fixture), { a: 1 });
    assert.equal(reports.length, 1);
    assert.ok(reports[0].error instanceof NoDeliveryPeersError);
    assert.equal(reports[0].changeId, document._lastSyncMessage.changeId);
    assert.equal(document.deliveryFailure, reports[0]);

    await document.requestSync();
    assert.equal(reports.length, 1);
    assert.equal(document.deliveryFailure, reports[0]);

    recipients = [
      { toString: () => document.swarm.heliaNode.libp2p.peerId.toString() },
    ];
    await document.change(setter('b', 2));
    assert.equal(reports.length, 2);
    assert.equal(document.deliveryFailure, reports[1]);

    recipients = [peer];
    await document.change(setter('c', 3));
    assert.equal(reports.length, 2);
    assert.equal(document.deliveryFailure, undefined);
    assert.deepEqual(root(fixture), { a: 1, b: 2, c: 3 });

    fixture.setPublish(async () => undefined);
    await document.change(setter('d', 4));
    assert.equal(reports.length, 2);
    assert.equal(document.deliveryFailure, undefined);
    await fixture.close();
  });

  test(`${adapter}: founding a document with no peer reports its founder change`, async () => {
    const fixture = await documentFixture({ adapter, path, open: false });
    fixture.setPublish(async () => ({ recipients: [] }));
    await fixture.document.create();
    assert.ok(
      fixture.document.deliveryFailure.error instanceof NoDeliveryPeersError,
    );
    fixture.setPublish(async () => ({ recipients: [peer] }));
    await fixture.document.change(setter('a', 1));
    assert.equal(fixture.document.deliveryFailure, undefined);
    await fixture.close();
  });
}
