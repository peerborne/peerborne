import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BeeKEM,
  eciesSeal,
  encodeWelcomeSealedPayloadV2,
  importEciesPublicKey,
} from '@peerborne/core';
import { AutomergeKeychainProvider } from '@peerborne/automerge';
import { YjsKeychainProvider } from '@peerborne/yjs';
import {
  documentFixture,
  project,
  publishedMessage,
  receiveEncrypted,
  signingIdentity,
} from '../../../verification/fixtures.mjs';

for (const method of ['log', 'info', 'debug', 'warn', 'error'])
  console[method] = () => {};

const ecdh = { name: 'ECDH', namedCurve: 'P-256' };
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const keyIds = async (fixture) =>
  (await fixture.document._keychain.keys()).map(([id]) => hex(id));

async function join(adapter, source, identity, index) {
  const replica = await documentFixture({
    adapter,
    index,
    identity,
    path: source.document.documentPath,
    open: false,
  });
  replica.document._writers.merge(source.document._writers.current());
  replica.document._readers.merge(source.document._readers.current());
  replica.document._keychain.merge(source.document._keychain.history());
  await replica.document._keychain.keys();
  assert.equal(
    await replica.document.sync(await publishedMessage(source)),
    true,
  );
  await replica.document.open();
  return replica;
}

// A founder, a second device of the founder that does not hear the forger,
// and a writer whose own keychain copy carries a key no rotation produced.
async function scenario(adapter) {
  const edit =
    adapter === 'yjs'
      ? (value) => (doc) => doc.getMap('root').set('v', value)
      : (value) => (doc) => {
          doc.v = value;
        };
  const value = (fixture) =>
    adapter === 'yjs' ? project(fixture).root.v : project(fixture).v;
  const [founderId, writerId] = await Promise.all([
    signingIdentity(),
    signingIdentity(),
  ]);
  const founder = await documentFixture({
    adapter,
    index: 1,
    identity: founderId,
    path: `/keychain-forgery-${adapter}`,
  });
  await founder.document.change(edit('founded'));
  await founder.document._publishPreparedWriterChange(
    await founder.document._prepareWriterAdd(writerId.publicKey),
    'add writer',
  );
  const device = await join(adapter, founder, founderId, 2);
  const writer = await join(adapter, founder, writerId, 3);
  const forger = (
    adapter === 'yjs'
      ? new YjsKeychainProvider()
      : new AutomergeKeychainProvider()
  ).initialize();
  forger.merge(writer.document._keychain.history());
  const [forgedKey] = await forger.add();
  return {
    founder,
    founderId,
    device,
    writer,
    forger,
    forgedKey,
    edit,
    value,
    async close() {
      for (const fixture of [writer, device, founder]) await fixture.close();
    },
  };
}

for (const adapter of ['yjs', 'automerge']) {
  test(`${adapter}: a writer's Welcome cannot add a key to or replace the tree of a replica that holds one`, async () => {
    const {
      founder,
      founderId,
      device,
      writer,
      forger,
      forgedKey,
      edit,
      value,
      close,
    } = await scenario(adapter);
    try {
      const founderKem = await crypto.subtle.generateKey(ecdh, true, [
        'deriveBits',
      ]);
      await founder.document.setKemKeyPair(founderKem);
      await writer.document._bindACLActor('reader');
      await writer.document._makeChangeOnce(
        await writer.document._authorACLChange(
          'reader',
          await writer.document._readers.add(founderId.publicKey),
        ),
        'reader',
      );
      assert.equal(
        await receiveEncrypted(founder, writer.stats.lastFrame),
        true,
      );
      assert.equal(
        await founder.document._readers.check(founderId.publicKey),
        true,
      );
      const honestKeys = await keyIds(founder);

      const ghost = await crypto.subtle.generateKey(ecdh, false, [
        'deriveBits',
      ]);
      const tree = new BeeKEM();
      await tree.initialize(ghost.privateKey, ghost.publicKey);
      const { welcome } = await tree.addMember(founderKem.publicKey);
      const founderKemRaw = new Uint8Array(
        await crypto.subtle.exportKey('raw', founderKem.publicKey),
      );
      const message = {
        documentId: writer.document.documentPath,
        signatureContext: 'beekem-welcome-v2',
        welcomeEpochId: new Uint8Array(forgedKey),
        welcomeRecipient: await writer.auth.serializePublicKey(
          founderId.publicKey,
        ),
        welcomeRecipientKemPublicKey: founderKemRaw,
        eciesSealed: await eciesSeal(
          encodeWelcomeSealedPayloadV2({
            keychainChanges: writer.serializer.serializeChanges(
              forger.history(),
            ),
            beekemWelcome: welcome,
          }),
          await importEciesPublicKey(founderKemRaw),
        ),
      };
      message.signature = await writer.document._signWelcomeAsWriter(message);
      assert.equal(
        await founder.document._evaluateAndApplyBeeKEMWelcome(
          writer.serializer.deserializeSyncMessage(
            writer.serializer.serializeSyncMessage(message),
          ),
          { fromBuffer: false },
        ),
        'terminal',
      );

      assert.deepEqual(await keyIds(founder), honestKeys);
      assert.equal(founder.document._beekem, null);
      assert.equal(founder.document._beekemInitialized, false);
      assert.equal(founder.document._invitationEpoch, undefined);
      await founder.document.change(edit('after forgery'));
      assert.equal(
        await receiveEncrypted(device, founder.stats.lastFrame),
        true,
      );
      assert.equal(value(device), 'after forgery');
    } finally {
      await close();
    }
  });

  test(`${adapter}: a writer's load response cannot add a key to a lagging replica`, async () => {
    const { founder, device, writer, forger, edit, value, close } =
      await scenario(adapter);
    try {
      const honestKeys = await keyIds(device);
      const [honestCurrent] = await device.document._keychain.current();
      const response = async (signer, keychainChanges) => {
        const message = {
          documentId: signer.document.documentPath,
          signatureContext: 'load-response-v4',
          keychainChanges,
        };
        message.signature =
          await signer.document._signAsWriterUnconditional(message);
        return message;
      };
      const warnings = [];
      console.warn = (message) => warnings.push(message);

      assert.equal(
        await device.document._syncValidatedProtocolMessage(
          await response(writer, forger.history()),
          'load-response-v4',
        ),
        false,
      );
      assert.deepEqual(warnings, [
        `Rejected keychain changes that would add keys to ${device.document.documentPath}`,
      ]);
      assert.deepEqual(await keyIds(device), honestKeys);
      assert.deepEqual(
        hex((await device.document._keychain.current())[0]),
        hex(honestCurrent),
      );

      assert.equal(
        await device.document._syncValidatedProtocolMessage(
          await response(founder, founder.document._keychain.history()),
          'load-response-v4',
        ),
        true,
      );
      assert.deepEqual(await keyIds(device), await keyIds(founder));
      await device.document.change(edit('from the device'));
      assert.equal(
        await receiveEncrypted(founder, device.stats.lastFrame),
        true,
      );
      assert.equal(value(founder), 'from the device');
    } finally {
      console.warn = () => {};
      await close();
    }
  });
}
