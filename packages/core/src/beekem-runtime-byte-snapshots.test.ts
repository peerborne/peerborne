import { describe, expect, test } from '@jest/globals';
import { pathUpdateFixture, welcomeFixture } from './__testutils__/beekem-v2.js';
import { serializeBeeKEMWelcomeV2ForWire } from './beekem-welcome-wire.js';
import { serializePathUpdateV2ForWire } from './path-update-wire.js';

describe('BeeKEM runtime byte snapshots', () => {
  test('Welcome captures bytes before later descriptors can mutate them', () => {
    const welcome = welcomeFixture();
    const expected = serializeBeeKEMWelcomeV2ForWire(welcome);
    const pathNode = welcome.pathKeys[0];
    welcome.pathKeys[0] = new Proxy(pathNode, {
      getOwnPropertyDescriptor(target, key) {
        if (key === 'encryptedPrivateKey') pathNode.publicKey.fill(7);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    welcome.treeNodePublicKeys[0] = new Proxy(welcome.treeNodePublicKeys[0], {
      getOwnPropertyDescriptor(target, key) {
        pathNode.encryptedPrivateKey.fill(8);
        welcome.treeHash.fill(9);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    expect(serializeBeeKEMWelcomeV2ForWire(welcome)).toEqual(expected);
  });

  test('PathUpdate captures headers, path keys and bundles before later descriptors', () => {
    const update = pathUpdateFixture();
    const expected = serializePathUpdateV2ForWire(update);
    const pathNode = update.nodes[0];
    update.nodes[0] = new Proxy(pathNode, {
      getOwnPropertyDescriptor(target, key) {
        if (key === 'encryptedPathKeyBundles') pathNode.publicKey.fill(7);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    update.treeNodePublicKeys[0] = new Proxy(update.treeNodePublicKeys[0], {
      getOwnPropertyDescriptor(target, key) {
        pathNode.encryptedPathKeyBundles[0].ciphertext.fill(8);
        update.senderLeafPublicKey.fill(9);
        update.treeHash.fill(10);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    const hostile = new Proxy(update, {
      getOwnPropertyDescriptor(target, key) {
        if (key === 'senderLeafPublicKey') update.parentTreeHash.fill(11);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    expect(serializePathUpdateV2ForWire(hostile)).toEqual(expected);
  });
});
