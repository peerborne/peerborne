import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import { PathUpdate, PathUpdateV2, TreeNode } from './beekem/types.js';
import {
  applyBeeKEMPathUpdateWithEpoch,
  isBeeKEMMessageForDocument,
} from './beekem-path-update-apply.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import {
  deserializePathUpdateFromWire,
  serializePathUpdateForWire,
} from './path-update-wire.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

function projectLegacyPathUpdate(update: PathUpdateV2): PathUpdate {
  return {
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: update.senderLeafPublicKey,
    nodes: update.nodes.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    })),
  };
}

async function treeFingerprint(beekem: BeeKEM): Promise<string> {
  const nodes = (
    beekem as unknown as { _nodes: Map<number, TreeNode> }
  )._nodes;
  const entries = await Promise.all(
    [...nodes.entries()]
      .sort(([left], [right]) => left - right)
      .map(async ([index, node]) => ({
        index,
        type: node.type,
        hasPrivateKey: node.privateKey !== undefined,
        publicKey:
          node.publicKey === null
            ? null
            : Buffer.from(
                await crypto.subtle.exportKey('raw', node.publicKey),
              ).toString('base64'),
      })),
  );
  return JSON.stringify(entries);
}

async function twoMemberUpdate() {
  const alice = new BeeKEM();
  const aliceKeys = await keyPair();
  await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
  const bobKeys = await keyPair();
  const { welcome } = await alice.addMember(bobKeys.publicKey);
  const bob = new BeeKEM();
  await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);
  const update = await alice.update();
  return { bob, ...update };
}

describe('BeeKEM PathUpdate document handler', () => {
  test.each([undefined, '', '/doc/other'])(
    'rejects a missing or cross-document ID (%p)',
    (documentId) => {
      expect(
        isBeeKEMMessageForDocument(documentId, '/doc/path-update'),
      ).toBe(false);
    },
  );

  test('accepts only the exact document ID', () => {
    expect(
      isBeeKEMMessageForDocument(
        '/doc/path-update',
        '/doc/path-update',
      ),
    ).toBe(true);
  });

  test('an authenticated v1 update cannot downgrade generation-bearing state', async () => {
    const { bob, pathUpdate, rootSecret } = await twoMemberUpdate();
    const beforeRoot = await bob.getRootSecret();
    const beforeGeneration = bob.generation;
    const beforeTree = await treeFingerprint(bob);
    let installs = 0;
    const legacyUpdate = deserializePathUpdateFromWire(
      serializePathUpdateForWire(projectLegacyPathUpdate(pathUpdate)),
    );
    const result = await applyBeeKEMPathUpdateWithEpoch(
      bob,
      legacyUpdate,
      1,
      await deriveEpochIdFromRootSecret(rootSecret),
      {
        deriveEpochId: deriveEpochIdFromRootSecret,
        deriveDocumentKey: deriveDocumentKeyFromRootSecret,
        installEpochKey: async () => {
          installs++;
        },
      },
    );

    expect(result).toEqual({ kind: 'rejected', reason: 'legacy-downgrade' });
    expect(installs).toBe(0);
    expect(bob.generation).toBe(beforeGeneration);
    expect(await bob.getRootSecret()).toEqual(beforeRoot);
    expect(await treeFingerprint(bob)).toBe(beforeTree);
  });

  test('an exact v2 replay validates its epoch but installs the key only once', async () => {
    const { bob, pathUpdate, rootSecret } = await twoMemberUpdate();
    const expectedEpochId = await deriveEpochIdFromRootSecret(rootSecret);
    const installedEpochs: string[] = [];
    const dependencies = {
      deriveEpochId: deriveEpochIdFromRootSecret,
      deriveDocumentKey: deriveDocumentKeyFromRootSecret,
      installEpochKey: async (epochId: Uint8Array) => {
        installedEpochs.push(Buffer.from(epochId).toString('hex'));
      },
    };

    expect(
      await applyBeeKEMPathUpdateWithEpoch(
        bob,
        pathUpdate,
        2,
        expectedEpochId,
        dependencies,
      ),
    ).toEqual({ kind: 'applied' });
    const afterFirst = {
      generation: bob.generation,
      root: await bob.getRootSecret(),
      tree: await treeFingerprint(bob),
    };

    expect(
      await applyBeeKEMPathUpdateWithEpoch(
        bob,
        pathUpdate,
        2,
        expectedEpochId,
        dependencies,
      ),
    ).toEqual({ kind: 'duplicate' });
    expect(installedEpochs).toEqual([
      Buffer.from(expectedEpochId).toString('hex'),
    ]);
    expect(bob.generation).toBe(afterFirst.generation);
    expect(await bob.getRootSecret()).toEqual(afterFirst.root);
    expect(await treeFingerprint(bob)).toBe(afterFirst.tree);
  });

  test.each(['epoch mismatch', 'keychain failure'])(
    '%s rolls the tree, generation, and root back',
    async (failure) => {
      const { bob, pathUpdate, rootSecret } = await twoMemberUpdate();
      const beforeRoot = await bob.getRootSecret();
      const beforeGeneration = bob.generation;
      const beforeTree = await treeFingerprint(bob);
      let installAttempts = 0;
      const result = await applyBeeKEMPathUpdateWithEpoch(
        bob,
        pathUpdate,
        2,
        failure === 'epoch mismatch'
          ? new Uint8Array(32)
          : await deriveEpochIdFromRootSecret(rootSecret),
        {
          deriveEpochId: deriveEpochIdFromRootSecret,
          deriveDocumentKey: deriveDocumentKeyFromRootSecret,
          installEpochKey: async () => {
            installAttempts++;
            if (failure === 'keychain failure') {
              throw new Error('injected keychain failure');
            }
          },
        },
      );

      expect(result).toMatchObject({
        kind: 'rejected',
        reason: failure === 'epoch mismatch' ? 'epoch-mismatch' : 'key-install',
      });
      expect(installAttempts).toBe(failure === 'keychain failure' ? 1 : 0);
      expect(bob.generation).toBe(beforeGeneration);
      expect(await bob.getRootSecret()).toEqual(beforeRoot);
      expect(await treeFingerprint(bob)).toBe(beforeTree);

      expect(await bob.processPathUpdate(pathUpdate)).toEqual(rootSecret);
    },
  );
});
