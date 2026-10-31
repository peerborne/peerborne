import assert from 'node:assert/strict';
import { BeeKEM } from '../../../packages/core/dist/esm/src/beekem/beekem.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from '../../../packages/core/dist/esm/src/derive-doc-key.js';
import {
  serializePathUpdateV2ForWire,
  deserializePathUpdateV2FromWire,
} from '../../../packages/core/dist/esm/src/path-update-wire.js';
import {
  documentFixture,
  replicaOf,
  publishedMessage,
  receiveEncrypted,
  seededRandom,
  project,
} from '../../fixtures.mjs';
import { measure, measuredOnly } from '../../measure.mjs';

export async function group(count = 3) {
  const keys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const first = new BeeKEM();
  await first.initialize(keys.privateKey, keys.publicKey);
  const members = [first];
  for (let i = 1; i < count; i++) {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    const { welcome, pathUpdate } = await first.addMember(pair.publicKey);
    for (const member of members.slice(1))
      await member.processPathUpdate(pathUpdate);
    const next = new BeeKEM();
    await next.processWelcome(welcome, pair.privateKey, pair.publicKey);
    members.push(next);
  }
  return members;
}

const same = (left, right) => Buffer.from(left).equals(right);
async function install(fixture, root) {
  await fixture.document._keychain.addEpochKey(
    await deriveEpochIdFromRootSecret(root),
    await deriveDocumentKeyFromRootSecret(root),
  );
}

export async function epochFork({ full, seed }) {
  const [a, b, removed] = await group();
  const originalGeneration = a.generation;
  const receiver = a.clone();
  const left = await a.removeMember(removed.myLeafIndex);
  const right = await b.removeMember(removed.myLeafIndex);
  assert.equal(
    a.generation,
    originalGeneration + 1,
    'left partition advances one generation',
  );
  assert.equal(
    b.generation,
    originalGeneration + 1,
    'right partition advances one generation',
  );
  assert(
    !same(left.rootSecret, right.rootSecret),
    'concurrent revocations must actually create distinct roots',
  );
  const rootA = await a.getRootSecret();
  const rootB = await b.getRootSecret();
  const rejection = await Promise.allSettled([
    a.processPathUpdate(right.pathUpdate),
    b.processPathUpdate(left.pathUpdate),
  ]);
  assert(
    rejection.every(({ status }) => status === 'rejected'),
    'siblings must not silently overwrite current ratchet state',
  );
  assert(
    same(await a.getRootSecret(), rootA) &&
      same(await b.getRootSecret(), rootB),
    'fork rejection must preserve committed roots',
  );

  const wire = serializePathUpdateV2ForWire(left.pathUpdate);
  const random = seededRandom(seed);
  const cases = full ? 512 : 48;
  for (let i = 0; i < cases; i++) {
    const malformed = structuredClone(wire);
    switch (i % 4) {
      case 0:
        malformed.generation = [
          -1,
          0,
          0x100000000,
          Number.MAX_SAFE_INTEGER,
          null,
          1.5,
        ][Math.floor(random() * 6)];
        break;
      case 1:
        malformed.parentTreeHash = ['', 'AA==', [], {}, null][
          Math.floor(random() * 5)
        ];
        break;
      case 2:
        malformed.numLeaves = [-1, 0, 8193, Number.MAX_SAFE_INTEGER][
          Math.floor(random() * 4)
        ];
        break;
      case 3:
        malformed.nodes = [null, {}, [null]][Math.floor(random() * 3)];
        break;
    }
    assert.throws(
      () => deserializePathUpdateV2FromWire(malformed),
      'malformed transition must be rejected by the actual codec',
    );
  }
  for (const generation of [-1, 1.5, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(() =>
      receiver.processPathUpdate({ ...left.pathUpdate, generation }),
    );
    assert.equal(
      receiver.generation,
      originalGeneration,
      'malformed runtime transition cannot advance state',
    );
  }
  const writer = await documentFixture();
  let peer;
  try {
    peer = await replicaOf(writer, 2);
    await install(writer, rootA);
    await install(peer, rootB);
    await writer.document.change((doc) =>
      doc.getMap('root').set('partitionA', true),
    );
    await peer.document.change((doc) =>
      doc.getMap('root').set('partitionB', true),
    );
    const cannotReadA = !(await receiveEncrypted(peer, writer.stats.lastFrame));
    const cannotReadB = !(await receiveEncrypted(writer, peer.stats.lastFrame));
    assert(
      cannotReadA && cannotReadB,
      'probe must expose the unresolved divergent epoch keys',
    );
    return {
      scope:
        'Actual BeeKEM sibling revocations, v2 boundary codec, and signed/encrypted document ingress; transitions and partition delivery are scheduled by the fixture.',
      metrics: {
        originalGeneration,
        siblingRejections: 2,
        malformedWireCases: cases,
        malformedRuntimeCases: 3,
        rootsPreservedOnRejection: true,
        subsequentCrossPartitionFramesDecryptable: false,
        localMutationsStillWork: true,
      },
      gaps: [
        'Sibling epochs are rejected and remain divergent. No automatic causal-epoch-DAG resolution or authenticated catch-up/rejoin was observed; subsequent cross-partition mutations cannot be decrypted.',
      ],
    };
  } finally {
    await peer?.close();
    await writer.close();
  }
}

export async function keyCompromise({ full }) {
  const [a, b] = await group(2);
  const authFixture = await documentFixture();
  try {
    const oldRoot = await a.getRootSecret();
    const oldKey = await deriveDocumentKeyFromRootSecret(oldRoot);
    await install(authFixture, oldRoot);
    const past = await authFixture.auth.encrypt(
      new Uint8Array([1, 2, 3]),
      oldKey,
    );
    const first = await a.update();
    await b.processPathUpdate(first.pathUpdate);
    const leakedEpochKey = await deriveDocumentKeyFromRootSecret(
      first.rootSecret,
    );
    const sameEpochPast = await authFixture.auth.encrypt(
      new Uint8Array([7, 8]),
      leakedEpochKey,
    );
    assert(
      same(
        await authFixture.auth.decrypt(
          sameEpochPast.data,
          leakedEpochKey,
          sameEpochPast.nonce,
        ),
        new Uint8Array([7, 8]),
      ),
      'a sole epoch key leak reveals earlier operations in that same epoch',
    );
    await assert.rejects(() =>
      authFixture.auth.decrypt(past.data, leakedEpochKey, past.nonce),
    );
    // A current member can read retained key history despite distinct AES keys.
    await install(authFixture, await b.getRootSecret());
    const historicId = await deriveEpochIdFromRootSecret(oldRoot);
    assert(
      authFixture.document._keychain.getKey(historicId),
      'retained historical key must actually be present in this compromise model',
    );

    const attacker = b.clone();
    const rounds = full ? 32 : 3;
    for (let i = 0; i < rounds; i++) {
      const update = await a.update();
      await b.processPathUpdate(update.pathUpdate);
      await attacker.processPathUpdate(update.pathUpdate);
      assert(
        same(await attacker.getRootSecret(), await b.getRootSecret()),
        'full member-state compromise follows other members updates',
      );
    }
    const healing = await b.update();
    await a.processPathUpdate(healing.pathUpdate);
    const nextKey = await deriveDocumentKeyFromRootSecret(healing.rootSecret);
    const future = await authFixture.auth.encrypt(
      new Uint8Array([4, 5, 6]),
      nextKey,
    );
    const application = await Promise.allSettled([
      attacker.processPathUpdate(healing.pathUpdate),
    ]);
    const staleAttackerKey = await deriveDocumentKeyFromRootSecret(
      await attacker.getRootSecret(),
    );
    const staleDecryption = await Promise.allSettled([
      authFixture.auth.decrypt(future.data, staleAttackerKey, future.nonce),
    ]);
    await assert.rejects(() =>
      authFixture.auth.decrypt(future.data, leakedEpochKey, future.nonce),
    );
    const fullStateHealed = staleDecryption[0].status === 'rejected';
    const timing = await measure(async () =>
      authFixture.auth.decrypt(
        future.data,
        await deriveDocumentKeyFromRootSecret(await a.getRootSecret()),
        future.nonce,
      ),
    );
    assert(
      same(timing.value, new Uint8Array([4, 5, 6])),
      'legitimate survivor must decrypt the post-ratchet state',
    );
    return {
      scope:
        'Separate attacker models: sole epoch AES key, retained document keychain, and cloned in-memory BeeKEM member state. Real crypto and ratchets; not MLS or persistent key erasure evidence.',
      metrics: {
        soleCurrentKeyDecryptsPriorEpoch: false,
        soleCurrentKeyDecryptsEarlierSameEpoch: true,
        soleCurrentKeyDecryptsFuture: false,
        retainedHistoryKeyAvailableToMember: true,
        otherMemberUpdatesFollowedByAttacker: rounds,
        ownFreshRatchetRejectedByAttacker: application[0].status === 'rejected',
        fullMemberStateHealedAfterOwnRatchet: fullStateHealed,
        ...measuredOnly(timing),
      },
      gaps: [
        'A leaked epoch key decrypts earlier ciphertext from that same epoch; there is no per-operation ratchet in this path.',
        'Distinct epoch AES keys do not establish forward secrecy for full device/member compromise: the shipped keychain retains old keys and history can be distributed to members. Durable key erasure, restart behavior and a reviewed forward-secrecy/post-compromise protocol remain outside this primitive proof.',
        ...(!fullStateHealed
          ? [
              'The cloned compromised member state could still decrypt after the member ratcheted.',
            ]
          : []),
      ],
    };
  } finally {
    await authFixture.close();
  }
}

export async function documentReplay({ full, seed }) {
  const a = await documentFixture({ path: `/advanced/replay-a-${seed}` });
  let b;
  try {
    b = await documentFixture({
      path: `/advanced/replay-b-${seed}`,
      identity: a.identity,
      index: 2,
    });
    const [sharedEpoch, sharedKey] = await a.document._keychain.current();
    await b.document._keychain.addEpochKey(sharedEpoch, sharedKey);
    await a.document.change((doc) =>
      doc.getMap('root').set('syntheticCanary', true),
    );
    const original = a.stats.lastFrame;
    const before = project(b);
    const raw = await b.document._decryptBlock(
      original.slice(0, 32),
      original.slice(32, 44),
      original.slice(44),
    );
    const decryptedAtCryptoLayer = raw !== undefined;
    assert.equal(
      await receiveEncrypted(b, original),
      false,
      'exact signed frame from A must not apply to B',
    );
    assert.deepEqual(
      project(b),
      before,
      'cross-document replay must not mutate B',
    );
    const message = await publishedMessage(a);
    const rebound = { ...message, documentId: b.document.documentPath };
    assert.equal(
      await b.document.sync(rebound),
      false,
      'rebinding document ID without a new signature must fail',
    );
    const changedParent = structuredClone(message);
    changedParent.changes.children = {};
    assert.equal(
      await a.document.sync(changedParent),
      false,
      'parent graph mutation must invalidate the original signature',
    );
    const random = seededRandom(seed);
    const count = full ? 512 : 32;
    for (let i = 0; i < count; i++) {
      const corrupt = original.slice();
      const index = Math.floor(random() * corrupt.length);
      corrupt[index] ^= 1 << i % 8;
      assert.equal(
        await receiveEncrypted(b, corrupt),
        false,
        'tampered key ID, nonce or ciphertext must never apply',
      );
    }
    for (const length of [0, 1, 11, 12, 31, 32, 43, 44, 45])
      assert.equal(
        await receiveEncrypted(b, original.slice(0, length)),
        false,
        'truncated frame must fail closed',
      );
    for (const context of [
      'load-response-v4',
      'invitation-bootstrap-v1',
      'invitation-catch-up-v1',
    ])
      assert.equal(
        await a.document.sync({ ...message, signatureContext: context }),
        false,
        'ordinary ingress must reject another signing context',
      );
    assert.deepEqual(
      project(b),
      before,
      'flood and boundary failures cannot mutate B',
    );
    return {
      scope:
        'Same signing authority and shared key material across two actual documents; raw AEAD ingress, signed document/parent/context binding, and ciphertext boundary mutations.',
      metrics: {
        exactCrossDocumentReplayRejected: true,
        documentIdRebindingRejected: true,
        parentTamperingRejected: true,
        decryptionSucceededBeforeRouting: decryptedAtCryptoLayer,
        corruptedFrames: count,
        truncatedFrames: 9,
        wrongContexts: 3,
        recipientStateUnchanged: true,
      },
      gaps: decryptedAtCryptoLayer
        ? [
            'Cross-document rejection occurs at signed message routing/verification after AEAD decryption. The shared-key ciphertext is not bound to the target document through AEAD additional authenticated data; this is not rejection at the cryptographic decryption layer.',
          ]
        : [],
    };
  } finally {
    await b?.close();
    await a.close();
  }
}
