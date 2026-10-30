import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { BeeKEM } from '../../packages/core/dist/esm/src/beekem/beekem.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from '../../packages/core/dist/esm/src/derive-doc-key.js';
import {
  serializePathUpdateV2ForWire,
  deserializePathUpdateV2FromWire,
} from '../../packages/core/dist/esm/src/path-update-wire.js';
import {
  documentFixture,
  replicaOf,
  project,
  receiveEncrypted,
} from '../fixtures.mjs';
import { measure, measuredOnly, memory, nextTurn } from '../measure.mjs';

async function kemIdentity() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
}

async function newGroup() {
  const keys = await kemIdentity();
  const founder = new BeeKEM();
  await founder.initialize(keys.privateKey, keys.publicKey);
  return [founder];
}

async function addMember(members, keys) {
  const { welcome, pathUpdate } = await members[0].addMember(keys.publicKey);
  for (const member of members.slice(1))
    await member.processPathUpdate(pathUpdate);
  const joined = new BeeKEM();
  await joined.processWelcome(welcome, keys.privateKey, keys.publicKey);
  members.push(joined);
  const root = await members[0].getRootSecret();
  for (const member of members.slice(1)) {
    assert(
      Buffer.from(await member.getRootSecret()).equals(root),
      'all live BeeKEM roots must agree',
    );
  }
  return pathUpdate;
}

export async function group({ full, budgetMs, progress }) {
  const sizes = full ? [2, 4, 8, 16, 32, 64, 100] : [2, 4, 8];
  const rows = [];
  const fixture = await documentFixture();
  try {
    for (const size of sizes) {
      progress(`membership ${size} peers`);
      const members = await newGroup();
      for (let i = 1; i < size - 1; i++)
        await addMember(members, await kemIdentity());
      const invitee = await kemIdentity();
      let localMutationMs;
      let localFinishedBeforeMembership;
      let membershipFinished = false;
      const invitation = await measure(async () => {
        const changing = addMember(members, invitee).finally(() => {
          membershipFinished = true;
        });
        const started = performance.now();
        await fixture.document.change((doc) =>
          doc.getMap('local').set(`invite-${size}`, size),
        );
        localMutationMs = performance.now() - started;
        localFinishedBeforeMembership = !membershipFinished;
        return changing;
      });
      const removalIndex = members.at(-1).myLeafIndex;
      const removed = members.at(-1);
      const removedKey = await deriveDocumentKeyFromRootSecret(
        await removed.getRootSecret(),
      );
      let removeMutationMs;
      const revocation = await measure(async () => {
        const changing = (async () => {
          const { pathUpdate } = await members[0].removeMember(removalIndex);
          for (const survivor of members.slice(1, -1))
            await survivor.processPathUpdate(pathUpdate);
          await assert.rejects(
            () => removed.processPathUpdate(pathUpdate),
            /removed|not a member|blank/i,
          );
          return pathUpdate;
        })();
        const started = performance.now();
        await fixture.document.change((doc) =>
          doc.getMap('local').set(`revoke-${size}`, size),
        );
        removeMutationMs = performance.now() - started;
        return changing;
      });
      const root = await members[0].getRootSecret();
      for (const survivor of members.slice(1, -1)) {
        assert(
          Buffer.from(await survivor.getRootSecret()).equals(root),
          'revocation must converge among survivors',
        );
      }
      const newKey = await deriveDocumentKeyFromRootSecret(root);
      const encrypted = await fixture.auth.encrypt(
        new Uint8Array([1, 2, 3]),
        newKey,
      );
      await assert.rejects(() =>
        fixture.auth.decrypt(encrypted.data, removedKey, encrypted.nonce),
      );
      rows.push({
        peers: size,
        invitation: measuredOnly(invitation),
        revocation: measuredOnly(revocation),
        invitationWireBytes: JSON.stringify(
          serializePathUpdateV2ForWire(invitation.value),
        ).length,
        revocationWireBytes: JSON.stringify(
          serializePathUpdateV2ForWire(revocation.value),
        ).length,
        localMutationDuringInvitationMs: localMutationMs,
        localMutationDuringRevocationMs: removeMutationMs,
        localFinishedBeforeMembership,
      });
    }
    const exceeds = rows.filter(
      (row) =>
        Math.max(
          row.invitation.timerGapMs.max,
          row.revocation.timerGapMs.max,
          row.localMutationDuringInvitationMs,
          row.localMutationDuringRevocationMs,
        ) > budgetMs,
    );
    return {
      scope:
        'Legacy BeeKEM primitive, real per-member key application and an independent Peerborne local document. Includes fanout CPU, excludes network delivery and public addReader/removeReader coordination; not MLS.',
      metrics: {
        sizes,
        budgetMs,
        rows,
        localMutations: sizes.length * 2,
        removedPeerCannotDecrypt: true,
      },
      gaps: [
        'This primitive benchmark does not establish responsiveness of public document membership APIs or browser UI under a live multi-user membership change.',
        ...(exceeds.length
          ? [
              `Observed timer/local-mutation latency exceeds the configured ${budgetMs} ms budget at sizes: ${exceeds.map((row) => row.peers).join(', ')}.`,
            ]
          : []),
      ],
    };
  } finally {
    await fixture.close();
  }
}

export async function epochRace() {
  const writer = await documentFixture({ index: 1 });
  let receiver;
  try {
    await writer.document.change((doc) =>
      doc.getMap('root').set('value', 'before'),
    );
    receiver = await replicaOf(writer, 2);
    const [founder] = await newGroup();
    const root = (await founder.update()).rootSecret;
    const id = await deriveEpochIdFromRootSecret(root);
    const key = await deriveDocumentKeyFromRootSecret(root);
    await writer.document._keychain.addEpochKey(id, key);
    await writer.document.change((doc) =>
      doc.getMap('root').set('value', 'epoch-N'),
    );
    const frame = writer.stats.lastFrame;
    const initial = project(receiver);

    // Invoke the actual fire-and-forget pubsub listener installed by open().
    // A wrapped decrypt barrier and sync drain let the schedule settle without
    // relying on a fixed sleep to decide whether a mutation was lost.
    let decryptDone;
    const decrypted = new Promise((resolve) => {
      decryptDone = resolve;
    });
    const decrypt = receiver.document._decryptBlock.bind(receiver.document);
    receiver.document._decryptBlock = async (...args) => {
      try {
        return await decrypt(...args);
      } finally {
        decryptDone();
      }
    };
    const event = new Event('message');
    Object.defineProperty(event, 'detail', {
      value: { data: frame, topic: receiver.document._topic },
    });
    receiver.helia.libp2p.services.pubsub.dispatchEvent(event);
    await decrypted;
    await nextTurn();
    assert.deepEqual(
      project(receiver),
      initial,
      'unknown epoch must not mutate state or crash',
    );

    await receiver.document._keychain.addEpochKey(id, key);
    await nextTurn();
    await nextTurn();
    const automaticallyReplayed = project(receiver).root.value === 'epoch-N';
    assert.equal(
      await receiveEncrypted(receiver, frame),
      true,
      'explicit retransmission after installing key must recover',
    );
    assert.deepEqual(project(receiver), project(writer));

    const tampered = frame.slice();
    tampered[tampered.length - 1] ^= 1;
    assert.equal(
      await receiveEncrypted(receiver, tampered),
      false,
      'tampered AEAD frame must fail closed',
    );
    assert.deepEqual(project(receiver), project(writer));
    return {
      scope:
        'Production pubsub listener and AES-GCM + signed sync with a manually delayed authenticated key installation; no live network.',
      metrics: {
        automaticallyReplayed,
        explicitRetransmissionRecovered: true,
        tamperRejected: true,
        encryptedFrameBytes: frame.byteLength,
      },
      gaps: automaticallyReplayed
        ? []
        : [
            'The production listener drops ciphertext with an unknown epoch. Installing the delayed key does not replay it; a bounded authenticated epoch queue and retry path are not implemented.',
          ],
    };
  } finally {
    await receiver?.close();
    await writer.close();
  }
}

export async function offline({ full, budgetMs, progress }) {
  const transitions = full ? 500 : 12;
  const members = await newGroup();
  await addMember(members, await kemIdentity());
  const [online, offlinePeer] = members;
  const backlog = [];
  for (let i = 0; i < transitions; i++) {
    const { pathUpdate } = await online.update();
    backlog.push(JSON.stringify(serializePathUpdateV2ForWire(pathUpdate)));
    if ((i + 1) % 100 === 0)
      progress(`epoch generation ${i + 1}/${transitions}`);
  }
  const generationBefore = offlinePeer.generation;
  // An attempt to skip ancestors must fail without advancing the receiver.
  if (transitions > 1) {
    await assert.rejects(() =>
      offlinePeer.processPathUpdate(
        deserializePathUpdateV2FromWire(JSON.parse(backlog.at(-1))),
      ),
    );
    assert.equal(offlinePeer.generation, generationBefore);
  }
  const before = memory();
  const catchup = await measure(async () => {
    for (let i = 0; i < backlog.length; i++) {
      await offlinePeer.processPathUpdate(
        deserializePathUpdateV2FromWire(JSON.parse(backlog[i])),
      );
      assert.equal(
        offlinePeer.generation,
        generationBefore + i + 1,
        'every ancestor must advance exactly one generation',
      );
    }
  });
  const onlineRoot = await online.getRootSecret();
  const offlineRoot = await offlinePeer.getRootSecret();
  assert(
    Buffer.from(onlineRoot).equals(offlineRoot),
    '500-transition replay must derive the current root',
  );
  const fixture = await documentFixture();
  try {
    const key = await deriveDocumentKeyFromRootSecret(onlineRoot);
    const recoveredKey = await deriveDocumentKeyFromRootSecret(offlineRoot);
    const payload = new TextEncoder().encode(
      'synthetic current document state',
    );
    const encrypted = await fixture.auth.encrypt(payload, key);
    const plaintext = await fixture.auth.decrypt(
      encrypted.data,
      recoveredKey,
      encrypted.nonce,
    );
    assert(
      Buffer.from(plaintext).equals(payload),
      'offline peer must decrypt current state',
    );
    // The newest exact replay must not create another generation.
    await offlinePeer.processPathUpdate(
      deserializePathUpdateV2FromWire(JSON.parse(backlog.at(-1))),
    );
    assert.equal(offlinePeer.generation, generationBefore + transitions);
    return {
      scope:
        'Real BeeKEM v2 wire codecs and sequential cryptographic replay in Node. Backlog is explicitly supplied by the fixture, not fetched from durable storage or a peer.',
      metrics: {
        transitions,
        backlogBytes: backlog.reduce(
          (sum, frame) => sum + Buffer.byteLength(frame),
          0,
        ),
        recovered: true,
        finalStateDecrypted: true,
        budgetMs,
        before,
        after: memory(),
        ...measuredOnly(catchup),
      },
      gaps: [
        'Automatic retrieval of 500 missed transitions, persistent BeeKEM restart recovery, and browser UI responsiveness remain unverified by this in-process replay.',
        ...(catchup.timerGapMs.max > budgetMs
          ? [`Catch-up timer gap exceeds ${budgetMs} ms.`]
          : []),
      ],
    };
  } finally {
    await fixture.close();
  }
}
