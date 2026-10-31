import { MlsProviderSpike } from './provider.js';
import * as mls from 'ts-mls';
import {
  EncryptedGroupState,
  WebCryptoGroupStateProtector,
} from '@peerborne/core/browser-primitives';

const encoder = new TextEncoder();
const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((value, index) => value === b[index]);
function check(value: unknown, name: string): asserts value {
  if (!value) throw new Error(name);
}
async function rejects(
  operation: () => unknown | Promise<unknown>,
  name: string,
) {
  let rejected = false;
  try {
    await operation();
  } catch {
    rejected = true;
  }
  check(rejected, name);
}

export async function runProviderChecks() {
  const group = crypto.getRandomValues(new Uint8Array(32));
  const ids = ['alice', 'bob', 'carol'].map((value) => encoder.encode(value));
  const proof = encoder.encode('public native integration fixture');
  const trusted = new Map<string, Uint8Array>();
  const revoked = new Set<string>();
  const label = (id: Uint8Array) => Array.from(id).join(',');
  const policy = async ({
    memberId,
    signingKey,
    credential,
  }: {
    memberId: Uint8Array;
    signingKey: Uint8Array;
    credential: Uint8Array;
  }) => {
    const expected = trusted.get(label(memberId));
    return (
      !!expected &&
      !revoked.has(label(memberId)) &&
      equal(expected, signingKey) &&
      equal(credential, proof)
    );
  };
  const peers = await Promise.all(
    ids.map((id) => MlsProviderSpike.initialize(id, ids[0], policy)),
  );
  peers.forEach((peer, index) =>
    trusted.set(label(ids[index]), peer.credentialSigningKey),
  );
  const [alice, originalBob, carol] = peers;
  const protector =
    await WebCryptoGroupStateProtector.generate('mls-native-fixture');
  const initial = await alice.createGroup({
    groupId: group,
    creatorMemberId: ids[0],
    credential: proof,
  });
  check(
    initial.state.confirmedTranscriptHash.length === 0,
    'genesis must retain the real RFC empty transcript',
  );
  const bobPackage = await originalBob.createKeyPackage({
    groupId: group,
    memberId: ids[1],
    credential: proof,
    requestCommitment: crypto.getRandomValues(new Uint8Array(32)),
  });
  const encryptedPackage = await originalBob.exportEncryptedKeyPackage(
    bobPackage.reference,
    protector,
  );
  check(
    equal(
      encryptedPackage.serialize(),
      (
        await originalBob.exportEncryptedKeyPackage(
          bobPackage.reference,
          protector,
        )
      ).serialize(),
    ),
    'pending export must be stable',
  );
  const bob = await MlsProviderSpike.initialize(ids[1], ids[0], policy);
  const imported = await bob.importEncryptedKeyPackage(
    encryptedPackage,
    protector,
  );
  check(
    equal(await alice.authenticateKeyPackageMember(imported), ids[1]),
    'member must come from credential',
  );
  const wrongGroup = structuredClone(imported);
  wrongGroup.groupId[0] ^= 1;
  await rejects(
    () => alice.authenticateKeyPackageMember(wrongGroup),
    'package must bind intended group',
  );
  const wrongReference = structuredClone(imported);
  wrongReference.reference[0] ^= 1;
  await rejects(
    () => alice.authenticateKeyPackageMember(wrongReference),
    'package reference must bind signed bytes',
  );
  const add = await alice.createCommit({
    changes: [{ kind: 'add', memberId: ids[1], keyPackage: imported }],
  });
  check(
    add.welcomes.length === 1 &&
      add.appliedMembership.changes[0].kind === 'add',
    'add must carry one matching welcome',
  );
  await bob.joinGroup({
    welcome: add.welcomes[0],
    keyPackageRef: imported.reference,
  });
  await rejects(
    () => bob.importEncryptedKeyPackage(encryptedPackage, protector),
    'consumed package must not reimport',
  );
  await rejects(
    () => bob.createCommit({ changes: [] }),
    'only controller commits',
  );
  const epochOne = await alice.exportEncryptedState(protector);
  const resumed = await MlsProviderSpike.initialize(ids[0], ids[0], policy);
  await resumed.importEncryptedState(epochOne, protector);
  check(
    equal(resumed.credentialSigningKey, alice.credentialSigningKey),
    'restored signing binding',
  );
  const context = {
    label: 'peerborne/document-content-encryption/v1',
    context: group,
    length: 32,
  };
  const firstSecret = await resumed.exportSecret(context);
  check(
    equal(firstSecret, await bob.exportSecret(context)),
    'restored exporter must converge',
  );
  firstSecret.fill(0);
  const carolPackage = await carol.createKeyPackage({
    groupId: group,
    memberId: ids[2],
    credential: proof,
    requestCommitment: crypto.getRandomValues(new Uint8Array(32)),
  });
  await rejects(
    () =>
      resumed.createCommit({
        changes: [{ kind: 'add', memberId: ids[1], keyPackage: carolPackage }],
      }),
    'subject substitution',
  );
  const second = await resumed.createCommit({
    changes: [{ kind: 'add', memberId: ids[2], keyPackage: carolPackage }],
  });
  check(
    (await bob.applyCommit(second.commit)).status === 'applied',
    'existing member applies add',
  );
  await carol.joinGroup({
    welcome: second.welcomes[0],
    keyPackageRef: carolPackage.reference,
  });
  const before = await bob.exportSecret(context);
  const corrupt = structuredClone(second.commit);
  corrupt.payload[corrupt.payload.length - 1] ^= 1;
  await rejects(() => bob.applyCommit(corrupt), 'tampered or replayed commit');
  check(
    equal(before, await bob.exportSecret(context)),
    'failed commit must leave state unchanged',
  );
  const update = await resumed.createCommit({ changes: [] });
  check(
    update.appliedMembership.changes.length === 0 &&
      update.welcomes.length === 0,
    'self-update has no membership delta',
  );
  const freshTampered = structuredClone(update.commit);
  freshTampered.payload[freshTampered.payload.length - 1] ^= 1;
  await rejects(() => bob.applyCommit(freshTampered), 'fresh tampered commit');
  check(
    equal(before, await bob.exportSecret(context)),
    'cryptographic failure must leave state unchanged',
  );
  const trailing = {
    ...structuredClone(update.commit),
    payload: new Uint8Array([...update.commit.payload, 0]),
  };
  await rejects(() => bob.applyCommit(trailing), 'trailing wire bytes');
  const changedEpoch = {
    ...structuredClone(update.commit),
    epoch: update.commit.epoch + 1n,
  };
  await rejects(
    () => bob.applyCommit(changedEpoch),
    'mismatched envelope epoch',
  );
  const captured = structuredClone(update.commit),
    applying = bob.applyCommit(captured);
  captured.payload.fill(0);
  await applying;
  await carol.applyCommit(update.commit);
  if (typeof SharedArrayBuffer !== 'undefined') {
    await rejects(
      () =>
        bob.applyCommit({
          ...update.commit,
          payload: new Uint8Array(new SharedArrayBuffer(32)),
        }),
      'shared byte input',
    );
  }
  const after = await resumed.exportSecret(context);
  check(!equal(before, after), 'self-update rotates exporter');
  before.fill(0);
  after.fill(0);
  const saved = await bob.exportEncryptedState(protector);
  const plaintext = await saved.open(protector);
  try {
    const metadata = saved.state;
    metadata.treeHash[0] ^= 1;
    const forged = await EncryptedGroupState.seal(
      metadata,
      plaintext,
      protector,
    );
    const prior = await bob.exportSecret(context);
    await rejects(
      () => bob.importEncryptedState(forged, protector),
      'authenticated metadata substitution',
    );
    check(
      equal(prior, await bob.exportSecret(context)),
      'bad import must be atomic',
    );
    prior.fill(0);
    const modified = plaintext.slice();
    const view = new DataView(modified.buffer);
    let offset = encoder.encode('peerborne/mls-group-spike/1\0').length;
    for (let field = 0; field < 3; field++)
      offset += 4 + view.getUint32(offset);
    const length = view.getUint32(offset);
    offset += 4;
    const encoded = modified.slice(offset, offset + length);
    const decoded = mls.decodeGroupState(encoded, 0);
    check(decoded && decoded[1] === encoded.length, 'test checkpoint framing');
    const privateKey =
      decoded[0].privatePath.privateKeys[decoded[0].privatePath.leafIndex * 2];
    privateKey[16] ^= 1;
    const changed = mls.encodeGroupState(decoded[0]);
    check(changed.length === length, 'test checkpoint width');
    modified.set(changed, offset);
    try {
      const badKey = await EncryptedGroupState.seal(
        saved.state,
        modified,
        protector,
      );
      await rejects(
        () => bob.importEncryptedState(badKey, protector),
        'restored HPKE key must match its public tree node',
      );
    } finally {
      modified.fill(0);
      encoded.fill(0);
      changed.fill(0);
      privateKey.fill(0);
    }
  } finally {
    plaintext.fill(0);
  }
  const savedBytes = saved.serialize();
  savedBytes[savedBytes.length - 1] ^= 1;
  await rejects(
    () =>
      bob.importEncryptedState(
        EncryptedGroupState.deserialize(savedBytes),
        protector,
      ),
    'ciphertext corruption',
  );
  const oldCarolSecret = await carol.exportSecret(context);
  revoked.add(label(ids[2]));
  const removal = await resumed.createCommit({
    changes: [{ kind: 'remove', memberId: ids[2] }],
  });
  check(
    resumed.obsoletePathsErased > 0,
    'obsolete private paths must be erased after tree contraction',
  );
  await bob.applyCommit(removal.commit);
  check(
    (await carol.applyCommit(removal.commit)).status === 'removed',
    'removed member is terminal',
  );
  check(!(await carol.hasActiveGroup()), 'removed member has no active group');
  await rejects(
    () => carol.exportSecret(context),
    'removed member cannot export',
  );
  const survivor = await resumed.exportSecret(context);
  check(
    equal(survivor, await bob.exportSecret(context)) &&
      !equal(survivor, oldCarolSecret),
    'removal changes exporter and survivors converge',
  );
  survivor.fill(0);
  oldCarolSecret.fill(0);
  const restartedBob = await MlsProviderSpike.initialize(
    ids[1],
    ids[0],
    policy,
  );
  await rejects(
    () => restartedBob.importEncryptedState(saved, protector),
    'revoked binding prevents stale roster import',
  );
  const latest = await bob.exportEncryptedState(protector);
  await restartedBob.importEncryptedState(latest, protector);
  check(
    (await restartedBob.getPublicState()).epoch === removal.state.epoch,
    'latest state survives fresh provider reconstruction',
  );
  await rejects(
    () => restartedBob.importEncryptedKeyPackage(encryptedPackage, protector),
    'joined-state consumed package cannot return',
  );
  await Promise.all(
    [resumed, bob, restartedBob, alice, originalBob].map((peer) =>
      peer.clearGroupState(),
    ),
  );
  return {
    pendingKeyPackageRecovery: true,
    stablePendingExport: true,
    authenticatedAdds: true,
    selfUpdate: true,
    exporterConvergence: true,
    encryptedStateRecovery: true,
    atomicInvalidImport: true,
    credentialRevocation: true,
    controllerEnforcement: true,
    terminalRemoval: true,
    consumedPackageRejection: true,
  };
}
