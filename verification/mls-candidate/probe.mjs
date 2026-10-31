const encoder = new TextEncoder();
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
function check(value, code) {
  if (!value) throw new Error(code);
}
function decode(mls, bytes, expected) {
  check(bytes.length > 0 && bytes.length <= 4 * 1024 * 1024, 'wire-size');
  const result = mls.decodeMlsMessage(bytes, 0);
  check(result && result[1] === bytes.length, 'incomplete-wire-decode');
  check(result[0].version === 'mls10', 'wire-version');
  check(result[0].wireformat === expected, 'wire-kind');
  return result[0];
}
const wire = (mls, message, expected) =>
  decode(mls, mls.encodeMlsMessage(message), expected);

export async function runProbe(mls) {
  const suite = await mls.getCiphersuiteImpl(
    mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
  );
  const trusted = [];
  const authService = {
    async validateCredential(credential, signaturePublicKey) {
      return (
        credential.credentialType === 'basic' &&
        trusted.some(
          (member) =>
            !member.revoked &&
            member.expires > Date.now() &&
            equal(credential.identity, member.id) &&
            equal(signaturePublicKey, member.key),
        )
      );
    },
  };
  const config = {
    authService,
    keyRetentionConfig: {
      retainKeysForGenerations: 0,
      retainKeysForEpochs: 0,
      maximumForwardRatchetSteps: 32,
    },
    lifetimeConfig: mls.defaultLifetimeConfig,
    keyPackageEqualityConfig: mls.defaultKeyPackageEqualityConfig,
    paddingConfig: mls.defaultPaddingConfig,
  };
  const members = [];
  for (const name of ['alice', 'bob', 'carol']) {
    const keys = await suite.signature.keygen();
    const credential = {
      credentialType: 'basic',
      identity: encoder.encode(name),
    };
    const generated = await mls.generateKeyPackageWithKey(
      credential,
      mls.defaultCapabilities(),
      mls.defaultLifetime,
      [],
      keys,
      suite,
    );
    trusted.push({
      id: credential.identity,
      key: keys.publicKey,
      expires: Date.now() + 60_000,
      revoked: false,
    });
    members.push({ name, ...generated, state: undefined });
  }
  const [alice, bob, carol] = members;
  alice.state = await mls.createGroup(
    crypto.getRandomValues(new Uint8Array(32)),
    alice.publicPackage,
    alice.privatePackage,
    [],
    suite,
    config,
  );
  const sizes = { commits: [], welcomes: [], states: [] };
  function cloneState(state) {
    const bytes = mls.encodeGroupState(state);
    try {
      const restored = mls.decodeGroupState(bytes, 0);
      check(
        restored && restored[1] === bytes.length,
        'state-decode-incomplete',
      );
      return { ...structuredClone(restored[0]), clientConfig: config };
    } finally {
      bytes.fill(0);
    }
  }
  async function rejects(operation) {
    try {
      await operation();
      return false;
    } catch {
      return true;
    }
  }
  function erase(result) {
    result.consumed.forEach(mls.zeroOutUint8Array);
    check(
      result.consumed.every((secret) => secret.every((b) => b === 0)),
      'consumed-key-not-zeroed',
    );
  }
  async function commit(proposals, recipients, joining) {
    const result = await mls.createCommit(
      { state: alice.state, cipherSuite: suite },
      {
        wireAsPublicMessage: true,
        ratchetTreeExtension: true,
        extraProposals: proposals,
      },
    );
    const encoded = mls.encodeMlsMessage(result.commit);
    sizes.commits.push(encoded.length);
    const decoded = decode(mls, encoded, 'mls_public_message');
    alice.state = result.newState;
    erase(result);
    for (const member of recipients) {
      const applied = await mls.processPublicMessage(
        member.state,
        decoded.publicMessage,
        mls.emptyPskIndex,
        suite,
      );
      member.state = applied.newState;
      erase(applied);
    }
    if (joining) {
      const welcome = mls.encodeMlsMessage({
        version: 'mls10',
        wireformat: 'mls_welcome',
        welcome: result.welcome,
      });
      sizes.welcomes.push(welcome.length);
      joining.state = await mls.joinGroup(
        decode(mls, welcome, 'mls_welcome').welcome,
        joining.publicPackage,
        joining.privatePackage,
        mls.emptyPskIndex,
        suite,
        undefined,
        undefined,
        config,
      );
      mls.zeroOutUint8Array(joining.privatePackage.initPrivateKey);
    }
    return encoded;
  }
  await commit(
    [
      {
        proposalType: 'add',
        add: {
          keyPackage: wire(
            mls,
            {
              version: 'mls10',
              wireformat: 'mls_key_package',
              keyPackage: bob.publicPackage,
            },
            'mls_key_package',
          ).keyPackage,
        },
      },
    ],
    [],
    bob,
  );
  const delayed = await mls.createApplicationMessage(
    alice.state,
    encoder.encode('delayed test fixture'),
    suite,
  );
  alice.state = delayed.newState;
  erase(delayed);
  await commit(
    [{ proposalType: 'add', add: { keyPackage: carol.publicPackage } }],
    [bob],
    carol,
  );
  const bobBeforeUpdate = cloneState(bob.state);
  const update = await commit([], [bob, carol]);
  const tampered = decode(mls, update, 'mls_public_message');
  tampered.publicMessage.auth.signature[0] ^= 1;
  const tamperedCommitRejected = await rejects(() =>
    mls.processPublicMessage(
      cloneState(bobBeforeUpdate),
      tampered.publicMessage,
      mls.emptyPskIndex,
      suite,
    ),
  );
  const commitReplayRejected = await rejects(() =>
    mls.processPublicMessage(
      cloneState(bob.state),
      decode(mls, update, 'mls_public_message').publicMessage,
      mls.emptyPskIndex,
      suite,
    ),
  );
  let delayedEpochReadable = false;
  try {
    const opened = await mls.processPrivateMessage(
      bob.state,
      delayed.privateMessage,
      mls.emptyPskIndex,
      suite,
    );
    delayedEpochReadable = opened.kind === 'applicationMessage';
    if (opened.kind === 'applicationMessage') opened.message.fill(0);
  } catch {}
  const retentionObservation = {
    requestedEpochRetention: 0,
    retainedEpochCounts: members.map(
      (member) => member.state.historicalReceiverData.size,
    ),
    delayedEpochReadable,
  };
  async function assertConvergence(active) {
    const keys = await Promise.all(
      active.map((member) =>
        mls.mlsExporter(
          member.state.keySchedule.exporterSecret,
          'peerborne/candidate/probe',
          encoder.encode('same-context'),
          32,
          suite,
        ),
      ),
    );
    try {
      check(
        keys.every((key) => equal(key, keys[0])),
        'exporter-divergence',
      );
      check(
        active.every(
          (member) =>
            member.state.groupContext.epoch ===
            active[0].state.groupContext.epoch,
        ),
        'epoch-divergence',
      );
    } finally {
      keys.forEach((key) => key.fill(0));
    }
  }
  await assertConvergence(members);
  const plaintext = crypto.getRandomValues(new Uint8Array(1024));
  const sent = await mls.createApplicationMessage(
    alice.state,
    plaintext,
    suite,
  );
  alice.state = sent.newState;
  erase(sent);
  const application = wire(
    mls,
    {
      version: 'mls10',
      wireformat: 'mls_private_message',
      privateMessage: sent.privateMessage,
    },
    'mls_private_message',
  ).privateMessage;
  for (const member of [bob, carol]) {
    const result = await mls.processPrivateMessage(
      member.state,
      application,
      mls.emptyPskIndex,
      suite,
    );
    check(
      result.kind === 'applicationMessage' && equal(result.message, plaintext),
      'message-not-converged',
    );
    member.state = result.newState;
    result.message.fill(0);
    erase(result);
  }
  let replayRejected = false;
  try {
    await mls.processPrivateMessage(
      bob.state,
      application,
      mls.emptyPskIndex,
      suite,
    );
  } catch {
    replayRejected = true;
  }
  check(replayRejected, 'replay-accepted');
  const removedLeaf = carol.state.privatePath.leafIndex;
  await commit(
    [{ proposalType: 'remove', remove: { removed: removedLeaf } }],
    [bob, carol],
  );
  check(
    carol.state.groupActiveState.kind === 'removedFromGroup',
    'removed-member-still-active',
  );
  await assertConvergence([alice, bob]);
  const survivorExporter = await mls.mlsExporter(
    alice.state.keySchedule.exporterSecret,
    'peerborne/candidate/probe',
    encoder.encode('same-context'),
    32,
    suite,
  );
  const removedExporter = await mls.mlsExporter(
    carol.state.keySchedule.exporterSecret,
    'peerborne/candidate/probe',
    encoder.encode('same-context'),
    32,
    suite,
  );
  const removedExporterDiffers = !equal(survivorExporter, removedExporter);
  survivorExporter.fill(0);
  removedExporter.fill(0);
  check(removedExporterDiffers, 'removed-member-exporter-matches');
  const credentialRejections = {};
  const authorizedKeys = await suite.signature.keygen();
  const authorizedCredential = {
    credentialType: 'basic',
    identity: encoder.encode('authorized-control'),
  };
  trusted.push({
    id: authorizedCredential.identity,
    key: authorizedKeys.publicKey,
    expires: Date.now() + 60_000,
    revoked: false,
  });
  const authorizedPackage = await mls.generateKeyPackageWithKey(
    authorizedCredential,
    mls.defaultCapabilities(),
    mls.defaultLifetime,
    [],
    authorizedKeys,
    suite,
  );
  const authorizedAdd = await mls.createCommit(
    { state: cloneState(alice.state), cipherSuite: suite },
    {
      extraProposals: [
        {
          proposalType: 'add',
          add: { keyPackage: authorizedPackage.publicPackage },
        },
      ],
      ratchetTreeExtension: true,
    },
  );
  const authorizedJoin = await mls.joinGroup(
    authorizedAdd.welcome,
    authorizedPackage.publicPackage,
    authorizedPackage.privatePackage,
    mls.emptyPskIndex,
    suite,
    undefined,
    undefined,
    config,
  );
  await assertConvergence([
    { state: authorizedAdd.newState },
    { state: authorizedJoin },
  ]);
  erase(authorizedAdd);
  mls.zeroOutUint8Array(authorizedPackage.privatePackage.initPrivateKey);
  for (const kind of ['unknown', 'substituted', 'expired', 'revoked']) {
    const keys = await suite.signature.keygen();
    const credential = {
      credentialType: 'basic',
      identity: kind === 'substituted' ? trusted[0].id : encoder.encode(kind),
    };
    if (kind === 'expired' || kind === 'revoked') {
      trusted.push({
        id: credential.identity,
        key: keys.publicKey,
        expires: kind === 'expired' ? Date.now() - 1 : Date.now() + 60_000,
        revoked: kind === 'revoked',
      });
    }
    const candidate = await mls.generateKeyPackageWithKey(
      credential,
      mls.defaultCapabilities(),
      mls.defaultLifetime,
      [],
      keys,
      suite,
    );
    credentialRejections[kind] = await rejects(() =>
      mls.createCommit(
        { state: cloneState(alice.state), cipherSuite: suite },
        {
          extraProposals: [
            {
              proposalType: 'add',
              add: { keyPackage: candidate.publicPackage },
            },
          ],
        },
      ),
    );
    Object.values(candidate.privatePackage).forEach(mls.zeroOutUint8Array);
  }
  const next = await mls.createApplicationMessage(
    alice.state,
    plaintext,
    suite,
  );
  alice.state = next.newState;
  erase(next);
  let removedRejected = false;
  try {
    await mls.processPrivateMessage(
      carol.state,
      next.privateMessage,
      mls.emptyPskIndex,
      suite,
    );
  } catch {
    removedRejected = true;
  }
  check(removedRejected, 'removed-member-decrypted');
  plaintext.fill(0);
  for (const member of [alice, bob]) {
    const encoded = mls.encodeGroupState(member.state);
    sizes.states.push(encoded.length);
    const restored = mls.decodeGroupState(encoded, 0);
    check(
      restored && restored[1] === encoded.length,
      'state-decode-incomplete',
    );
    member.state = { ...structuredClone(restored[0]), clientConfig: config };
    encoded.fill(0);
  }
  await assertConvergence([alice, bob]);
  const afterRestorePayload = crypto.getRandomValues(new Uint8Array(32));
  const afterRestoreSent = await mls.createApplicationMessage(
    bob.state,
    afterRestorePayload,
    suite,
  );
  bob.state = afterRestoreSent.newState;
  erase(afterRestoreSent);
  const afterRestoreOpened = await mls.processPrivateMessage(
    alice.state,
    afterRestoreSent.privateMessage,
    mls.emptyPskIndex,
    suite,
  );
  check(
    afterRestoreOpened.kind === 'applicationMessage' &&
      equal(afterRestoreOpened.message, afterRestorePayload),
    'restored-state-cannot-exchange-message',
  );
  alice.state = afterRestoreOpened.newState;
  erase(afterRestoreOpened);
  afterRestorePayload.fill(0);
  afterRestoreOpened.message.fill(0);
  check(
    !(await authService.validateCredential(
      { credentialType: 'basic', identity: encoder.encode('unknown') },
      trusted[0].key,
    )),
    'unknown-credential-accepted',
  );
  check(
    !(await authService.validateCredential(
      { credentialType: 'basic', identity: trusted[0].id },
      trusted[1].key,
    )),
    'substituted-key-accepted',
  );
  trusted[0].revoked = true;
  check(
    !(await authService.validateCredential(
      { credentialType: 'basic', identity: trusted[0].id },
      trusted[0].key,
    )),
    'revoked-credential-accepted',
  );
  return {
    suite: suite.name,
    members: 3,
    epoch: Number(alice.state.groupContext.epoch),
    sequentialAdds: true,
    selfUpdate: true,
    removalExclusion: true,
    removedExporterDiffers,
    applicationReplayRejected: replayRejected,
    commitReplayRejected,
    tamperedCommitRejected,
    credentialRejections,
    authorizedAddControl: true,
    stateRoundTrip: true,
    retentionObservation,
    zeroEpochRetentionHonored:
      !delayedEpochReadable &&
      [alice, bob].every(
        (member) => member.state.historicalReceiverData.size === 0,
      ),
    sizes,
  };
}
