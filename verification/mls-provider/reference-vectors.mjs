import * as mls from 'ts-mls';
import { decodeRatchetTree } from 'ts-mls/ratchetTree.js';
import vectors from './vectors/passive-client.json' with { type: 'json' };

const equal = (a, b) =>
  a.length === b.length && a.every((value, index) => value === b[index]);
function check(value) {
  if (!value) throw new Error('MLS reference vector check failed');
}
function hex(value) {
  check(/^(?:[0-9a-f]{2})*$/i.test(value));
  return Uint8Array.from(value.match(/../g) ?? [], (part) =>
    Number.parseInt(part, 16),
  );
}
function decode(value) {
  const input = hex(value),
    result = mls.decodeMlsMessage(input, 0);
  check(result && result[1] === input.length);
  return result[0];
}
export async function runReferenceVectors() {
  const suite = await mls.getCiphersuiteImpl(
    mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
  );
  let epochs = 0;
  for (const vector of vectors.cases) {
    const kp = decode(vector.key_package),
      welcome = decode(vector.welcome);
    check(
      kp.wireformat === 'mls_key_package' &&
        welcome.wireformat === 'mls_welcome',
    );
    const privateKeys = {
      hpkePrivateKey: hex(vector.encryption_priv),
      initPrivateKey: hex(vector.init_priv),
      signaturePrivateKey: hex(vector.signature_priv),
    };
    const psks = Object.fromEntries(
      vector.external_psks.map((value) => [
        mls.bytesToBase64(hex(value.psk_id)),
        hex(value.psk),
      ]),
    );
    let tree;
    if (vector.ratchet_tree !== null) {
      const input = hex(vector.ratchet_tree),
        parsed = decodeRatchetTree(input, 0);
      check(parsed && parsed[1] === input.length);
      tree = parsed[0];
    }
    // The RFC fixtures use upstream retention/credential policy; application policy is tested separately.
    let state = await mls.joinGroup(
      welcome.welcome,
      kp.keyPackage,
      privateKeys,
      mls.makePskIndex(undefined, psks),
      suite,
      tree,
    );
    check(
      equal(
        state.keySchedule.epochAuthenticator,
        hex(vector.initial_epoch_authenticator),
      ),
    );
    for (const epoch of vector.epochs) {
      for (const input of [...epoch.proposals, epoch.commit]) {
        const message = decode(input);
        let applied;
        if (message.wireformat === 'mls_private_message')
          applied = await mls.processPrivateMessage(
            state,
            message.privateMessage,
            mls.makePskIndex(state, psks),
            suite,
          );
        else {
          check(message.wireformat === 'mls_public_message');
          applied = await mls.processPublicMessage(
            state,
            message.publicMessage,
            mls.makePskIndex(state, psks),
            suite,
          );
        }
        state = applied.newState;
        applied.consumed.forEach((secret) => secret.fill(0));
      }
      check(
        equal(
          state.keySchedule.epochAuthenticator,
          hex(epoch.epoch_authenticator),
        ),
      );
      epochs++;
    }
    for (const material of Object.values(privateKeys)) material.fill(0);
    for (const material of Object.values(psks)) material.fill(0);
  }
  return {
    cases: vectors.cases.length,
    epochs,
    revision: vectors.revision,
    sha256: vectors.sha256,
  };
}
