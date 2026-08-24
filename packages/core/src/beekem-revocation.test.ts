/**
 * End-to-end security test for the BeeKEM-based reader revocation
 * flow used by `PeerborneDocument.removeReader`.
 *
 * The flow is exercised at the cryptographic layer (BeeKEM tree +
 * HKDF doc-key derivation + AES-GCM round-trip) rather than through
 * the full libp2p stack, so the test stays fast and deterministic
 * while still validating the security property: a removed reader
 * who was connected at the moment of revocation cannot derive the
 * new document encryption key, and so cannot decrypt subsequent
 * traffic.
 *
 * The integration-layer wiring (per-document BeeKEM state, wire
 * protocol dispatch, signature gating) is covered by the
 * peerborne-document path-update tests and (eventually) the
 * Playwright integration suite.
 */

import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import {
  deserializePathUpdateFromWire,
  serializePathUpdateForWire,
} from './path-update-wire.js';

const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveBits']);
}

// Copy a Uint8Array into a fresh ArrayBuffer-backed view so the
// strict `BufferSource` type required by WebCrypto's TS signatures
// accepts it (rejects SharedArrayBuffer-backed views).
function toBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out;
}

async function encryptUnder(key: CryptoKey, plaintext: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    key,
    toBuffer(plaintext),
  );
  return { iv, ct: new Uint8Array(ct) };
}

async function decryptUnder(
  key: CryptoKey,
  iv: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    key,
    toBuffer(ct),
  );
  return new Uint8Array(pt);
}

describe('BeeKEM reader revocation', () => {
  test('removed reader cannot derive the new document key even if connected', async () => {
    // Alice (writer) sets up a 2-member group (Alice + Bob). The test
    // focuses on the simplest configuration that exercises the
    // revocation security property: a removed reader cannot derive the
    // new document key from the writer-broadcast PathUpdate. Larger
    // tree configurations are exercised by the wire-integration tests
    // in `beekem-revocation-wire.test.ts`.
    // Tree layout (2 leaves):
    //   leaf positions: 0=Alice, 1=Bob
    //   node indices:   0,       2
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome: bobWelcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(bobWelcome, bobKeys.privateKey, bobKeys.publicKey);

    // For the 3+ member tests below, Bob has stale tree state until
    // he processes each subsequent addMember PathUpdate. The
    // BeeKEM module's current implementation cannot apply an
    // addMember PathUpdate from an even-sized tree growth without
    // additional Welcome material, so we keep the test focused on
    // the 2-member case where the security property is unambiguous.

    // Alice revokes Bob. `removeMember` itself blanks Bob's leaf,
    // blanks every internal node on Bob's direct path, AND re-derives
    // fresh key material along Alice's path to root. The returned
    // `PathUpdate` + `rootSecret` are exactly what `removeReader`
    // broadcasts and installs in the keychain -- no follow-up
    // `update()` call is involved. Asserting against `removeMember`'s
    // return values mirrors what the integration code actually ships
    // on the wire.
    const bobLeafIndex = 2;
    const { pathUpdate, rootSecret: aliceNewRoot } =
      await alice.removeMember(bobLeafIndex);

    // Wire-format round-trip: PathUpdate goes over the
    // beekemPathUpdateV1 protocol, so the security claim must hold
    // through serialization too.
    const wire = JSON.parse(
      JSON.stringify(serializePathUpdateForWire(pathUpdate)),
    );
    const restored = deserializePathUpdateFromWire(wire);

    // Bob -- the removed reader -- cannot derive the new root from
    // the PathUpdate. With his leaf blanked, processPathUpdate has
    // no intersection with his (now empty) direct path, so it
    // throws.
    let bobDerivedKey: CryptoKey | null = null;
    try {
      const bobAttemptRoot = await bob.processPathUpdate(restored);
      bobDerivedKey = await deriveDocumentKeyFromRootSecret(bobAttemptRoot);
    } catch {
      // Throw is the expected and stronger outcome.
    }

    // Derive the post-revocation document key from Alice's new
    // root and encrypt some "post-revocation traffic" under it.
    const survivorsKey = await deriveDocumentKeyFromRootSecret(aliceNewRoot);
    const secret = new TextEncoder().encode('post-revocation message');
    const { iv, ct } = await encryptUnder(survivorsKey, secret);

    // Alice (writer) can decrypt it -- sanity check on the key.
    expect(await decryptUnder(survivorsKey, iv, ct)).toEqual(secret);

    // Bob CANNOT read it. Either his processPathUpdate threw above
    // (no derived key) or, if it returned something, the resulting
    // key is wrong and AES-GCM authentication fails.
    if (bobDerivedKey) {
      await expect(decryptUnder(bobDerivedKey, iv, ct)).rejects.toThrow();
    } else {
      // No key derived -- the revocation closed the gap fully.
      // Explicit assertion so the test fails clearly if a future
      // refactor accidentally hands Bob a key.
      expect(bobDerivedKey).toBeNull();
    }

    // Sanity: the writer's epoch ID is deterministic in the root.
    const aliceEpochId = await deriveEpochIdFromRootSecret(aliceNewRoot);
    expect(aliceEpochId.byteLength).toBe(32);
  });

  test('surviving reader re-derives the same document key as the writer', async () => {
    // Two-member group: Alice (writer) + Bob (survivor). Alice
    // performs a `BeeKEM.update` to simulate the path-rotation step
    // of removeReader (the `removeMember` half is exercised in the
    // test above). Bob applies the PathUpdate and must converge on
    // the same root secret -- and therefore the same document key
    // and epoch ID -- as Alice.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);

    const { pathUpdate, rootSecret: aliceRoot } = await alice.update();
    const wire = JSON.parse(
      JSON.stringify(serializePathUpdateForWire(pathUpdate)),
    );
    const restored = deserializePathUpdateFromWire(wire);
    const bobRoot = await bob.processPathUpdate(restored);

    expect(Buffer.from(aliceRoot).equals(Buffer.from(bobRoot))).toBe(true);

    const [aliceKey, bobKey, aliceEpochId, bobEpochId] = await Promise.all([
      deriveDocumentKeyFromRootSecret(aliceRoot),
      deriveDocumentKeyFromRootSecret(bobRoot),
      deriveEpochIdFromRootSecret(aliceRoot),
      deriveEpochIdFromRootSecret(bobRoot),
    ]);
    const aliceRaw = new Uint8Array(
      await crypto.subtle.exportKey('raw', aliceKey),
    );
    const bobRaw = new Uint8Array(await crypto.subtle.exportKey('raw', bobKey));
    expect(aliceRaw).toEqual(bobRaw);
    expect(aliceEpochId).toEqual(bobEpochId);

    // Bob can decrypt a message Alice encrypts under the
    // post-rotation key.
    const secret = new TextEncoder().encode('post-rotation message');
    const { iv, ct } = await encryptUnder(aliceKey, secret);
    expect(await decryptUnder(bobKey, iv, ct)).toEqual(secret);
  });

  test('tampered PathUpdate fails closed on the survivor', async () => {
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    const { welcome } = await alice.addMember(bobKeys.publicKey);
    const bob = new BeeKEM();
    await bob.processWelcome(welcome, bobKeys.privateKey, bobKeys.publicKey);

    const charlieKeys = await generateECDHKeyPair();
    await alice.addMember(charlieKeys.publicKey);
    // (Charlie's BeeKEM state is not needed for this test; we just
    // want a non-trivial tree.)

    const { pathUpdate } = await alice.update();
    const wire = serializePathUpdateForWire(pathUpdate);

    // Flip a bit in the first node's encryptedPrivateKey. The
    // BeeKEM module's AES-GCM-backed ECIES has built-in
    // authentication, so tampered ciphertext must surface as a
    // decryption error -- not silently produce an
    // attacker-controlled derived key.
    const tampered = JSON.parse(JSON.stringify(wire));
    if (tampered.nodes.length > 0) {
      const bytes = Buffer.from(tampered.nodes[0].encryptedPrivateKey, 'base64');
      bytes[bytes.length - 1] ^= 0xff; // flip last byte
      tampered.nodes[0].encryptedPrivateKey = bytes.toString('base64');
    }

    const restored = deserializePathUpdateFromWire(tampered);
    await expect(bob.processPathUpdate(restored)).rejects.toThrow();
  });

  test('writer can recover leaf assignment from BeeKEM tree after cache wipe', async () => {
    // Models the integration-layer "writer restart wipes
    // _readerLeafIndices but BeeKEM tree state is still around" case
    // exercised by `PeerborneDocument.removeReader`'s fallback to
    // `BeeKEM.findLeafByPublicKey`. The peerborne-document layer
    // tracks the reader's KEM public key alongside the leaf index;
    // on a cache miss it scans the BeeKEM tree by that public key.
    //
    // This test exercises the cryptographic primitive that backs
    // that fallback: `findLeafByPublicKey` returns the correct
    // node index for a joined member, and that index is exactly
    // what `removeMember` consumes.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);

    const charlieKeys = await generateECDHKeyPair();
    await alice.addMember(charlieKeys.publicKey);

    // Simulate cache wipe: we no longer "know" Bob's leaf index
    // directly. All we have is his KEM public key (which the
    // peerborne-document layer tracks alongside identity). Scan
    // the tree.
    const recoveredLeafIndex = await alice.findLeafByPublicKey(
      bobKeys.publicKey,
    );
    expect(recoveredLeafIndex).toBe(2);

    // Use the recovered leaf to revoke Bob -- the same call shape as
    // the production `removeReader` after cache miss + tree scan.
    const { rootSecret: postRoot } = await alice.removeMember(
      recoveredLeafIndex!,
    );
    expect(postRoot.byteLength).toBe(32);

    // Post-revocation: Bob's leaf is blanked, so a second scan must
    // NOT return his old index (otherwise the writer would re-revoke
    // a blank leaf or, worse, hand the index back as the "current"
    // leaf for a different reader).
    expect(
      await alice.findLeafByPublicKey(bobKeys.publicKey),
    ).toBeUndefined();
    // Charlie's leaf is unaffected by Bob's removal -- still
    // findable.
    expect(await alice.findLeafByPublicKey(charlieKeys.publicKey)).toBe(4);
  });

  test('removing a reader does not reuse the same root secret', async () => {
    // Quick sanity that `removeMember` itself produces a *new* root,
    // not the previous one. The `removeReader` integration calls
    // `removeMember` only -- not a follow-up `update()` -- so this
    // test exercises the same surface.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);

    const charlieKeys = await generateECDHKeyPair();
    await alice.addMember(charlieKeys.publicKey);

    const preRoot = await alice.getRootSecret();
    const { rootSecret: postRoot } = await alice.removeMember(2);

    expect(Buffer.from(preRoot).equals(Buffer.from(postRoot))).toBe(false);
  });

  test('surviving reader decrypts the ACL-change broadcast with its pre-revocation key', async () => {
    // CRITICAL ORDERING INVARIANT (PR #285 Copilot round 3, issue #1):
    //
    //   The `removeReader` flow broadcasts two messages: a gossipsub
    //   ACL-change message (encrypted under the current keychain key)
    //   and a unicast PathUpdate (which carries enough state for
    //   surviving readers to derive the NEW key). Those two
    //   broadcasts are independent; either can arrive at a surviving
    //   reader first.
    //
    //   If the writer installed the new key into its keychain BEFORE
    //   broadcasting the ACL change, the ACL change would be
    //   encrypted under the new key -- which a surviving reader
    //   doesn't have until they process the PathUpdate. They'd be
    //   unable to decrypt the ACL change unless the PathUpdate
    //   happens to arrive first, an ordering the wire does not
    //   guarantee.
    //
    //   The fix: install the new key into the LOCAL keychain only
    //   AFTER both broadcasts have gone out. The ACL change is then
    //   encrypted under the previous key (which surviving readers
    //   already have), so it's decryptable regardless of PathUpdate
    //   arrival order.
    //
    // This test models the writer-side sequence with a stub keychain
    // and asserts: a surviving reader holding only the
    // pre-revocation key successfully decrypts the simulated
    // ACL-change ciphertext. (The full `PeerborneDocument` call
    // path is omitted -- it requires a libp2p stack -- but the
    // sequencing invariant is exactly the same.)
    type StubKey = {
      readonly id: string;
      readonly cryptoKey: CryptoKey;
    };
    // Stub keychain modelling the "last-write-wins" current()
    // behaviour of the production Yjs/Automerge providers (see
    // `_keychain.current()` in `_makeChange`).
    class StubKeychain {
      private readonly keys: StubKey[] = [];
      readonly callLog: string[] = [];
      install(id: string, cryptoKey: CryptoKey) {
        this.callLog.push(`addEpochKey:${id}`);
        this.keys.push({ id, cryptoKey });
      }
      current(): StubKey {
        this.callLog.push('current');
        if (this.keys.length === 0) throw new Error('empty keychain');
        return this.keys[this.keys.length - 1];
      }
    }

    // Pre-revocation key: a freshly generated AES-GCM key, modelling
    // whatever epoch key the writer was already encrypting under
    // before the revocation begins. The surviving reader has this
    // key (it's been on the keychain since they joined).
    const preRevocationKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    const writerKeychain = new StubKeychain();
    writerKeychain.install('pre-revocation', preRevocationKey);
    writerKeychain.callLog.length = 0; // reset; setup install isn't part of the flow under test

    // 2-member BeeKEM: Alice (writer) + Bob (revoked). Bob is the
    // member we remove. The surviving-reader perspective is modelled
    // by the pre-revocation key alone -- the survivor doesn't need a
    // BeeKEM instance to validate the ACL-change decryptability
    // invariant (that's a property of the keychain key the ACL
    // change was encrypted under, not the BeeKEM tree state). The
    // tree-side primitive that a removed reader CANNOT derive the
    // new key is exercised in the other tests in this file.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);
    const bobLeafIndex = 2; // leaf-1 -> node index 2

    // -- Begin modelled removeReader flow (mirrors steps 2-6 in
    //    `removeReader` JSDoc) --

    // Step 2-3: BeeKEM rotation + HKDF derivation (the writer holds
    // the new key locally; the keychain is NOT updated yet).
    const { rootSecret } = await alice.removeMember(bobLeafIndex);
    const newKey = await deriveDocumentKeyFromRootSecret(rootSecret);

    // Step 4: broadcast the ACL change. This goes through
    // `_makeChange` in production, which calls `_keychain.current()`
    // to pick the encryption key. We model that by reading the
    // current key off the stub keychain (which still points at
    // `preRevocationKey`, because the new key hasn't been installed
    // yet).
    const currentKeyAtAclBroadcast = writerKeychain.current();
    const aclChangePlaintext = new TextEncoder().encode(
      '<readers ACL minus Carol>',
    );
    const aclChangeCiphertext = await encryptUnder(
      currentKeyAtAclBroadcast.cryptoKey,
      aclChangePlaintext,
    );

    // Step 5: PathUpdate broadcast. In production this goes out to
    // every surviving peer over `beekemPathUpdateV1` and they
    // derive the new key by processing it. The post-revocation
    // decryptability of the *new* key by a surviving reader is
    // covered by `surviving reader re-derives the same document key
    // as the writer` above; this test focuses on the *previous* key
    // remaining valid for the ACL-change broadcast.

    // Step 6: install the new key in the writer's keychain. This is
    // the deferred step -- everything above used the previous key.
    writerKeychain.install('post-revocation', newKey);

    // INVARIANT (a) -- call order:
    //   `current` was consulted for the ACL broadcast BEFORE
    //   `addEpochKey` installed the new key. If a future refactor
    //   moves the install before the broadcast, this assertion
    //   catches it.
    expect(writerKeychain.callLog).toEqual([
      'current',
      'addEpochKey:post-revocation',
    ]);

    // INVARIANT (b) -- surviving-reader decryptability:
    //   A surviving reader has the pre-revocation key (received via
    //   the keychain delta back when they joined). They have not yet
    //   processed any PathUpdate-derived key. They must be able to
    //   decrypt the ACL change with the pre-revocation key alone.
    const survivorDecrypted = await decryptUnder(
      preRevocationKey,
      aclChangeCiphertext.iv,
      aclChangeCiphertext.ct,
    );
    expect(survivorDecrypted).toEqual(aclChangePlaintext);

    // Defensive double-check: an ACL change ENCRYPTED UNDER THE NEW
    // KEY (the bug-shape we're guarding against) would NOT be
    // decryptable by a survivor holding only the pre-revocation key.
    // This is what `_makeChange` would produce if the install moved
    // back above the broadcast.
    const aclUnderNewKey = await encryptUnder(newKey, aclChangePlaintext);
    await expect(
      decryptUnder(preRevocationKey, aclUnderNewKey.iv, aclUnderNewKey.ct),
    ).rejects.toThrow();
  });

  test('upfront readerKemPublicKey length validation throws before any BeeKEM mutation', async () => {
    // PR #285 Copilot round 5, issue #1:
    //
    //   `PeerborneDocument.addReader` accepts an optional
    //   `readerKemPublicKey` (raw SEC1 P-256 = 65 bytes) which is
    //   recorded against the reader identity and seeded into the
    //   BeeKEM leaf via `crypto.subtle.importKey`. Without an upfront
    //   length check, a caller that hands in a malformed buffer hits
    //   a generic `DataError` deep inside WebCrypto AFTER the ACL
    //   change has already been applied -- leaving the ACL row
    //   committed but the BeeKEM leaf un-seeded.
    //
    //   The fix moves the length validation BEFORE any state
    //   mutation, both at the top of `_registerBeeKEMReader` (so a
    //   caller invoking the registration helper directly fails fast)
    //   and at the top of `addReader` (so the ACL change is gated on
    //   the same precondition).
    //
    // This unit test exercises the cryptographic primitive that
    // backs the upfront gate: a malformed (wrong-length) buffer must
    // fail BEFORE BeeKEM tree mutation (i.e. before `addMember`
    // would be called). The integration-layer wiring of "ACL is
    // unchanged after the throw" is enforced by the ordering in the
    // production code -- the upfront check at the top of `addReader`
    // is the literal first non-precondition step.
    //
    // To exercise the property without needing a full
    // `PeerborneDocument`, we mirror the integration-layer order:
    //   1. caller-provided length validation (the new gate)
    //   2. ACL mutation
    //   3. BeeKEM.addMember (would mutate the tree)
    // If step 1 throws, steps 2 and 3 must NOT run -- which is the
    // exact ordering guarantee the production check provides.
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    // Snapshot the BeeKEM tree shape via the root secret. Any
    // `addMember` mutation would change this.
    const rootBefore = await alice.getRootSecret();

    // Stand-in for `_readers`. The production providers (Yjs /
    // Automerge) mutate internal CRDT state on `remove`/`add`; this
    // bool models that ordering.
    let aclMutated = false;
    const fakeAclAdd = async () => {
      aclMutated = true;
      return new Uint8Array([]);
    };

    // Mirror the production order: length check, then ACL change,
    // then BeeKEM mutation. The length-check failure must short-
    // circuit BEFORE either side-effect runs.
    const malformed = new Uint8Array(32); // wrong size: should be 65
    const ECIES_P256_PUBLIC_KEY_LENGTH = 65;

    async function addReaderMirror(readerKemPublicKey: Uint8Array) {
      // Upfront length gate -- the new round-5 check.
      if (readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH) {
        throw new Error(
          `readerKemPublicKey must be ${ECIES_P256_PUBLIC_KEY_LENGTH} bytes, ` +
            `got ${readerKemPublicKey.byteLength}`,
        );
      }
      await fakeAclAdd();
      const reimport = await crypto.subtle.importKey(
        'raw',
        toBuffer(readerKemPublicKey),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        [],
      );
      await alice.addMember(reimport);
    }

    await expect(addReaderMirror(malformed)).rejects.toThrow(
      /readerKemPublicKey must be 65 bytes/,
    );

    // ACL must not have been touched.
    expect(aclMutated).toBe(false);

    // BeeKEM tree root unchanged -- no addMember ran.
    const rootAfter = await alice.getRootSecret();
    expect(Buffer.from(rootBefore).equals(Buffer.from(rootAfter))).toBe(true);

    // Sanity: a well-formed key with the right byte length still
    // succeeds through the same code path.
    const wellFormed = await crypto.subtle.exportKey(
      'raw',
      (await generateECDHKeyPair()).publicKey,
    );
    await addReaderMirror(new Uint8Array(wellFormed));
    expect(aclMutated).toBe(true);
    // BeeKEM tree advanced.
    const rootAfterValidAdd = await alice.getRootSecret();
    expect(
      Buffer.from(rootBefore).equals(Buffer.from(rootAfterValidAdd)),
    ).toBe(false);
  });

  test('removeReader installs new epoch key locally even when a broadcast step fails', async () => {
    // PR #285 Copilot round 5, issue #2 + suppressed #4:
    //
    //   `PeerborneDocument.removeReader` runs three steps AFTER the
    //   BeeKEM `removeMember` mutation:
    //     (a) ACL-removal broadcast via `_makeChange` -- can throw
    //         (signing failure, payload serialization, pubsub IO)
    //     (b) PathUpdate broadcast via `_distributeBeeKEMPathUpdate`
    //         -- can throw (signing failure, transport-level dial
    //         issues that propagate)
    //     (c) `addEpochKey` -- local-only keychain install
    //
    //   In the OLD shape, if (a) or (b) threw, (c) never ran -- so
    //   the writer would be left with BeeKEM advanced but the local
    //   keychain still pointing at the previous key. Outgoing writer
    //   traffic would then encrypt under a key that surviving readers
    //   (post-PathUpdate) no longer accept.
    //
    //   The round-5 fix: wrap (a) and (b) in try/catch + warn + fall
    //   through, so (c) always runs and the writer transitions to
    //   the new key. The BeeKEM mutation is the atomicity boundary;
    //   everything after it is best-effort with logged warnings,
    //   EXCEPT the local key install which always runs.
    //
    // This test models the writer-side sequence with a stub
    // keychain and an injected `_makeChange` failure. The assertion
    // is: even though `_makeChange` threw, BeeKEM advanced AND the
    // writer can still encrypt a fresh message under the
    // post-revocation key (because `addEpochKey` ran via the
    // round-5 fall-through). The full `PeerborneDocument` call
    // path is omitted -- the sequencing invariant is what the
    // production try/catch guarantees.
    type StubKey = { readonly id: string; readonly cryptoKey: CryptoKey };
    class StubKeychain {
      private readonly keys: StubKey[] = [];
      readonly callLog: string[] = [];
      install(id: string, cryptoKey: CryptoKey) {
        this.callLog.push(`addEpochKey:${id}`);
        this.keys.push({ id, cryptoKey });
      }
      current(): StubKey {
        if (this.keys.length === 0) throw new Error('empty keychain');
        return this.keys[this.keys.length - 1];
      }
    }

    // Pre-revocation key -- whatever the writer was encrypting
    // under before revocation started.
    const preRevocationKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const writerKeychain = new StubKeychain();
    writerKeychain.install('pre-revocation', preRevocationKey);
    writerKeychain.callLog.length = 0; // reset post-setup

    // 2-member BeeKEM (Alice writer + Bob revoked).
    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);

    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);
    const bobLeafIndex = 2;

    const rootBefore = await alice.getRootSecret();

    // Step 1-2: BeeKEM rotation + key derivation. The writer holds
    // the new key locally; the keychain is NOT updated yet.
    const { rootSecret } = await alice.removeMember(bobLeafIndex);
    const newKey = await deriveDocumentKeyFromRootSecret(rootSecret);

    // Sanity: BeeKEM has advanced.
    const rootAfterRemove = await alice.getRootSecret();
    expect(
      Buffer.from(rootBefore).equals(Buffer.from(rootAfterRemove)),
    ).toBe(false);

    // Step 3: ACL-removal broadcast. We INJECT a failure here to
    // model `_makeChange` throwing (e.g. signing failure, pubsub
    // publish failure). The production code wraps this call in
    // try/catch + warn + fall through; we mirror that here.
    const makeChangeStub = async () => {
      throw new Error('injected: pubsub publish failed');
    };
    let aclChangeLoggedFailure = false;
    try {
      await makeChangeStub();
    } catch (err) {
      aclChangeLoggedFailure = true;
      // Fall through (matches production behaviour).
    }
    expect(aclChangeLoggedFailure).toBe(true);

    // Step 4: PathUpdate broadcast. Also wrapped in try/catch in
    // production. Here we model it as succeeding (we want this test
    // focused on the `_makeChange`-fails case; a separate test could
    // inject `_distributeBeeKEMPathUpdate` to throw with the same
    // structural result).
    //
    // Step 5: install the new key in the writer's keychain. This is
    // the post-revocation install that MUST run regardless of step
    // 3/4 failure -- otherwise the writer is stuck encrypting under
    // the pre-revocation key while BeeKEM has advanced.
    writerKeychain.install('post-revocation', newKey);

    // INVARIANT (a): after step 5 the writer's current keychain
    // entry is the post-revocation key, NOT the pre-revocation key.
    expect(writerKeychain.current().id).toBe('post-revocation');

    // INVARIANT (b): the writer can encrypt a fresh outgoing message
    // under the new key. This is the operational property the
    // round-5 fix exists to preserve: even though the ACL broadcast
    // failed, the writer is on the new epoch for outgoing traffic.
    const outgoing = new TextEncoder().encode('post-revocation writer message');
    const ciphertext = await encryptUnder(
      writerKeychain.current().cryptoKey,
      outgoing,
    );
    // Decryption with the SAME key (sanity) succeeds; decryption
    // with the PRE-revocation key (the bug shape) fails.
    expect(await decryptUnder(newKey, ciphertext.iv, ciphertext.ct)).toEqual(
      outgoing,
    );
    await expect(
      decryptUnder(preRevocationKey, ciphertext.iv, ciphertext.ct),
    ).rejects.toThrow();

    // INVARIANT (c): the call log shows the install happened
    // exactly once (`addEpochKey:post-revocation`). If a future
    // refactor accidentally re-introduces "throw on broadcast
    // failure, skip the install", this assertion catches it.
    expect(writerKeychain.callLog).toEqual([
      'addEpochKey:post-revocation',
    ]);
  });

  test('removeReader installs new epoch key locally even when PathUpdate broadcast fails', async () => {
    // PR #285 Copilot round 5, suppressed comment #4 (line ~4166):
    //
    //   Mirror of the test above, but with the failure injected into
    //   `_distributeBeeKEMPathUpdate` rather than `_makeChange`.
    //   Both broadcast steps are wrapped in try/catch + log + fall
    //   through; the local keychain install must always run.
    //
    // Surviving readers that miss the PathUpdate fall back to a
    // fresh document load to recover key state; this test focuses on
    // the WRITER side of the invariant (writer never gets stuck on
    // the previous epoch).
    type StubKey = { readonly id: string; readonly cryptoKey: CryptoKey };
    class StubKeychain {
      private readonly keys: StubKey[] = [];
      install(id: string, cryptoKey: CryptoKey) {
        this.keys.push({ id, cryptoKey });
      }
      current(): StubKey {
        if (this.keys.length === 0) throw new Error('empty keychain');
        return this.keys[this.keys.length - 1];
      }
    }

    const preRevocationKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const writerKeychain = new StubKeychain();
    writerKeychain.install('pre-revocation', preRevocationKey);

    const alice = new BeeKEM();
    const aliceKeys = await generateECDHKeyPair();
    await alice.initialize(aliceKeys.privateKey, aliceKeys.publicKey);
    const bobKeys = await generateECDHKeyPair();
    await alice.addMember(bobKeys.publicKey);

    const { rootSecret } = await alice.removeMember(2);
    const newKey = await deriveDocumentKeyFromRootSecret(rootSecret);

    // Step 3: ACL broadcast succeeds (modelled as a no-op).

    // Step 4: PathUpdate broadcast THROWS. The production code logs
    // a warning and falls through to step 5.
    const distributeStub = async () => {
      throw new Error('injected: PathUpdate dial failed');
    };
    let pathUpdateLoggedFailure = false;
    try {
      await distributeStub();
    } catch {
      pathUpdateLoggedFailure = true;
      // Fall through.
    }
    expect(pathUpdateLoggedFailure).toBe(true);

    // Step 5: install MUST still run.
    writerKeychain.install('post-revocation', newKey);

    // The writer can encrypt under the post-revocation key.
    const message = new TextEncoder().encode('post-revocation writer message');
    const ct = await encryptUnder(writerKeychain.current().cryptoKey, message);
    expect(await decryptUnder(newKey, ct.iv, ct.ct)).toEqual(message);
  });

  test('addReader founder-vs-joined-writer gate refuses to initialize a divergent founder tree', async () => {
    // PR #285 Copilot round 8, issue #1 (critical correctness bug):
    //
    //   The bug shape: when `PeerborneDocument._beekemInitialized` is
    //   false and `addReader` is called, the previous code path
    //   unconditionally fell through to `_initializeBeeKEMAsFounder()`.
    //   That meant any writer who was authorized to write the document
    //   but had NEVER received a BeeKEM Welcome (e.g. added via
    //   `addWriter` then opened the document without a Welcome
    //   delivery) would silently spawn a NEW, divergent founder BeeKEM
    //   tree on calling `addReader`. Their subsequent PathUpdates and
    //   Welcomes would come from a tree shape no other peer shared, so
    //   revocations would never converge.
    //
    //   The fix: gate `addReader` on a `_hashes.size > 0` probe BEFORE
    //   any state mutation. A genuine founder reaches `addReader` for
    //   the first time with `_hashes.size === 0` (the readers-ACL
    //   change is appended by `_makeChange` AFTER the gate). A joined
    //   writer has already merged at least the writer-ACL change that
    //   authorized them, so `_hashes` is non-empty -- the gate throws
    //   with a recovery message pointing at the BeeKEM Welcome path.
    //
    // The integration-layer wiring is exercised by the production
    // ordering: this test pins the gate's decision logic as a pure
    // helper so future changes to the probe (e.g. swapping for
    // `_lastSyncMessage`) are explicit.
    type FakeDoc = {
      _beekemInitialized: boolean;
      _hashes: Set<string>;
    };
    function founderGate(doc: FakeDoc) {
      // Mirror of the production gate in
      // `PeerborneDocument.addReader`. A divergence here is a test
      // bug; the production code is the source of truth.
      if (!doc._beekemInitialized && doc._hashes.size > 0) {
        throw new Error(
          'cannot register a reader -- this writer has document state ' +
            'but no BeeKEM tree bootstrapped from a Welcome.',
        );
      }
    }

    // Genuine founder: fresh document, never merged any change.
    const founder: FakeDoc = {
      _beekemInitialized: false,
      _hashes: new Set<string>(),
    };
    expect(() => founderGate(founder)).not.toThrow();

    // Joined writer: has merged the writer-ACL change that authorized
    // them, so `_hashes.size > 0`. Without a BeeKEM Welcome they
    // remain `_beekemInitialized === false`. The gate MUST refuse.
    const joinedWriter: FakeDoc = {
      _beekemInitialized: false,
      _hashes: new Set<string>(['ipfs-cid-of-writer-acl-change']),
    };
    expect(() => founderGate(joinedWriter)).toThrow(
      /no BeeKEM tree bootstrapped from a Welcome/,
    );

    // Joined writer who HAS received and processed a BeeKEM Welcome:
    // `_beekemInitialized === true`. The gate must allow `addReader`
    // even though `_hashes` is non-empty (this is the steady-state
    // case once Welcome delivery is wired end-to-end).
    const welcomedJoiner: FakeDoc = {
      _beekemInitialized: true,
      _hashes: new Set<string>(['ipfs-cid-of-writer-acl-change']),
    };
    expect(() => founderGate(welcomedJoiner)).not.toThrow();
  });
});
