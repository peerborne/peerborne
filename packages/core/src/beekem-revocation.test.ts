/**
 * Unit-level coverage of BeeKEM reader-revocation primitives.
 *
 * These tests compose the BeeKEM tree, HKDF document-key derivation, and
 * AES-GCM helpers without constructing a `PeerborneDocument` or network
 * stack. Document transition ordering is covered by the dedicated
 * peerborne-document transition and reader-registration harnesses.
 */

import { describe, expect, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import {
  deserializePathUpdateV2FromWire,
  serializePathUpdateV2ForWire,
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

async function treeFingerprint(beekem: BeeKEM): Promise<string> {
  const nodes = (
    beekem as unknown as {
      _nodes: Map<
        number,
        {
          type: string;
          publicKey: CryptoKey | null;
          privateKey?: CryptoKey;
        }
      >;
    }
  )._nodes;
  const entries = await Promise.all(
    [...nodes.entries()]
      .sort(([left], [right]) => left - right)
      .map(async ([index, node]) => ({
        index,
        type: node.type,
        publicKey:
          node.publicKey === null
            ? null
            : Buffer.from(
                await crypto.subtle.exportKey('raw', node.publicKey),
              ).toString('base64'),
        privateKey:
          node.privateKey === undefined
            ? null
            : Buffer.from(
                await crypto.subtle.exportKey('pkcs8', node.privateKey),
              ).toString('base64'),
      })),
  );
  return JSON.stringify(entries);
}

describe('BeeKEM reader revocation', () => {
  test('removed reader cannot derive the new document key even if connected', async () => {
    // Alice (writer) sets up a 2-member group (Alice + Bob). The test
    // focuses on the simplest configuration that exercises the
    // revocation security property: a removed reader cannot derive the
    // new document key from the writer-broadcast PathUpdate. Larger
    // tree configurations are exercised by the wire-codec composition tests
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
    // return values covers the primitives consumed by the document layer.
    const bobLeafIndex = 2;
    const { pathUpdate, rootSecret: aliceNewRoot } =
      await alice.removeMember(bobLeafIndex);

    // Wire-format round-trip: PathUpdate goes over the
    // beekemPathUpdateV2 protocol, so the security claim must hold
    // through serialization too.
    const wire = JSON.parse(
      JSON.stringify(serializePathUpdateV2ForWire(pathUpdate)),
    );
    const restored = deserializePathUpdateV2FromWire(wire);

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
      JSON.stringify(serializePathUpdateV2ForWire(pathUpdate)),
    );
    const restored = deserializePathUpdateV2FromWire(wire);
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
    const bobControl = new BeeKEM();
    const bobSubject = new BeeKEM();
    await bobControl.processWelcome(
      welcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );
    await bobSubject.processWelcome(
      welcome,
      bobKeys.privateKey,
      bobKeys.publicKey,
    );

    const { pathUpdate, rootSecret: aliceRoot } = await alice.update();
    const wire = serializePathUpdateV2ForWire(pathUpdate);

    // The unchanged generation-2 update must be applicable and converge. This
    // control ensures the tampered subject below reaches ciphertext
    // authentication rather than failing an earlier generation check.
    const controlUpdate = deserializePathUpdateV2FromWire(
      JSON.parse(JSON.stringify(wire)),
    );
    const controlRoot = await bobControl.processPathUpdate(controlUpdate);
    expect(controlRoot).toEqual(aliceRoot);

    const generationBefore = bobSubject.generation;
    const treeBefore = await treeFingerprint(bobSubject);
    const rootBefore = await bobSubject.getRootSecret();

    // Flip a bit in the first v2 copath bundle. The
    // BeeKEM module's AES-GCM-backed ECIES has built-in
    // authentication, so tampered ciphertext must surface as a
    // decryption error -- not silently produce an
    // attacker-controlled derived key.
    const tampered = JSON.parse(JSON.stringify(wire));
    const firstBundle = tampered.nodes[0]?.encryptedPathKeyBundles[0];
    if (!firstBundle) throw new Error('test PathUpdate has no v2 bundle');
    const bytes = Buffer.from(firstBundle.ciphertext, 'base64');
    bytes[bytes.length - 1] ^= 0xff; // flip last byte
    firstBundle.ciphertext = bytes.toString('base64');

    const restored = deserializePathUpdateV2FromWire(tampered);
    await expect(bobSubject.processPathUpdate(restored)).rejects.toThrow();
    expect(bobSubject.generation).toBe(generationBefore);
    expect(await treeFingerprint(bobSubject)).toBe(treeBefore);
    expect(await bobSubject.getRootSecret()).toEqual(rootBefore);
  });

  test('writer can recover leaf assignment from BeeKEM tree after cache wipe', async () => {
    // Models loss of the in-memory `_readerLeafIndices` cache while the same
    // BeeKEM instance and tree remain available. This does not model a process
    // restart or durable tree restoration. The peerborne-document layer tracks
    // the reader's KEM public key alongside the leaf index and can scan the
    // live BeeKEM tree by that public key on a cache miss.
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
    // not the previous one, without requiring a follow-up `update()`.
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

  test('upfront readerKemPublicKey length validation throws before any BeeKEM mutation', async () => {
    // READER KEM KEY VALIDATION INVARIANT:
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
    // would be called). This establishes only the modeled primitive order;
    // document-level behavior belongs in the peerborne-document harness.
    //
    // To exercise the property without needing a full
    // `PeerborneDocument`, we mirror the intended document-layer order:
    //   1. caller-provided length validation (the new gate)
    //   2. ACL mutation
    //   3. BeeKEM.addMember (would mutate the tree)
    // If step 1 throws, steps 2 and 3 must NOT run -- which is the
    // local mirror is intended to exercise.
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
      // Upfront length gate before any state mutation.
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

  test('addReader founder-vs-joined-writer gate refuses to initialize a divergent founder tree', async () => {
    // FOUNDER-TREE INITIALIZATION INVARIANT:
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
    //   The fix uses explicit local-creation provenance. Hash count alone is
    //   insufficient because successful founder creation replicates its writer
    //   ACL before the first addReader call. Loaded/invited writers never set
    //   the monotonic local-founder flag and therefore cannot seed a new tree.
    //
    // This test pins only the gate's decision logic as a pure helper. The
    // peerborne-document transition harness exercises the actual method.
    type FakeDoc = {
      _beekemInitialized: boolean;
      _hashes: Set<string>;
      _localFounderEstablished: boolean;
      _invitationEpoch?: Uint8Array;
    };
    function founderGate(doc: FakeDoc) {
      // Mirror of the production gate in
      // `PeerborneDocument.addReader`. A divergence here is a test
      // bug; the production code is the source of truth.
      if (
        !doc._beekemInitialized &&
        !doc._localFounderEstablished &&
        (doc._hashes.size > 0 || doc._invitationEpoch !== undefined)
      ) {
        throw new Error(
          'cannot register a reader -- this writer has document state ' +
            'but no BeeKEM tree bootstrapped from a Welcome.',
        );
      }
    }

    // Genuine founder: successful creation already replicated one change.
    const founder: FakeDoc = {
      _beekemInitialized: false,
      _hashes: new Set<string>(['founder-writer-acl']),
      _localFounderEstablished: true,
    };
    expect(() => founderGate(founder)).not.toThrow();

    // Joined writer: has merged the writer-ACL change that authorized
    // them, so `_hashes.size > 0`. Without a BeeKEM Welcome they
    // remain `_beekemInitialized === false`. The gate MUST refuse.
    const joinedWriter: FakeDoc = {
      _beekemInitialized: false,
      _hashes: new Set<string>(['ipfs-cid-of-writer-acl-change']),
      _localFounderEstablished: false,
    };
    expect(() => founderGate(joinedWriter)).toThrow(
      /no BeeKEM tree bootstrapped from a Welcome/,
    );

    // Joined writer who HAS received and processed a BeeKEM Welcome:
    // `_beekemInitialized === true`. The gate must allow `addReader`
    // even though `_hashes` is non-empty (the post-Welcome steady state).
    const welcomedJoiner: FakeDoc = {
      _beekemInitialized: true,
      _hashes: new Set<string>(['ipfs-cid-of-writer-acl-change']),
      _localFounderEstablished: false,
    };
    expect(() => founderGate(welcomedJoiner)).not.toThrow();
  });
});
