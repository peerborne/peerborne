import { describe, expect, test } from '@jest/globals';
import { CRDTSyncMessage } from './crdt-sync-message.js';

/**
 * Unit-level coverage for the BeeKEM Welcome receive flow.
 *
 * The full receive path lives in `PeerborneDocument.handleBeeKEMWelcomeRequestData`
 * which requires libp2p/Helia and a real CRDT/keychain provider to instantiate.
 * Following the convention used by `compaction.test.ts` and the
 * `validateDocumentPath` tests in `peerborne.test.ts`, this file replicates
 * the decision logic of the receive path against a minimal in-memory keychain
 * substitute, so we can verify:
 *
 *   1. `_invitationEpoch` is set from `welcomeEpochId` after a Welcome is
 *      processed (Issue #178).
 *   2. The visibility filter (`since_invited`) returns only the keys at or
 *      after the recorded `_invitationEpoch` (Issue #179).
 *
 * The real implementations live in:
 *   - `PeerborneDocument.handleBeeKEMWelcomeRequestData` (sets `_invitationEpoch`)
 *   - `PeerborneDocument._keychainChangesForVisibility` (filters by visibility)
 *   - `YjsKeychain.historySince` / `AutomergeKeychain.historySince` (filtering)
 */

type Visibility = 'full_history' | 'since_invited' | 'current_only';

// Minimal in-memory keychain that emulates the parts of the Keychain
// interface relevant to history visibility filtering. Mirrors the Yjs/
// Automerge implementations' append-only insertion-order semantics.
class InMemoryKeychain {
  private _keys: { id: string; key: string }[] = [];

  static toHex(b: Uint8Array): string {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }

  add(id: Uint8Array, key: string): void {
    this._keys.push({ id: InMemoryKeychain.toHex(id), key });
  }

  history(): { id: string; key: string }[] {
    return this._keys.slice();
  }

  currentKeyChange(): { id: string; key: string }[] {
    if (this._keys.length === 0) {
      throw new Error('empty keychain');
    }
    return [this._keys[this._keys.length - 1]];
  }

  historySince(id: Uint8Array): { id: string; key: string }[] {
    const target = InMemoryKeychain.toHex(id);
    const idx = this._keys.findIndex((k) => k.id === target);
    if (idx === -1) return this._keys.slice(); // fallback to full history
    return this._keys.slice(idx);
  }

  merge(slice: { id: string; key: string }[]): void {
    for (const entry of slice) {
      if (!this._keys.find((k) => k.id === entry.id)) this._keys.push(entry);
    }
  }
}

/**
 * Mirrors `PeerborneDocument._keychainChangesForVisibility` so the
 * visibility branching can be exercised in a pure unit test.
 *
 * If you change the visibility semantics in the production code, mirror the
 * change here so the test continues to reflect real behavior.
 */
function keychainChangesForVisibility(
  kc: InMemoryKeychain,
  visibility: Visibility,
  invitationEpoch: Uint8Array | undefined,
): { id: string; key: string }[] {
  switch (visibility) {
    case 'full_history':
      return kc.history();
    case 'since_invited':
      // When the local boundary is unknown (e.g. founding member),
      // default to `current_only` rather than full history. Mirrors the
      // production fallback in
      // `PeerborneDocument._keychainChangesForVisibility`; if you
      // change the production fallback, change it here too.
      if (invitationEpoch === undefined) return kc.currentKeyChange();
      return kc.historySince(invitationEpoch);
    case 'current_only':
    default:
      return kc.currentKeyChange();
  }
}

/**
 * Mirrors `PeerborneDocument._keychainChangesForWelcome`. Visibility is
 * evaluated from the **recipient's** perspective: under `since_invited`
 * the recipient's invitation epoch is the welcome's current key, so the
 * Welcome should carry only the current key.
 *
 * If you change the Welcome visibility semantics in the production code,
 * mirror the change here.
 */
function keychainChangesForWelcome(
  kc: InMemoryKeychain,
  visibility: Visibility,
): { id: string; key: string }[] {
  switch (visibility) {
    case 'full_history':
      return kc.history();
    case 'since_invited':
    case 'current_only':
    default:
      return kc.currentKeyChange();
  }
}

/**
 * Mirrors the receive-side state mutations from
 * `PeerborneDocument.handleBeeKEMWelcomeRequestData` AFTER the
 * ECIES seal has been opened:
 *  - drop if `welcomeEpochId` is missing
 *  - drop if `welcomeRecipient` is missing or does not match the local
 *    serialized public key
 *  - merge keychain changes (decrypted from `eciesSealed`) from the welcome
 *  - record `welcomeEpochId` as `_invitationEpoch`
 *
 * For convenience, this in-memory mirror reads the plaintext keychain
 * delta directly from `keychainChanges` on the test message rather
 * than running the full ECIES seal/open round-trip. Direct
 * unit coverage of the ECIES primitive lives in `ecies.test.ts`; the
 * wire-level "non-recipient cannot read the seal" property is covered
 * in `beekem-welcome-encryption.test.ts`.
 *
 * The signature, readers-ACL, and seal-presence checks are not modeled
 * in this helper; direct unit-test coverage of those security-critical
 * gates lives in `beekem-welcome-handler.test.ts`, which drives the
 * extracted `evaluateBeeKEMWelcome` function with mock providers. Full
 * end-to-end coverage that stands up a real `PeerborneDocument` over
 * libp2p/Helia lives in `e2e/integration/`.
 *
 * The helper requires `welcomeRecipient` on every message to mirror
 * production behavior, which unconditionally drops Welcomes missing the
 * recipient binding. Tests that exercise the "missing recipient binding"
 * case set `localSerializedKey` to a non-undefined value.
 */
function applyWelcomeStateChanges(
  state: {
    invitationEpoch: Uint8Array | undefined;
    keychain: InMemoryKeychain;
    /** Serialized form of the local user's public key. */
    localSerializedKey: string;
  },
  message: CRDTSyncMessage<{ id: string; key: string }[], unknown>,
): void {
  if (!message.welcomeEpochId) return;
  // Match production: Welcomes without a recipient binding are dropped
  // unconditionally.
  if (!message.welcomeRecipient) return;
  if (message.welcomeRecipient !== state.localSerializedKey) return;
  // In the in-memory mirror, `keychainChanges` stands in for the
  // ECIES-opened plaintext that production code recovers from
  // `eciesSealed`. The mirror does not run ECIES; the seal/open
  // round-trip is covered separately in `ecies.test.ts`.
  if (message.keychainChanges) state.keychain.merge(message.keychainChanges);
  // Monotonic-forward update: never regress the invitation-epoch
  // anchor (mirrors `PeerborneDocument._shouldAdvanceInvitationEpoch`).
  // See the doc-comment on the production method for the threat model
  // (an out-of-order or hostile Welcome carrying an earlier
  // `welcomeEpochId` would otherwise shrink the recipient's join
  // boundary and leak more history via `since_invited`).
  state.invitationEpoch = chooseInvitationEpoch(
    state.invitationEpoch,
    message.welcomeEpochId,
    state.keychain,
  );
}

/**
 * Pure mirror of `PeerborneDocument._shouldAdvanceInvitationEpoch`
 * for unit-test exercise without a libp2p/Helia stack. Returns the
 * epoch the local node should record as its anchor:
 *   - the incoming one iff strictly later than the existing one in
 *     keychain insertion order,
 *   - the existing one in every other case (equal bytes, earlier
 *     incoming, either ID missing from the keychain).
 */
function chooseInvitationEpoch(
  existing: Uint8Array | undefined,
  incoming: Uint8Array,
  keychain: InMemoryKeychain,
): Uint8Array {
  if (existing === undefined) return incoming;
  // Byte-equal: no-op.
  const sameBytes =
    existing.length === incoming.length &&
    existing.every((b, i) => b === incoming[i]);
  if (sameBytes) return existing;
  const order = keychain.history();
  const existingHex = InMemoryKeychain.toHex(existing);
  const incomingHex = InMemoryKeychain.toHex(incoming);
  const existingIdx = order.findIndex((k) => k.id === existingHex);
  const incomingIdx = order.findIndex((k) => k.id === incomingHex);
  if (existingIdx === -1 || incomingIdx === -1) return existing;
  return incomingIdx > existingIdx ? incoming : existing;
}

describe('BeeKEM Welcome receive flow (Issue #178)', () => {
  test('handler records welcomeEpochId as _invitationEpoch', () => {
    const senderKc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    const id2 = new Uint8Array(32).fill(2);
    senderKc.add(id1, 'k1');
    senderKc.add(id2, 'k2');

    const welcomeMessage: CRDTSyncMessage<{ id: string; key: string }[], unknown> = {
      documentId: '/doc/welcome',
      welcomeEpochId: id2,
      welcomeRecipient: 'my-pubkey',
      keychainChanges: keychainChangesForVisibility(senderKc, 'current_only', undefined),
    };

    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    applyWelcomeStateChanges(receiver, welcomeMessage);

    // _invitationEpoch is set on the receiver from the Welcome's epoch ID.
    expect(receiver.invitationEpoch).toBeDefined();
    expect(Array.from(receiver.invitationEpoch!)).toEqual(Array.from(id2));
    // The keychain delta from the Welcome is merged so the new reader can
    // decrypt the current state.
    expect(receiver.keychain.history()).toHaveLength(1);
    expect(receiver.keychain.history()[0].id).toBe(InMemoryKeychain.toHex(id2));
  });

  test('handler drops Welcomes addressed to a different recipient', () => {
    const senderKc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    senderKc.add(id1, 'k1');

    const welcomeMessage: CRDTSyncMessage<{ id: string; key: string }[], unknown> = {
      documentId: '/doc/welcome',
      welcomeEpochId: id1,
      welcomeRecipient: 'someone-elses-pubkey',
      keychainChanges: senderKc.history(),
    };

    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    applyWelcomeStateChanges(receiver, welcomeMessage);

    // Welcome was for someone else -- our state is untouched.
    expect(receiver.invitationEpoch).toBeUndefined();
    expect(receiver.keychain.history()).toHaveLength(0);
  });

  test('handler drops Welcomes with no welcomeRecipient when binding is required', () => {
    const senderKc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    senderKc.add(id1, 'k1');

    const malformed: CRDTSyncMessage<{ id: string; key: string }[], unknown> = {
      documentId: '/doc/welcome',
      welcomeEpochId: id1,
      // welcomeRecipient omitted
      keychainChanges: senderKc.history(),
    };

    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    applyWelcomeStateChanges(receiver, malformed);

    expect(receiver.invitationEpoch).toBeUndefined();
    expect(receiver.keychain.history()).toHaveLength(0);
  });

  test('handler accepts Welcomes whose welcomeRecipient matches the local key', () => {
    const senderKc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    senderKc.add(id1, 'k1');

    const welcomeMessage: CRDTSyncMessage<{ id: string; key: string }[], unknown> = {
      documentId: '/doc/welcome',
      welcomeEpochId: id1,
      welcomeRecipient: 'my-pubkey',
      keychainChanges: senderKc.history(),
    };

    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    applyWelcomeStateChanges(receiver, welcomeMessage);

    expect(Array.from(receiver.invitationEpoch!)).toEqual(Array.from(id1));
    expect(receiver.keychain.history()).toHaveLength(1);
  });

  test('handler does NOT regress _invitationEpoch when a later Welcome carries an earlier epoch ID', () => {
    // Threat model: a later writer-signed
    // Welcome addressed to this node might carry an *earlier*
    // `welcomeEpochId` than the one already recorded -- either
    // through network reordering or as a deliberate attempt to shrink
    // the recipient's join boundary. Unconditionally overwriting
    // `_invitationEpoch` would regress the anchor and cause this
    // node's future `since_invited` history responses to leak keys
    // from before the original invitation. The production handler
    // therefore applies a monotonic-forward update.
    const senderKc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    const id2 = new Uint8Array(32).fill(2);
    const id3 = new Uint8Array(32).fill(3);
    senderKc.add(id1, 'k1');
    senderKc.add(id2, 'k2');
    senderKc.add(id3, 'k3');

    // Receiver: ships with the full keychain merged in (e.g. via a
    // prior doc-load) so the monotonic comparison can locate both
    // IDs in keychain insertion order.
    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    receiver.keychain.merge(senderKc.history());

    // First Welcome lands at id2 -- recipient records invitation epoch = id2.
    applyWelcomeStateChanges(receiver, {
      documentId: '/doc/welcome',
      welcomeEpochId: id2,
      welcomeRecipient: 'my-pubkey',
      keychainChanges: [],
    });
    expect(Array.from(receiver.invitationEpoch!)).toEqual(Array.from(id2));

    // Second (stale / hostile) Welcome arrives addressed to us but
    // claims an earlier epoch ID. The anchor must NOT regress.
    applyWelcomeStateChanges(receiver, {
      documentId: '/doc/welcome',
      welcomeEpochId: id1,
      welcomeRecipient: 'my-pubkey',
      keychainChanges: [],
    });
    expect(Array.from(receiver.invitationEpoch!)).toEqual(Array.from(id2));

    // A *later* Welcome (id3) should advance the anchor forward.
    applyWelcomeStateChanges(receiver, {
      documentId: '/doc/welcome',
      welcomeEpochId: id3,
      welcomeRecipient: 'my-pubkey',
      keychainChanges: [],
    });
    expect(Array.from(receiver.invitationEpoch!)).toEqual(Array.from(id3));
  });

  test('chooseInvitationEpoch: equal IDs leave the anchor unchanged', () => {
    const kc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    kc.add(id1, 'k1');
    const chosen = chooseInvitationEpoch(id1, new Uint8Array(id1), kc);
    expect(Array.from(chosen)).toEqual(Array.from(id1));
  });

  test('chooseInvitationEpoch: unknown incoming ID keeps existing anchor', () => {
    // Conservative fallback: if the new epoch ID is not present in
    // the keychain (perhaps the keychain delta was dropped or arrived
    // separately), we cannot establish ordering, so we keep the
    // known-good existing anchor rather than risk a regression.
    const kc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    kc.add(id1, 'k1');
    const unknown = new Uint8Array(32).fill(0xff);
    const chosen = chooseInvitationEpoch(id1, unknown, kc);
    expect(Array.from(chosen)).toEqual(Array.from(id1));
  });

  test('handler drops Welcomes without a welcomeEpochId', () => {
    const malformedWelcome: CRDTSyncMessage<{ id: string; key: string }[], unknown> = {
      documentId: '/doc/welcome',
      welcomeRecipient: 'my-pubkey',
      // welcomeEpochId intentionally omitted -- mirrors the
      // handler's "drop if missing" guard.
    };
    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    applyWelcomeStateChanges(receiver, malformedWelcome);
    expect(receiver.invitationEpoch).toBeUndefined();
    expect(receiver.keychain.history()).toHaveLength(0);
  });
});

describe('Epoch-based keychain visibility filtering (Issue #179)', () => {
  test('since_invited returns only the keys at or after _invitationEpoch', () => {
    const kc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    const id2 = new Uint8Array(32).fill(2);
    const id3 = new Uint8Array(32).fill(3);
    kc.add(id1, 'k1');
    kc.add(id2, 'k2');
    kc.add(id3, 'k3');

    const slice = keychainChangesForVisibility(kc, 'since_invited', id2);
    expect(slice.map((k) => k.id)).toEqual([
      InMemoryKeychain.toHex(id2),
      InMemoryKeychain.toHex(id3),
    ]);
  });

  test('since_invited with no _invitationEpoch falls back to current_only (founding member)', () => {
    const kc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    const id2 = new Uint8Array(32).fill(2);
    kc.add(id1, 'k1');
    kc.add(id2, 'k2');

    // No recorded invitation epoch (e.g. founding member) defaults to
    // current_only, not full history. Returning the full keychain in
    // this case would silently leak every prior epoch to a peer the
    // founder responds to. Documents that truly need full-history
    // sharing should configure `historyVisibility: 'full_history'`
    // explicitly.
    const slice = keychainChangesForVisibility(kc, 'since_invited', undefined);
    expect(slice).toHaveLength(1);
    expect(slice[0].id).toBe(InMemoryKeychain.toHex(id2));
  });

  test('since_invited with an unknown epoch falls back to full history', () => {
    const kc = new InMemoryKeychain();
    const id1 = new Uint8Array(32).fill(1);
    const id2 = new Uint8Array(32).fill(2);
    kc.add(id1, 'k1');
    kc.add(id2, 'k2');

    const unknown = new Uint8Array(32).fill(0xff);
    const slice = keychainChangesForVisibility(kc, 'since_invited', unknown);
    // Boundary key not found -- the underlying historySince() falls
    // back to full history rather than returning an empty slice (which
    // would wedge the recipient). Note this is `historySince`'s
    // recovery path for malformed input, not the
    // founder/unset-invitationEpoch path covered above.
    expect(slice).toHaveLength(2);
  });

  test('full_history returns every key', () => {
    const kc = new InMemoryKeychain();
    kc.add(new Uint8Array(32).fill(1), 'k1');
    kc.add(new Uint8Array(32).fill(2), 'k2');
    kc.add(new Uint8Array(32).fill(3), 'k3');
    const slice = keychainChangesForVisibility(kc, 'full_history', undefined);
    expect(slice).toHaveLength(3);
  });

  test('current_only returns only the most recent key', () => {
    const kc = new InMemoryKeychain();
    kc.add(new Uint8Array(32).fill(1), 'k1');
    kc.add(new Uint8Array(32).fill(2), 'k2');
    const slice = keychainChangesForVisibility(kc, 'current_only', undefined);
    expect(slice).toHaveLength(1);
    expect(slice[0].key).toBe('k2');
  });
});

describe('Welcome-side keychain filtering (recipient perspective)', () => {
  // Regression: under `since_invited`, the inviter's own
  // `_invitationEpoch` was being used to filter the keychain in the
  // Welcome, which leaks the inviter's post-invite slice to a newly-
  // added reader whose invitation epoch is the *current* key. The
  // recipient-perspective filter should send only the current key.
  test('since_invited sends only the current key (not the inviter slice)', () => {
    const kc = new InMemoryKeychain();
    const epochs = [1, 2, 3, 4].map((i) => new Uint8Array(32).fill(i));
    for (let i = 0; i < epochs.length; i++) {
      kc.add(epochs[i], `k${i + 1}`);
    }

    const slice = keychainChangesForWelcome(kc, 'since_invited');
    expect(slice).toHaveLength(1);
    expect(slice[0].key).toBe('k4');
  });

  test('current_only sends only the current key', () => {
    const kc = new InMemoryKeychain();
    kc.add(new Uint8Array(32).fill(1), 'k1');
    kc.add(new Uint8Array(32).fill(2), 'k2');
    const slice = keychainChangesForWelcome(kc, 'current_only');
    expect(slice).toHaveLength(1);
    expect(slice[0].key).toBe('k2');
  });

  test('full_history sends the full keychain', () => {
    const kc = new InMemoryKeychain();
    kc.add(new Uint8Array(32).fill(1), 'k1');
    kc.add(new Uint8Array(32).fill(2), 'k2');
    kc.add(new Uint8Array(32).fill(3), 'k3');
    const slice = keychainChangesForWelcome(kc, 'full_history');
    expect(slice).toHaveLength(3);
  });
});

describe('End-to-end Welcome -> since_invited filtering (Issues #178 + #179)', () => {
  test('after Welcome is applied, since_invited returns only keys from invitation onward', () => {
    // Sender's keychain has 4 keys.
    const senderKc = new InMemoryKeychain();
    const epochs = [1, 2, 3, 4].map((i) => new Uint8Array(32).fill(i));
    for (let i = 0; i < epochs.length; i++) {
      senderKc.add(epochs[i], `k${i + 1}`);
    }

    // Sender invites a new reader at epoch index 2 (i.e. id `3`).
    const invitationEpoch = epochs[2];
    const welcome: CRDTSyncMessage<{ id: string; key: string }[], unknown> = {
      documentId: '/doc/welcome',
      welcomeEpochId: invitationEpoch,
      welcomeRecipient: 'my-pubkey',
      // For Welcome we send what the new reader needs to decrypt going forward
      // under `current_only` semantics: the current key + future ones via
      // subsequent updates. For an end-to-end since_invited test we use
      // `full_history` so the new reader has both id3 and id4 to feed into
      // its later filtering operation.
      keychainChanges: keychainChangesForVisibility(senderKc, 'full_history', undefined),
    };

    const receiver = {
      invitationEpoch: undefined as Uint8Array | undefined,
      keychain: new InMemoryKeychain(),
      localSerializedKey: 'my-pubkey',
    };
    applyWelcomeStateChanges(receiver, welcome);

    // Receiver now has the full keychain merged in (4 entries).
    expect(receiver.keychain.history()).toHaveLength(4);
    // ...and has _invitationEpoch set to the boundary at id3.
    expect(Array.from(receiver.invitationEpoch!)).toEqual(Array.from(invitationEpoch));

    // When this receiver later sends a doc-load response under
    // `since_invited`, the recipient should observe id3 and id4 only.
    const reLoadSlice = keychainChangesForVisibility(
      receiver.keychain,
      'since_invited',
      receiver.invitationEpoch,
    );
    expect(reLoadSlice.map((k) => k.id)).toEqual([
      InMemoryKeychain.toHex(epochs[2]),
      InMemoryKeychain.toHex(epochs[3]),
    ]);
  });
});
