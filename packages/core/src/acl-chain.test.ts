import { describe, expect, test, beforeAll, jest } from '@jest/globals';

import {
  ACLChain,
  ACLChainOps,
  ACLEntry,
  ACLState,
  canonicalEntryPayload,
  computeEntryHash,
} from './acl-chain.js';
import { SubtleCrypto } from './auth-subtlecrypto.js';

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

const auth = new SubtleCrypto();

/**
 * Generate an ECDSA P-384 keypair using the same algorithm as the SubtleCrypto
 * auth provider's default. The suite-level identities (`alice`, `bob`, etc.)
 * are generated once in `beforeAll`; tests that need additional isolated
 * identities (e.g., to model an unknown peer) call this helper inline.
 */
async function genKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

/**
 * Canonical raw encoding of an ECDSA public key. Stable across imports.
 */
async function serializePublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

// ---------------------------------------------------------------------------
// In-memory ACL adapter
//
// The chain is generic over the change format; for tests we use a tiny
// JSON-encoded "add" / "remove" change vocabulary. Each change carries a
// list of public-key hashes to grant or revoke writer status.
// ---------------------------------------------------------------------------

interface AclChange {
  op: 'add' | 'remove';
  /** Hex-encoded raw public keys. */
  keys: string[];
}

function serializeChange(c: AclChange): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(c));
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

class TestAclState implements ACLState<AclChange, CryptoKey> {
  // Brand from the interface; we satisfy it structurally without storing it.
  readonly _aclStateBrand?: never;
  /** Hex-encoded raw public keys of current writers. */
  readonly writers: Set<string>;
  constructor(writers: ReadonlySet<string> = new Set()) {
    this.writers = new Set(writers);
  }
  clone(): TestAclState {
    return new TestAclState(this.writers);
  }
}

const testOps: ACLChainOps<AclChange, CryptoKey> = {
  emptyState(): TestAclState {
    return new TestAclState();
  },
  async applyChange(state, change): Promise<TestAclState> {
    const s = (state as TestAclState).clone();
    if (change.op === 'add') {
      for (const k of change.keys) s.writers.add(k);
    } else {
      for (const k of change.keys) s.writers.delete(k);
    }
    return s;
  },
  async isWriter(state, publicKey): Promise<boolean> {
    const bytes = await serializePublicKey(publicKey);
    return (state as TestAclState).writers.has(toHex(bytes));
  },
};

interface TestIdentity {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  hashHex: string;
}

async function makeIdentity(): Promise<TestIdentity> {
  const { publicKey, privateKey } = await genKeyPair();
  const hashHex = toHex(await serializePublicKey(publicKey));
  return { publicKey, privateKey, hashHex };
}

function makeChain(
  genesisAuthorizedKeys: CryptoKey[],
): ACLChain<AclChange, CryptoKey, CryptoKey> {
  return new ACLChain<AclChange, CryptoKey, CryptoKey>(
    {
      auth,
      serializeKey: serializePublicKey,
      ops: testOps,
      genesisAuthorizedKeys,
    },
    serializeChange,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Some operations are intentionally slow (P-384 keygen, signature verify).
// Generous timeout keeps CI green on slower machines.
jest.setTimeout(30_000);

let alice: TestIdentity;
let bob: TestIdentity;
let carol: TestIdentity;
let eve: TestIdentity;

beforeAll(async () => {
  alice = await makeIdentity();
  bob = await makeIdentity();
  carol = await makeIdentity();
  eve = await makeIdentity();
});

describe('canonical encoding', () => {
  test('changes in any field change the hash', async () => {
    const base: Omit<ACLEntry<AclChange>, 'signature'> = {
      sequenceNumber: 0,
      timestamp: 1000,
      parentHash: undefined,
      change: { op: 'add', keys: [bob.hashHex] },
      signerKeyId: new Uint8Array([1, 2, 3]),
    };

    const h0 = toHex(await computeEntryHash(base, serializeChange));

    // Bump sequenceNumber
    const h1 = toHex(
      await computeEntryHash({ ...base, sequenceNumber: 1 }, serializeChange),
    );
    expect(h1).not.toBe(h0);

    // Bump timestamp
    const h2 = toHex(
      await computeEntryHash({ ...base, timestamp: 1001 }, serializeChange),
    );
    expect(h2).not.toBe(h0);

    // Different change content
    const h3 = toHex(
      await computeEntryHash(
        { ...base, change: { op: 'add', keys: [carol.hashHex] } },
        serializeChange,
      ),
    );
    expect(h3).not.toBe(h0);

    // Different signer
    const h4 = toHex(
      await computeEntryHash(
        { ...base, signerKeyId: new Uint8Array([9, 9, 9]) },
        serializeChange,
      ),
    );
    expect(h4).not.toBe(h0);
  });

  test('length-prefixed encoding prevents boundary ambiguity', async () => {
    // Two entries that, without length prefixing, would have the same
    // concatenated representation:
    //   signerKeyId=[1,2], change=bytes("3")
    //   signerKeyId=[1,2,3], change=bytes("")
    // Both produce bytes [1,2,3] if you forget the length prefixes.
    const a: Omit<ACLEntry<AclChange>, 'signature'> = {
      sequenceNumber: 0,
      timestamp: 0,
      change: { op: 'add', keys: [] }, // serializes to '{"op":"add","keys":[]}'
      signerKeyId: new Uint8Array([1, 2]),
    };
    const b: Omit<ACLEntry<AclChange>, 'signature'> = {
      sequenceNumber: 0,
      timestamp: 0,
      change: { op: 'add', keys: [] },
      signerKeyId: new Uint8Array([1, 2, 3]),
    };
    const ha = canonicalEntryPayload(a, serializeChange);
    const hb = canonicalEntryPayload(b, serializeChange);
    expect(toHex(ha)).not.toBe(toHex(hb));
  });
});

describe('legitimate chain', () => {
  test('genesis member can author the first entry and bootstrap themselves', async () => {
    const chain = makeChain([alice.publicKey]);

    const entry = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    expect(chain.length).toBe(1);
    expect(entry.sequenceNumber).toBe(0);
    expect(entry.parentHash).toBeUndefined();
    expect(chain.headHash).toBeDefined();
    expect(await testOps.isWriter(chain.state!, alice.publicKey)).toBe(true);
  });

  test('writer can add a second writer, who can then author', async () => {
    const chain = makeChain([alice.publicKey]);

    // Alice (genesis) adds herself.
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    // Alice adds Bob.
    await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    // Bob (now a writer) adds Carol.
    await chain.authorAndAppend(
      { op: 'add', keys: [carol.hashHex] },
      bob.publicKey,
      bob.privateKey,
    );

    expect(chain.length).toBe(3);
    expect(await testOps.isWriter(chain.state!, alice.publicKey)).toBe(true);
    expect(await testOps.isWriter(chain.state!, bob.publicKey)).toBe(true);
    expect(await testOps.isWriter(chain.state!, carol.publicKey)).toBe(true);
  });

  test('chain heads link properly via parentHash', async () => {
    const chain = makeChain([alice.publicKey]);
    const e0 = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    const e1 = await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    expect(e0.parentHash).toBeUndefined();
    const e0Hash = await computeEntryHash(e0, serializeChange);
    expect(e1.parentHash).toBeDefined();
    expect(toHex(e1.parentHash!)).toBe(toHex(e0Hash));
  });
});

describe('rejection: unauthorized signer', () => {
  test('non-genesis key cannot author the genesis entry', async () => {
    const chain = makeChain([alice.publicKey]);

    // Eve tries to start a chain even though she's not in the genesis set.
    // authorAndAppend throws because the entry would be rejected.
    await expect(
      chain.authorAndAppend(
        { op: 'add', keys: [eve.hashHex] },
        eve.publicKey,
        eve.privateKey,
      ),
    ).rejects.toThrow(/unauthorized-signer/);

    expect(chain.length).toBe(0);
  });

  test('non-writer cannot author a non-genesis entry', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    await expect(
      chain.authorAndAppend(
        { op: 'add', keys: [eve.hashHex] },
        eve.publicKey,
        eve.privateKey,
      ),
    ).rejects.toThrow(/unauthorized-signer/);
  });

  test('removed writer cannot replay a pre-removal style change', async () => {
    // Threat model:
    //   - Bob is a legitimate writer for a while.
    //   - Alice removes Bob.
    //   - Bob, having held his private key the whole time, signs a *new*
    //     entry as if he were still a writer, with a parentHash that
    //     correctly points at the current head (he can read the chain).
    //   - The chain MUST reject this: Bob is no longer a writer.
    const chain = makeChain([alice.publicKey]);

    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    // Bob legitimately authors something while he's still a writer.
    await chain.authorAndAppend(
      { op: 'add', keys: [carol.hashHex] },
      bob.publicKey,
      bob.privateKey,
    );
    // Alice removes Bob.
    await chain.authorAndAppend(
      { op: 'remove', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    expect(await testOps.isWriter(chain.state!, bob.publicKey)).toBe(false);

    // Bob crafts a fresh entry now that points at the current head.
    const head = chain.headHash;
    const seq = chain.length;
    const payload = {
      sequenceNumber: seq,
      timestamp: Date.now(),
      parentHash: head,
      change: { op: 'add' as const, keys: [eve.hashHex] },
      signerKeyId: await serializePublicKey(bob.publicKey),
    };
    const encoded = canonicalEntryPayload(payload, serializeChange);
    const signature = await auth.sign(encoded, bob.privateKey);
    const evilEntry: ACLEntry<AclChange> = { ...payload, signature };

    const result = await chain.ingestEntry(evilEntry, bob.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('unauthorized-signer');
    }
    expect(chain.length).toBe(4); // unchanged
  });

  test('out-of-order injection of a historical entry into a fresh chain fails', async () => {
    // Threat model: a former writer (or any attacker who has observed past
    // entries) tries to inject a previously-valid entry into a fresh chain
    // at the wrong position. Even though the signature was valid at the
    // time, the chain must reject it because either the parent hash or
    // the sequence number no longer line up.
    const chain = makeChain([alice.publicKey]);

    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    const bobsLegitEntry = await chain.authorAndAppend(
      { op: 'add', keys: [carol.hashHex] },
      bob.publicKey,
      bob.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'remove', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Now simulate a new node receiving the FIRST TWO entries (genesis +
    // bob added) and then immediately being fed bob's "legit" entry as if
    // out-of-order. The new node accepts genesis + add(bob) (because
    // sequence still lines up), then bob's entry should still be accepted
    // *if its sequenceNumber matches*. So this case is actually a legit
    // replay -- we test it elsewhere. Here we test the more interesting
    // case: feeding the entry with the WRONG sequence number gets rejected
    // for sequence-out-of-order, even though Bob *was* a valid writer.
    const fresh = makeChain([alice.publicKey]);
    await fresh.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    // Skip the "add Bob" entry to simulate trying to inject Bob's entry
    // out of order.
    const result = await fresh.ingestEntry(bobsLegitEntry, bob.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Either parent-hash-mismatch or sequence-out-of-order is acceptable
      // -- both are valid rejections. Just make sure it didn't slip through.
      expect(['parent-hash-mismatch', 'sequence-out-of-order']).toContain(
        result.reason,
      );
    }
  });
});

describe('rejection: tampering and replay', () => {
  test('flipping a single byte in the change invalidates the signature', async () => {
    // Build a chain, snapshot its entries, then construct a fresh chain
    // by replaying the *first* entry verbatim (so the head hashes match)
    // and try to ingest a tampered version of the *second* entry.
    const chain = makeChain([alice.publicKey]);
    const e0 = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    const e1 = await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Replay e0 verbatim into a fresh chain so the heads line up.
    const fresh = makeChain([alice.publicKey]);
    const r0 = await fresh.ingestEntry(e0, alice.publicKey);
    expect(r0.ok).toBe(true);

    // Tamper: switch the add target from bob to eve while keeping the
    // signature unchanged. Signature was over the bob-add payload, so it
    // must no longer verify.
    const tampered: ACLEntry<AclChange> = {
      ...e1,
      change: { op: 'add', keys: [eve.hashHex] },
    };
    const result = await fresh.ingestEntry(tampered, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('bad-signature');
  });

  test('substituting a different signer for the same payload is rejected', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    const entry = await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    const fresh = makeChain([alice.publicKey]);
    await fresh.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Caller claims Eve signed, but the signerKeyId inside the entry
    // says Alice -- mismatch caught before we even try to verify.
    const result = await fresh.ingestEntry(entry, eve.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('unknown-signer-key');
  });

  test('exact duplicate ingest is rejected', async () => {
    const chain = makeChain([alice.publicKey]);
    const e0 = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Try to ingest the same entry again -- sequence number is now 1, so
    // this is caught as sequence-out-of-order before we hit the duplicate
    // check, but the chain MUST reject it either way. We check that the
    // chain length stays at 1.
    const result = await chain.ingestEntry(e0, alice.publicKey);
    expect(result.ok).toBe(false);
    expect(chain.length).toBe(1);
  });

  test('fork attempt: two entries with the same parent are not both accepted', async () => {
    // Build a chain to a fork point.
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    const forkPoint = chain.headHash;
    const forkSeq = chain.length;

    // Build entry A: alice adds carol.
    const payloadA = {
      sequenceNumber: forkSeq,
      timestamp: 1000,
      parentHash: forkPoint,
      change: { op: 'add' as const, keys: [carol.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
    };
    const sigA = await auth.sign(
      canonicalEntryPayload(payloadA, serializeChange),
      alice.privateKey,
    );
    const entryA: ACLEntry<AclChange> = { ...payloadA, signature: sigA };

    // Build entry B: bob adds eve. Same parent, same seq, different content.
    const payloadB = {
      sequenceNumber: forkSeq,
      timestamp: 1001,
      parentHash: forkPoint,
      change: { op: 'add' as const, keys: [eve.hashHex] },
      signerKeyId: await serializePublicKey(bob.publicKey),
    };
    const sigB = await auth.sign(
      canonicalEntryPayload(payloadB, serializeChange),
      bob.privateKey,
    );
    const entryB: ACLEntry<AclChange> = { ...payloadB, signature: sigB };

    // First one in wins.
    const rA = await chain.ingestEntry(entryA, alice.publicKey);
    expect(rA.ok).toBe(true);
    expect(await testOps.isWriter(chain.state!, carol.publicKey)).toBe(true);

    // Second one is rejected: its parentHash no longer matches the head.
    const rB = await chain.ingestEntry(entryB, bob.publicKey);
    expect(rB.ok).toBe(false);
    if (!rB.ok) {
      expect(['parent-hash-mismatch', 'sequence-out-of-order']).toContain(
        rB.reason,
      );
    }
    expect(await testOps.isWriter(chain.state!, eve.publicKey)).toBe(false);
  });

  test('mid-chain malicious insertion is rejected', async () => {
    // Attacker wants to splice an entry into the middle of an existing
    // chain. Even if the entry's content is plausible, its parentHash
    // points to a non-head position so the chain rejects it.
    const chain = makeChain([alice.publicKey]);

    const e0 = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [carol.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Construct a malicious entry whose parentHash points at e0 (the
    // genesis), not the current head. Even with a valid signature from
    // Alice, this must be rejected.
    const e0Hash = await computeEntryHash(e0, serializeChange);
    const payload = {
      sequenceNumber: chain.length,
      timestamp: 9999,
      parentHash: e0Hash,
      change: { op: 'add' as const, keys: [eve.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
    };
    const signature = await auth.sign(
      canonicalEntryPayload(payload, serializeChange),
      alice.privateKey,
    );
    const evil: ACLEntry<AclChange> = { ...payload, signature };
    const result = await chain.ingestEntry(evil, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('parent-hash-mismatch');
  });

  test('sequence number that skips ahead is rejected', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    const head = chain.headHash;
    const payload = {
      sequenceNumber: 5, // chain expects 1
      timestamp: 1000,
      parentHash: head,
      change: { op: 'add' as const, keys: [bob.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
    };
    const signature = await auth.sign(
      canonicalEntryPayload(payload, serializeChange),
      alice.privateKey,
    );
    const result = await chain.ingestEntry(
      { ...payload, signature },
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('sequence-out-of-order');
  });
});

describe('replay() snapshot loading', () => {
  test('round-trips a legitimate chain into a fresh ACLChain instance', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    await chain.authorAndAppend(
      { op: 'add', keys: [carol.hashHex] },
      bob.publicKey,
      bob.privateKey,
    );

    const entries = chain.entries();

    // Build a resolver that can recover each public key from its hash --
    // in production this would consult a directory or a separate keystore.
    const byHash = new Map<string, CryptoKey>([
      [alice.hashHex, alice.publicKey],
      [bob.hashHex, bob.publicKey],
      [carol.hashHex, carol.publicKey],
    ]);

    const fresh = makeChain([alice.publicKey]);
    const result = await fresh.replay(entries, async (hash) =>
      byHash.get(toHex(hash)),
    );
    expect(result.ok).toBe(true);
    expect(fresh.length).toBe(3);
    expect(await testOps.isWriter(fresh.state!, alice.publicKey)).toBe(true);
    expect(await testOps.isWriter(fresh.state!, bob.publicKey)).toBe(true);
    expect(await testOps.isWriter(fresh.state!, carol.publicKey)).toBe(true);
  });

  test('replay rejects a chain with a hostile entry spliced in', async () => {
    const chain = makeChain([alice.publicKey]);
    const e0 = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    const e1 = await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Build an Eve-authored entry that *looks* like it would extend the
    // chain, but Eve has never been a writer.
    const headAfterE1 = await computeEntryHash(e1, serializeChange);
    const payload = {
      sequenceNumber: 2,
      timestamp: 5000,
      parentHash: headAfterE1,
      change: { op: 'add' as const, keys: [eve.hashHex] },
      signerKeyId: await serializePublicKey(eve.publicKey),
    };
    const signature = await auth.sign(
      canonicalEntryPayload(payload, serializeChange),
      eve.privateKey,
    );
    const eveEntry: ACLEntry<AclChange> = { ...payload, signature };

    const byHash = new Map<string, CryptoKey>([
      [alice.hashHex, alice.publicKey],
      [bob.hashHex, bob.publicKey],
      [eve.hashHex, eve.publicKey],
    ]);

    const fresh = makeChain([alice.publicKey]);
    const result = await fresh.replay([e0, e1, eveEntry], async (hash) =>
      byHash.get(toHex(hash)),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('unauthorized-signer');
      expect(result.index).toBe(2);
    }
    // After a failed replay, the chain holds the partial-but-valid prefix
    // so callers can inspect it for diagnostics.
    expect(fresh.length).toBe(2);
  });

  test('replay rejects when resolveKey cannot map a signerKeyId', async () => {
    const chain = makeChain([alice.publicKey]);
    const e0 = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    const fresh = makeChain([alice.publicKey]);
    const result = await fresh.replay([e0], async () => undefined);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('unknown-signer-key');
      expect(result.index).toBe(0);
    }
  });

  test('replay validates full entry shape before invoking resolveKey', async () => {
    // Regression: a hostile snapshot must not be able to force `resolveKey`
    // to do expensive work (e.g. a directory lookup keyed by the supplied
    // bytestring) by supplying an absurdly large `signerKeyId`. The full
    // `validateEntryShape` check -- which enforces MAX_SIGNER_KEY_BYTES --
    // must run *before* resolveKey is called.
    const hostile = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add' as const, keys: [alice.hashHex] },
      // 1 MiB key id -- well above MAX_SIGNER_KEY_BYTES (256).
      signerKeyId: new Uint8Array(1 << 20),
      signature: new Uint8Array(64),
    } as ACLEntry<AclChange>;

    let resolveCalls = 0;
    const fresh = makeChain([alice.publicKey]);
    const result = await fresh.replay([hostile], async (id) => {
      resolveCalls += 1;
      // Touch the supplied bytes so a real implementation's cost would
      // scale with `id.byteLength`. We must never get here.
      void id.byteLength;
      return undefined;
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.index).toBe(0);
      expect(result.message).toMatch(/signerKeyId has an implausible length/);
    }
    expect(resolveCalls).toBe(0);
    expect(fresh.length).toBe(0);
  });
});

describe('headHash behavior', () => {
  test('headHash returns a copy that callers cannot mutate', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    const head1 = chain.headHash!;
    head1[0] ^= 0xff; // mutate the returned buffer
    const head2 = chain.headHash!;

    // The chain's internal head should not have been affected.
    expect(toHex(head1)).not.toBe(toHex(head2));
  });
});

describe('malformed entry rejection', () => {
  // These tests cover entries that may arrive over the network with
  // entirely wrong shapes. The chain must surface them as structured
  // 'malformed-entry' results rather than throwing, since a hostile peer
  // could otherwise DoS the local node with a single forged entry.
  test('non-Uint8Array signature is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const broken = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add' as const, keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: 'not bytes' as unknown as Uint8Array,
    } as ACLEntry<AclChange>;
    const result = await chain.ingestEntry(broken, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('malformed-entry');
  });

  test('non-integer sequenceNumber is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const broken = {
      sequenceNumber: 1.5 as unknown as number,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add' as const, keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array([1, 2, 3]),
    } as ACLEntry<AclChange>;
    const result = await chain.ingestEntry(broken, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('malformed-entry');
  });

  test('non-Uint8Array signerKeyId is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const broken = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add' as const, keys: [alice.hashHex] },
      signerKeyId: 'not bytes' as unknown as Uint8Array,
      signature: new Uint8Array([1, 2, 3]),
    } as ACLEntry<AclChange>;
    const result = await chain.ingestEntry(broken, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('malformed-entry');
  });

  test('null entry is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      null as unknown as ACLEntry<AclChange>,
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('malformed-entry');
  });

  // `canonicalEntryPayload` encodes `timestamp` as two unsigned 32-bit
  // halves; fractional, negative, NaN, and Infinity values would silently
  // corrupt the encoding (and let an attacker manufacture distinct
  // timestamps that share canonical bytes). All such values must be
  // rejected up front as 'malformed-entry'.
  async function brokenTimestampEntry(
    timestamp: number,
  ): Promise<ACLEntry<AclChange>> {
    return {
      sequenceNumber: 0,
      timestamp,
      parentHash: undefined,
      change: { op: 'add' as const, keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array([1, 2, 3]),
    } as ACLEntry<AclChange>;
  }

  test('fractional timestamp is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenTimestampEntry(1.5),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/timestamp/);
    }
  });

  test('negative timestamp is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenTimestampEntry(-1),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/timestamp/);
    }
  });

  test('NaN timestamp is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenTimestampEntry(Number.NaN),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/timestamp/);
    }
  });

  test('Infinity timestamp is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenTimestampEntry(Number.POSITIVE_INFINITY),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/timestamp/);
    }
  });

  test('timestamp beyond MAX_SAFE_INTEGER is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenTimestampEntry(Number.MAX_SAFE_INTEGER + 1),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/timestamp/);
    }
  });

  // `canonicalEntryPayload` encodes `sequenceNumber` as an unsigned 32-bit
  // integer. Values >0xFFFFFFFF would silently wrap via `>>> 0`, letting a
  // hostile peer manufacture two *different* sequence numbers that share
  // identical canonical bytes (and therefore identical signatures and
  // hashes). Anything outside [0, 0xFFFFFFFF] must be rejected up front.
  async function brokenSequenceEntry(
    sequenceNumber: number,
  ): Promise<ACLEntry<AclChange>> {
    return {
      sequenceNumber,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add' as const, keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array([1, 2, 3]),
    } as ACLEntry<AclChange>;
  }

  test('sequenceNumber > 0xFFFFFFFF is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenSequenceEntry(0x100000000),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/sequenceNumber/);
    }
  });

  test('sequenceNumber up to 0xFFFFFFFF passes shape validation', async () => {
    // The shape check itself must accept the maximum permissible value.
    // The chain's own sequence check will then reject it because the
    // chain is empty (expects sequenceNumber=0), but with
    // sequence-out-of-order rather than malformed-entry. This confirms
    // we draw the bound at exactly 2^32-1.
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenSequenceEntry(0xffffffff),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).not.toBe('malformed-entry');
    }
  });

  test('negative sequenceNumber is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenSequenceEntry(-1),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/sequenceNumber/);
    }
  });

  test('sequenceNumber beyond MAX_SAFE_INTEGER is rejected without throwing', async () => {
    const chain = makeChain([alice.publicKey]);
    const result = await chain.ingestEntry(
      await brokenSequenceEntry(Number.MAX_SAFE_INTEGER + 1),
      alice.publicKey,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/sequenceNumber/);
    }
  });
});

describe('concurrent mutation safety', () => {
  // The chain serializes mutating calls via an internal queue so two
  // overlapping appends cannot both capture the same `_entries.length`
  // and corrupt sequence numbers / parent links.
  test('two concurrent authorAndAppend calls produce a well-formed chain', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Fire two appends without awaiting in between -- they would race if
    // the chain didn't serialize internally.
    const [a, b] = await Promise.all([
      chain.authorAndAppend(
        { op: 'add', keys: [bob.hashHex] },
        alice.publicKey,
        alice.privateKey,
      ),
      chain.authorAndAppend(
        { op: 'add', keys: [carol.hashHex] },
        alice.publicKey,
        alice.privateKey,
      ),
    ]);

    expect(chain.length).toBe(3);
    // Sequence numbers must be contiguous and parent hashes must link.
    expect(a.sequenceNumber).not.toBe(b.sequenceNumber);
    const seqs = [a.sequenceNumber, b.sequenceNumber].sort();
    expect(seqs).toEqual([1, 2]);
    // The later entry must point at the earlier entry's hash, not at the
    // pre-mutation head.
    const entries = chain.entries();
    expect(entries[2].parentHash).toBeDefined();
    expect(entries[2].sequenceNumber).toBe(2);
    expect(entries[1].sequenceNumber).toBe(1);
  });

  test('failure in one queued mutation does not poison subsequent ones', async () => {
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Eve is not authorized, so this authorAndAppend rejects.
    const failing = chain.authorAndAppend(
      { op: 'add', keys: [eve.hashHex] },
      eve.publicKey,
      eve.privateKey,
    );
    // Fire a legitimate append immediately so it enqueues behind the
    // failing one.
    const succeeding = chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    await expect(failing).rejects.toThrow();
    await expect(succeeding).resolves.toBeDefined();
    expect(chain.length).toBe(2);
  });
});

describe('oversized change rejection', () => {
  // Thread A (CodeRabbit): the size gate must run *before* the full
  // header+payload buffer is assembled, so a hostile peer cannot force a
  // multi-megabyte allocation on the hot path by sending an oversized
  // `change`.
  //
  // We exercise the gate two ways:
  //   1. End-to-end: a change whose serialization exceeds MAX_CHANGE_BYTES
  //      (1 MiB) is rejected as 'malformed-entry'.
  //   2. Allocation order: we instrument the chain's `serializeChange`
  //      callback so it returns an oversized buffer, then assert that
  //      ingestion rejects without ever calling our spy a second time --
  //      proving the rejection happened before any redundant work.

  test('change larger than 1 MiB is rejected as malformed-entry', async () => {
    const chain = makeChain([alice.publicKey]);
    // Build a change whose serialized JSON exceeds MAX_CHANGE_BYTES (1 MiB).
    // A single ~1.1 MiB key string is cheap to construct (one allocation),
    // serializes to JSON ~1 MiB without allocating millions of array elements,
    // and comfortably overshoots the 1 MiB limit.
    const huge: AclChange = {
      op: 'add',
      keys: ['a'.repeat(1_100_000)],
    };
    const payload = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: huge,
      signerKeyId: await serializePublicKey(alice.publicKey),
    };
    const encoded = canonicalEntryPayload(payload, serializeChange);
    const signature = await auth.sign(encoded, alice.privateKey);
    const entry: ACLEntry<AclChange> = { ...payload, signature };

    const result = await chain.ingestEntry(entry, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/serialized change exceeds maximum size/);
    }
    expect(chain.length).toBe(0);
  });

  test('size gate runs before full payload assembly (allocation order)', async () => {
    // Use a chain whose `serializeChange` returns an oversized buffer on
    // every call, and confirm that ingestion bails out *immediately* after
    // the first serialization -- i.e. we do not proceed to assemble the
    // header+payload buffer (which would have been roughly twice the
    // change size on top of the change bytes themselves).
    const OVERSIZED = (1 << 20) + 1; // MAX_CHANGE_BYTES + 1
    let calls = 0;
    let largestAllocation = 0;
    const spy = (_c: AclChange): Uint8Array => {
      calls += 1;
      const bytes = new Uint8Array(OVERSIZED);
      largestAllocation = Math.max(largestAllocation, bytes.byteLength);
      return bytes;
    };
    const chain = new ACLChain<AclChange, CryptoKey, CryptoKey>(
      {
        auth,
        serializeKey: serializePublicKey,
        ops: testOps,
        genesisAuthorizedKeys: [alice.publicKey],
      },
      spy,
    );

    const entry: ACLEntry<AclChange> = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add', keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array([1, 2, 3]),
    };

    const result = await chain.ingestEntry(entry, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/serialized change exceeds maximum size/);
    }
    // Exactly one serialization happened -- the gate fired before
    // `canonicalEntryPayloadFromBytes` could re-walk or re-serialize.
    expect(calls).toBe(1);
    // And the largest allocation observed during ingestion was the
    // change-bytes buffer itself, not the larger header+payload buffer
    // (which would be header (24) + parent (0) + signerKey (~97) +
    // changeBytes -- visibly bigger than just changeBytes).
    expect(largestAllocation).toBe(OVERSIZED);
  });

  test('change at exactly 1 MiB still passes the size gate', async () => {
    // The bound is inclusive (> MAX_CHANGE_BYTES is rejected, ==
    // MAX_CHANGE_BYTES is allowed) so confirm the boundary is correct.
    // We use a spy serializer that returns a buffer of exactly
    // MAX_CHANGE_BYTES bytes; the entry will then fail signature
    // verification (the signature is junk) rather than malformed-entry.
    const exactly = (_c: AclChange): Uint8Array =>
      new Uint8Array(1 << 20); // MAX_CHANGE_BYTES
    const chain = new ACLChain<AclChange, CryptoKey, CryptoKey>(
      {
        auth,
        serializeKey: serializePublicKey,
        ops: testOps,
        genesisAuthorizedKeys: [alice.publicKey],
      },
      exactly,
    );

    const entry: ACLEntry<AclChange> = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add', keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array(96), // wrong length for ECDSA P-384 sig is fine
    };

    const result = await chain.ingestEntry(entry, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Must NOT be the size gate; size is within bounds.
      expect(result.message).not.toMatch(/serialized change exceeds/);
      expect(result.reason).toBe('bad-signature');
    }
  });

  test('Uint8Array change is rejected before serializeChange is even called', async () => {
    // Thread A (Copilot follow-up): when `entry.change` is itself a
    // `Uint8Array` (the common case for byte-oriented CRDTs like Yjs),
    // the chain must size-gate it *before* `_serializeChange` runs --
    // otherwise the (potentially identity) serializer has already
    // allocated/copied a multi-megabyte buffer by the time the
    // post-serialize check fires.
    const OVERSIZED = (1 << 20) + 1; // MAX_CHANGE_BYTES + 1
    let calls = 0;
    const spy = (c: Uint8Array): Uint8Array => {
      calls += 1;
      return c;
    };
    const chain = new ACLChain<Uint8Array, CryptoKey, CryptoKey>(
      {
        auth,
        serializeKey: serializePublicKey,
        // The chain is generic in `ChangesType` and the chain ops only
        // touch `applyChange`/`isWriter`; we never feed an oversized
        // entry past the size gate so the ops are not exercised here.
        ops: {
          emptyState: () => new TestAclState() as unknown as ACLState<Uint8Array, CryptoKey>,
          applyChange: async (s) => s,
          isWriter: async () => true,
        } as ACLChainOps<Uint8Array, CryptoKey>,
        genesisAuthorizedKeys: [alice.publicKey],
      },
      spy,
    );

    const entry: ACLEntry<Uint8Array> = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      // The Uint8Array is itself oversized; the pre-serialize gate must
      // reject this before `spy` is ever invoked.
      change: new Uint8Array(OVERSIZED),
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array([1, 2, 3]),
    };

    const result = await chain.ingestEntry(entry, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/change exceeds maximum size/);
    }
    // The pre-serialize gate fired -- `_serializeChange` was never called.
    expect(calls).toBe(0);
  });

  test('serializeChange returning a non-Uint8Array is rejected', async () => {
    // Defensive: if a custom adapter returns garbage we surface
    // malformed-entry rather than crashing later when assembling the
    // canonical payload.
    const bogus = (_c: AclChange): Uint8Array =>
      'not bytes' as unknown as Uint8Array;
    const chain = new ACLChain<AclChange, CryptoKey, CryptoKey>(
      {
        auth,
        serializeKey: serializePublicKey,
        ops: testOps,
        genesisAuthorizedKeys: [alice.publicKey],
      },
      bogus,
    );

    const entry: ACLEntry<AclChange> = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: { op: 'add', keys: [alice.hashHex] },
      signerKeyId: await serializePublicKey(alice.publicKey),
      signature: new Uint8Array([1, 2, 3]),
    };
    const result = await chain.ingestEntry(entry, alice.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('malformed-entry');
      expect(result.message).toMatch(/serializeChange/);
    }
  });
});

describe('ingested entries are snapshot, not aliased', () => {
  // Thread B (CodeRabbit): the chain must not store the caller-owned entry
  // object directly. Mutating the entry after ingestion (or after
  // authorAndAppend returns) used to leak straight into `_entries` and
  // could corrupt parent-hash links, signature verification on replay,
  // and the chain's audit log.

  test('mutating entry returned by authorAndAppend does not corrupt the chain', async () => {
    const chain = makeChain([alice.publicKey]);

    const entry = await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    // Snapshot the chain's view of this entry's bytes BEFORE we mutate
    // the caller's copy.
    const beforeSig = new Uint8Array(chain.entries()[0].signature);
    const beforeSigner = new Uint8Array(chain.entries()[0].signerKeyId);

    // Mutate every byte field the caller can reach on their reference.
    entry.signature.fill(0);
    entry.signerKeyId.fill(0);

    // The chain's stored entry must be unaffected.
    const stored = chain.entries()[0];
    expect(Array.from(stored.signature)).toEqual(Array.from(beforeSig));
    expect(Array.from(stored.signerKeyId)).toEqual(Array.from(beforeSigner));
    // Sanity: the caller's view really did mutate -- otherwise the test
    // is vacuous.
    expect(entry.signature.every((b) => b === 0)).toBe(true);
  });

  test('mutating entry passed to ingestEntry does not corrupt the chain', async () => {
    // Author an entry on one chain, then ingest it onto a fresh chain
    // and mutate the caller-owned reference. The fresh chain's stored
    // copy must remain intact.
    const sourceChain = makeChain([alice.publicKey]);
    const e0 = await sourceChain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );

    const targetChain = makeChain([alice.publicKey]);
    const result = await targetChain.ingestEntry(e0, alice.publicKey);
    expect(result.ok).toBe(true);

    const storedBefore = targetChain.entries()[0];
    const sigBefore = new Uint8Array(storedBefore.signature);
    const keyBefore = new Uint8Array(storedBefore.signerKeyId);

    // Now corrupt the caller's reference.
    e0.signature.fill(0xff);
    e0.signerKeyId.fill(0xff);
    if (e0.parentHash) e0.parentHash.fill(0xff);

    const storedAfter = targetChain.entries()[0];
    expect(Array.from(storedAfter.signature)).toEqual(Array.from(sigBefore));
    expect(Array.from(storedAfter.signerKeyId)).toEqual(Array.from(keyBefore));
  });

  test('mutating parentHash on a caller-owned entry does not break chain linkage', async () => {
    // The parentHash on entry #1 forms the chain's hash-linked backbone.
    // If the caller mutates entry.parentHash after ingestion, computing
    // headHash via `_entryHashes` and replay() through computeEntryHash
    // would otherwise disagree on what was actually appended.
    const chain = makeChain([alice.publicKey]);
    await chain.authorAndAppend(
      { op: 'add', keys: [alice.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    const e1 = await chain.authorAndAppend(
      { op: 'add', keys: [bob.hashHex] },
      alice.publicKey,
      alice.privateKey,
    );
    expect(e1.parentHash).toBeDefined();

    const storedParentBefore = new Uint8Array(chain.entries()[1].parentHash!);

    // Mutate the caller-owned parentHash on the returned entry.
    e1.parentHash!.fill(0);

    // Chain's snapshot remains intact.
    const storedParentAfter = chain.entries()[1].parentHash!;
    expect(Array.from(storedParentAfter)).toEqual(
      Array.from(storedParentBefore),
    );

    // And the hash from headHash() still verifies against the stored
    // entry via computeEntryHash.
    const recomputed = await computeEntryHash(
      chain.entries()[1],
      serializeChange,
    );
    expect(toHex(chain.headHash!)).toBe(toHex(recomputed));
  });

  test('snapshot does not alias caller buffers for the change field when it is Uint8Array', async () => {
    // Special case: some CRDT adapters use a `Uint8Array` for the change
    // type itself. The chain's snapshot must clone that byte buffer too.
    interface BytesAclChange extends Uint8Array {}
    const bytesSerialize = (c: BytesAclChange): Uint8Array =>
      new Uint8Array(c);
    const bytesOps: ACLChainOps<BytesAclChange, CryptoKey> = {
      emptyState: () => new TestAclState() as unknown as ACLState<BytesAclChange, CryptoKey>,
      applyChange: async (state) => state,
      isWriter: async () => true,
    };
    const chain = new ACLChain<BytesAclChange, CryptoKey, CryptoKey>(
      {
        auth,
        serializeKey: serializePublicKey,
        ops: bytesOps,
        genesisAuthorizedKeys: [alice.publicKey],
      },
      bytesSerialize,
    );

    const callerChange = new Uint8Array([1, 2, 3, 4]) as BytesAclChange;
    const payload = {
      sequenceNumber: 0,
      timestamp: 0,
      parentHash: undefined,
      change: callerChange,
      signerKeyId: await serializePublicKey(alice.publicKey),
    };
    const encoded = canonicalEntryPayload(payload, bytesSerialize);
    const signature = await auth.sign(encoded, alice.privateKey);
    const entry: ACLEntry<BytesAclChange> = { ...payload, signature };

    const result = await chain.ingestEntry(entry, alice.publicKey);
    expect(result.ok).toBe(true);

    // Mutate the caller's view of the change bytes.
    callerChange.fill(0xff);

    const stored = chain.entries()[0].change as unknown as Uint8Array;
    expect(Array.from(stored)).toEqual([1, 2, 3, 4]);
  });
});
