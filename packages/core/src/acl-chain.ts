/**
 * ACL chain-of-trust verification.
 *
 * The existing {@link ACL} interface tracks readers and writers but does not
 * record *who* authorized each ACL change, nor in what order. This makes it
 * impossible to detect attacks like:
 *
 *   - A former writer (removed via `removeWriter`) crafting ACL changes
 *     that would have been valid before their removal, then replaying them
 *     to re-grant themselves access.
 *   - An attacker re-ordering legitimate ACL changes (e.g. applying a
 *     "remove Alice" change *after* "add Bob" when Alice was supposed to be
 *     removed first, so Alice never appears as a co-signer for Bob).
 *   - Injecting a forged change mid-chain that has no path back to a
 *     genesis-authorized signer.
 *
 * {@link ACLChain} solves these problems by maintaining an append-only,
 * hash-linked log of {@link ACLEntry}s. Each entry is signed by its author
 * and references the hash of the previous entry. On append, the chain
 * verifies:
 *
 *   1. The entry's signature matches its declared author.
 *   2. The author was authorized (i.e. a writer) at the *previous* state.
 *   3. The entry's `parentHash` matches the current head -- so re-ordering,
 *      forks, and mid-chain insertion are all rejected.
 *   4. Sequence numbers strictly increase, catching duplicate / replayed
 *      entries with mutated timestamps.
 *
 * The chain is independent of the {@link ACL} implementation (Yjs, Automerge,
 * etc.). Callers provide an {@link ACLChainOps} adapter that knows how to
 * (a) apply an ACL change block to a snapshot of state and (b) check whether
 * a given public key is authorized as a writer in that snapshot. This keeps
 * the chain decoupled from any specific CRDT.
 *
 * This module does not yet wire into the main {@link PeerborneDocument}
 * sync path. It is a self-contained building block; a follow-up PR will
 * integrate it with `_mergeWriters` and the sync message verification path.
 */

import type { AuthProvider } from './auth-provider.js';

/**
 * Canonical serialization of a public key for use as a stable identifier.
 *
 * The same key must always produce the same bytes regardless of how it was
 * imported, so that signers can be compared across instances. For ECDSA P-384
 * keys, the SPKI or raw uncompressed point encoding both satisfy this.
 */
export type SerializePublicKey<PublicKey> = (
  key: PublicKey,
) => Promise<Uint8Array>;

/**
 * Adapter that the chain uses to talk to a concrete {@link ACL} backend.
 *
 * The chain is generic over the ACL change block type (`ChangesType`) and
 * the public key type (`PublicKey`). It does not itself know how to apply
 * a change block to an ACL state -- it delegates to this adapter.
 */
export interface ACLChainOps<ChangesType, PublicKey> {
  /**
   * Construct a fresh, empty ACL state snapshot. Used to replay the chain
   * from genesis when verifying.
   */
  emptyState(): ACLState<ChangesType, PublicKey>;

  /**
   * Apply a change block to a state snapshot, producing a new snapshot.
   * Must not mutate the input snapshot -- the chain re-uses snapshots
   * across verification runs.
   */
  applyChange(
    state: ACLState<ChangesType, PublicKey>,
    change: ChangesType,
  ): Promise<ACLState<ChangesType, PublicKey>>;

  /**
   * Whether the given public key is a writer in the given state.
   */
  isWriter(
    state: ACLState<ChangesType, PublicKey>,
    publicKey: PublicKey,
  ): Promise<boolean>;
}

/**
 * Opaque snapshot of ACL state at some point in the chain.
 *
 * Carried by {@link ACLChainOps} between calls. The chain treats this as a
 * black box; the adapter is free to use whatever representation it likes
 * (a wrapped {@link ACL} clone, a serialized blob, an immutable structure).
 */
export interface ACLState<_ChangesType, _PublicKey> {
  /** Marker brand to discourage misuse. */
  readonly _aclStateBrand?: never;
}

/**
 * A single signed entry in the ACL chain.
 *
 * The signature covers the canonical encoding of the entry's payload
 * (`change`, `signerKeyId`, `sequenceNumber`, `timestamp`, `parentHash`).
 *
 * @typeParam ChangesType The CRDT change block type produced by the ACL.
 */
export interface ACLEntry<ChangesType> {
  /**
   * Strictly increasing sequence number. The first entry must have sequence
   * `0`; each subsequent entry must be `previous.sequenceNumber + 1`.
   */
  sequenceNumber: number;

  /**
   * Author timestamp in Unix milliseconds. Advisory only -- the chain
   * does not reject entries based on the *value* of the timestamp (since
   * clocks may drift); it only requires the value to be a non-negative
   * safe integer so the canonical encoding is unambiguous. Used to break
   * ties for human-readable audit logs.
   */
  timestamp: number;

  /**
   * Hash of the previous entry, or `undefined` for the genesis entry.
   * Hash is computed via {@link computeEntryHash}.
   */
  parentHash?: Uint8Array;

  /**
   * The ACL change block authored by the signer. Opaque to the chain.
   */
  change: ChangesType;

  /**
   * Stable canonical identifier for the signer's public key.
   *
   * These are the raw bytes produced by {@link SerializePublicKey} (e.g. an
   * SPKI or raw-point encoding of the key) -- *not* a cryptographic digest
   * of those bytes. The chain uses this for fast identity comparisons; the
   * actual public key for signature verification is supplied separately at
   * {@link ACLChain.authorAndAppend} / {@link ACLChain.ingestEntry} time.
   */
  signerKeyId: Uint8Array;

  /**
   * Signature over the canonical encoding of all fields above.
   */
  signature: Uint8Array;
}

/**
 * Failure modes that can be reported when verifying or appending an entry.
 *
 * Stable string union so callers can switch on the failure reason.
 */
export type ACLChainVerifyError =
  | 'bad-signature'
  | 'unauthorized-signer'
  | 'parent-hash-mismatch'
  | 'sequence-out-of-order'
  | 'unknown-signer-key'
  | 'malformed-entry';

/**
 * Result returned by {@link ACLChain.replay}, {@link ACLChain.ingestEntry},
 * and {@link ACLChain.authorAndAppend}. `ok: false` results carry both a
 * structured reason and a human readable message for logging.
 */
export type ACLChainVerifyResult =
  | { ok: true }
  | { ok: false; reason: ACLChainVerifyError; message: string; index: number };

/**
 * Configuration for an {@link ACLChain}.
 */
export interface ACLChainConfig<ChangesType, PrivateKey, PublicKey> {
  /**
   * Auth provider used for sign / verify operations on entries. The chain
   * uses the same signing primitive as the rest of Peerborne so applications
   * do not need to manage a second key.
   */
  auth: AuthProvider<PrivateKey, PublicKey, unknown>;

  /**
   * Serializer that produces a canonical byte representation of a public
   * key. The same key must always produce the same bytes.
   */
  serializeKey: SerializePublicKey<PublicKey>;

  /**
   * Adapter that knows how to apply ACL changes and check writer authority
   * for a specific backend (Yjs, Automerge, etc.).
   */
  ops: ACLChainOps<ChangesType, PublicKey>;

  /**
   * Set of public keys authorized to author the *genesis* entry (i.e. the
   * first change in the chain). Without a bootstrap root, every chain
   * would be vacuously verifiable.
   *
   * In practice this is the set of founding members for the document.
   * After the genesis entry is applied, subsequent entries are authorized
   * against the ACL state produced by the chain itself.
   */
  genesisAuthorizedKeys: PublicKey[];
}

/**
 * Compute the canonical hash of an {@link ACLEntry}.
 *
 * Hashes only the entry's payload fields (everything except the signature),
 * so the hash is stable across signers and serialization round-trips. The
 * resulting digest is used in two places:
 *
 * - As the value embedded in the next entry's {@link ACLEntry.parentHash}
 *   field, forming the chain's hash-linked backbone.
 * - As an element of {@link ACLChain}'s internal `_entryHashes` array, which
 *   tracks the most recent entry's hash so the next append can stamp the
 *   correct `parentHash`.
 *
 * Note: this hash is *not* used as a deduplication key. `_ingestEntryInternal`
 * deliberately does not deduplicate by hash — sequence-number and
 * parent-hash checks enforce chain integrity instead.
 *
 * The encoding is length-prefixed to avoid ambiguity between adjacent
 * variable-length fields:
 *
 * ```text
 *   u32 BE sequenceNumber
 *   u64 BE timestamp (only low 53 bits are meaningful in JS)
 *   u32 BE parentHash.length || parentHash bytes
 *   u32 BE signerKeyId.length || signerKeyId bytes
 *   u32 BE change.length || change bytes
 * ```
 *
 * @param entry The entry to hash. The `signature` field is ignored.
 * @param serializeChange Adapter that converts the opaque `ChangesType` into
 *   a `Uint8Array` for hashing.
 */
export async function computeEntryHash<ChangesType>(
  entry: Omit<ACLEntry<ChangesType>, 'signature'>,
  serializeChange: (change: ChangesType) => Uint8Array,
): Promise<Uint8Array> {
  const payload = canonicalEntryPayload(entry, serializeChange);
  const hash = await crypto.subtle.digest('SHA-256', payload as BufferSource);
  return new Uint8Array(hash);
}

/**
 * Canonical byte encoding of an {@link ACLEntry}'s payload (everything
 * the signature covers). Exported for tests; callers should usually go
 * through {@link ACLChain.authorAndAppend} (when authoring new entries)
 * or {@link ACLChain.ingestEntry} (when verifying entries received from
 * peers), both of which handle canonical encoding internally.
 */
export function canonicalEntryPayload<ChangesType>(
  entry: Omit<ACLEntry<ChangesType>, 'signature'>,
  serializeChange: (change: ChangesType) => Uint8Array,
): Uint8Array {
  return canonicalEntryPayloadFromBytes(entry, serializeChange(entry.change));
}

/**
 * Internal helper: build the canonical payload from a pre-serialized `change`
 * byte buffer. Callers on the network ingestion path serialize and size-gate
 * the change *before* invoking this so an oversized `change` cannot force a
 * large header+payload allocation on the hot path.
 */
function canonicalEntryPayloadFromBytes<ChangesType>(
  entry: Omit<ACLEntry<ChangesType>, 'signature' | 'change'>,
  changeBytes: Uint8Array,
): Uint8Array {
  const parent = entry.parentHash ?? new Uint8Array(0);
  const signerKey = entry.signerKeyId;

  // Header is fixed-size: u32 seq + u64 ts + 3 u32 length prefixes.
  const headerLen = 4 + 8 + 4 + 4 + 4;
  const total =
    headerLen + parent.byteLength + signerKey.byteLength + changeBytes.byteLength;

  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;

  view.setUint32(off, entry.sequenceNumber >>> 0, false);
  off += 4;

  // Split timestamp into hi/lo 32-bit halves so we don't lose precision on
  // values >2^32. JS numbers are safe to 2^53 so this is sufficient.
  // `validateEntryShape` enforces that this is a non-negative safe integer
  // before we get here, so the hi/lo split is unambiguous. We keep the
  // `Math.floor` and `>>> 0` calls as defensive belt-and-braces for the
  // (test-only) code paths that construct payloads without going through
  // ingestion.
  const ts = entry.timestamp;
  const tsHi = Math.floor(ts / 0x100000000);
  const tsLo = ts >>> 0;
  view.setUint32(off, tsHi, false);
  off += 4;
  view.setUint32(off, tsLo, false);
  off += 4;

  view.setUint32(off, parent.byteLength >>> 0, false);
  off += 4;
  out.set(parent, off);
  off += parent.byteLength;

  view.setUint32(off, signerKey.byteLength >>> 0, false);
  off += 4;
  out.set(signerKey, off);
  off += signerKey.byteLength;

  view.setUint32(off, changeBytes.byteLength >>> 0, false);
  off += 4;
  out.set(changeBytes, off);

  return out;
}

/**
 * Constant-time byte equality for equal-length inputs.
 *
 * Returns `false` immediately when the lengths differ -- timing then
 * reveals only that the lengths differ, which is not secret here:
 * every call site compares values with publicly-known structural lengths
 * (canonical serialized public keys, SHA-256 hash digests). When the
 * lengths *do* match, the comparison runs a fixed-length XOR loop so we
 * don't leak which byte differs -- relevant since hashes and signature
 * key ids are compared on the hot path.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Upper bound on byte length accepted for `parentHash`. Sized generously
 * above SHA-256's 32-byte digest so the cap rejects only obviously
 * malformed peer input. Network-supplied entries with unreasonably large
 * `parentHash` buffers would otherwise force large allocations during
 * hashing.
 */
const MAX_PARENT_HASH_BYTES = 64;

/**
 * Upper bound on byte length accepted for `signerKeyId`. Sized above the
 * canonical ECDSA P-384 raw public-key serialization (~97 bytes) and SPKI
 * encoding (~120 bytes) with headroom for alternate algorithms a future
 * `AuthProvider` might use. Anything substantially larger than a couple
 * hundred bytes is hostile input.
 */
const MAX_SIGNER_KEY_BYTES = 256;

/**
 * Upper bound on the serialized change payload accepted from the network.
 * 1 MiB is well above any realistic ACL diff but small enough that a
 * hostile peer cannot exhaust memory with a single forged entry.
 */
const MAX_CHANGE_BYTES = 1 << 20;

/**
 * Structural runtime check for a network-supplied {@link ACLEntry}.
 *
 * Returns `null` if the entry is well-formed enough to attempt signature
 * verification, or a human-readable reason string otherwise. Callers
 * should treat any non-null result as a `malformed-entry` rejection --
 * do not throw, since the entry may have been delivered by a hostile peer.
 */
function validateEntryShape<ChangesType>(
  entry: ACLEntry<ChangesType>,
): string | null {
  if (entry === null || typeof entry !== 'object') {
    return 'entry is not an object';
  }
  // `sequenceNumber` is encoded as an unsigned 32-bit integer in
  // `canonicalEntryPayload`. Values >2^32-1 would silently wrap via the
  // `>>> 0` cast and let a hostile peer manufacture two *different*
  // sequence numbers that produce identical canonical bytes (and
  // therefore identical signatures and hashes). Cap at 0xFFFFFFFF.
  if (
    typeof entry.sequenceNumber !== 'number' ||
    !Number.isInteger(entry.sequenceNumber) ||
    entry.sequenceNumber < 0 ||
    entry.sequenceNumber > 0xffffffff
  ) {
    return 'sequenceNumber is not an unsigned 32-bit integer';
  }
  // `timestamp` is encoded as two unsigned 32-bit halves in
  // `canonicalEntryPayload`. Fractional values would be silently truncated
  // and negative values would wrap to enormous unsigned ints, both of which
  // would let a hostile peer manufacture two *different* timestamp values
  // that produce identical canonical bytes (and therefore identical
  // signatures). Reject anything that isn't a non-negative safe integer.
  if (
    typeof entry.timestamp !== 'number' ||
    !Number.isInteger(entry.timestamp) ||
    entry.timestamp < 0 ||
    entry.timestamp > Number.MAX_SAFE_INTEGER
  ) {
    return 'timestamp is not a non-negative safe integer';
  }
  if (!(entry.signerKeyId instanceof Uint8Array)) {
    return 'signerKeyId is not a Uint8Array';
  }
  if (
    entry.signerKeyId.byteLength === 0 ||
    entry.signerKeyId.byteLength > MAX_SIGNER_KEY_BYTES
  ) {
    // Public key encodings are a couple hundred bytes at most; reject
    // anything wildly out of range.
    return 'signerKeyId has an implausible length';
  }
  if (!(entry.signature instanceof Uint8Array)) {
    return 'signature is not a Uint8Array';
  }
  if (entry.signature.byteLength === 0 || entry.signature.byteLength > 1024) {
    return 'signature has an implausible length';
  }
  if (entry.parentHash !== undefined) {
    if (!(entry.parentHash instanceof Uint8Array)) {
      return 'parentHash is not a Uint8Array';
    }
    if (
      entry.parentHash.byteLength === 0 ||
      entry.parentHash.byteLength > MAX_PARENT_HASH_BYTES
    ) {
      return 'parentHash has an implausible length';
    }
  }
  // `change` is opaque to the chain; we cannot validate its internal
  // structure here. The caller-supplied `serializeChange` is responsible
  // for producing a byte buffer or throwing, and we bound the resulting
  // size below in ingestEntry().
  return null;
}

/**
 * An append-only, hash-linked log of signed ACL changes.
 *
 * Each entry is verified before being applied:
 *
 *   1. Its signature must match its declared signer key.
 *   2. The signer must be a writer in the state immediately *before* this
 *      entry (or in {@link ACLChainConfig.genesisAuthorizedKeys} for the
 *      first entry).
 *   3. Its `parentHash` must match the hash of the current head.
 *   4. Its `sequenceNumber` must be exactly the prior length.
 *
 * Verified entries are appended and the chain's `state` is advanced.
 *
 * @typeParam ChangesType The CRDT change block type produced by the ACL.
 * @typeParam PrivateKey The private key type used by the auth provider.
 * @typeParam PublicKey The public key type used by the auth provider.
 */
export class ACLChain<ChangesType, PrivateKey, PublicKey> {
  private readonly _entries: ACLEntry<ChangesType>[] = [];
  private readonly _entryHashes: Uint8Array[] = [];

  /**
   * Current ACL state, updated incrementally as entries are appended.
   * `null` while the chain is still empty.
   */
  private _state: ACLState<ChangesType, PublicKey> | null = null;

  /** Serializer used both for the change payload and for the AuthProvider. */
  private readonly _serializeChange: (change: ChangesType) => Uint8Array;

  /**
   * Tail of the mutation queue. Mutating methods (`ingestEntry`,
   * `authorAndAppend`, `replay`) chain onto this promise so they run
   * serially even if invoked concurrently. Without this, two overlapping
   * `ingestEntry` calls could both capture the same `_entries.length`,
   * pass their checks against the same prior state, and then both append --
   * silently corrupting sequence numbers and parent-hash links.
   */
  private _mutationQueue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly _config: ACLChainConfig<ChangesType, PrivateKey, PublicKey>,
    /**
     * Adapter for converting an opaque `ChangesType` to bytes for signing
     * and hashing. Required because the chain has no direct knowledge of
     * the CRDT change format.
     */
    serializeChange: (change: ChangesType) => Uint8Array,
  ) {
    this._serializeChange = serializeChange;
  }

  /**
   * Number of entries currently in the chain.
   */
  get length(): number {
    return this._entries.length;
  }

  /**
   * Hash of the most recently appended entry, or `undefined` if the chain
   * is empty.
   *
   * Use this as the `parentHash` for the next entry you author.
   */
  get headHash(): Uint8Array | undefined {
    const last = this._entryHashes[this._entryHashes.length - 1];
    return last ? new Uint8Array(last) : undefined;
  }

  /**
   * Snapshot of the chain's entries. Returns a shallow copy so callers
   * can iterate without risk of seeing live mutations from concurrent
   * appends.
   *
   * The entries themselves are the chain's *internal snapshots* of the
   * originally-ingested entries (see `_ingestEntryInternal`); their byte
   * fields are private copies that do not alias caller-owned buffers.
   * They are still not frozen, so do not mutate the returned objects —
   * doing so would corrupt subsequent reads through `entries()` and
   * could desynchronize a serialized chain on the wire from this
   * instance's view.
   */
  entries(): ReadonlyArray<ACLEntry<ChangesType>> {
    return this._entries.slice();
  }

  /**
   * Serialize the given task against the mutation queue.
   *
   * Returns a promise that resolves with the task's result once all prior
   * queued tasks have settled. The queue catches and discards errors so
   * one failing task does not poison the queue for subsequent ones.
   */
  private _runExclusive<T>(task: () => Promise<T>): Promise<T> {
    const next = this._mutationQueue.then(task, task);
    // Swallow the result so the next task isn't poisoned by a rejection.
    this._mutationQueue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  /**
   * Build, sign, and append a new entry authored by `signerKey`.
   *
   * The signer must currently be authorized (a writer in the chain's
   * current state, or in `genesisAuthorizedKeys` for the genesis entry).
   * On success the entry is verified, applied to the chain's internal
   * state, and returned for transmission to peers.
   *
   * Concurrent `authorAndAppend` / {@link ingestEntry} calls are
   * serialized via an internal queue, so each call sees a consistent
   * `_entries.length`, head hash, and ACL state during its checks.
   *
   * @throws Error if the signer is not authorized -- this is a programmer
   *   error and indicates a misuse of the API, not a network attack.
   *   Network-supplied entries should be passed through {@link ingestEntry}
   *   instead, which returns a structured error rather than throwing.
   *   Errors from {@link ACLChainConfig.serializeKey} (e.g. unsupported key
   *   types) and from {@link ACLChainConfig.auth}'s `sign` method (e.g.
   *   WebCrypto failures, key/algorithm incompatibility, hardware backend
   *   errors) also propagate as a rejected promise.
   */
  async authorAndAppend(
    change: ChangesType,
    signerPublicKey: PublicKey,
    signerPrivateKey: PrivateKey,
    timestamp: number = Date.now(),
  ): Promise<ACLEntry<ChangesType>> {
    return this._runExclusive(async () => {
      const signerKeyId = await this._config.serializeKey(signerPublicKey);

      const payload: Omit<ACLEntry<ChangesType>, 'signature'> = {
        sequenceNumber: this._entries.length,
        timestamp,
        parentHash: this.headHash,
        change,
        signerKeyId,
      };

      const encoded = canonicalEntryPayload(payload, this._serializeChange);
      const signature = await this._config.auth.sign(encoded, signerPrivateKey);

      const entry: ACLEntry<ChangesType> = { ...payload, signature };

      const result = await this._ingestEntryInternal(entry, signerPublicKey);
      if (!result.ok) {
        // Author tried to append an entry they're not allowed to author.
        // This is a programmer error, not a hostile-input case.
        throw new Error(
          `ACLChain.authorAndAppend: refusing to append entry: ${result.reason}: ${result.message}`,
        );
      }
      return entry;
    });
  }

  /**
   * Verify and apply a (presumably network-supplied) entry.
   *
   * Returns a structured result rather than throwing so callers can log
   * and discard malicious or stale entries without unwinding their own
   * control flow. Malformed runtime data (wrong field types, oversized
   * byte buffers, exceptions thrown by `serializeKey`/`serializeChange`)
   * is surfaced as a `'malformed-entry'` result rather than propagating
   * as an exception, so a single hostile entry cannot DoS the caller.
   *
   * Concurrent invocations are serialized via an internal queue so each
   * call observes a consistent prior chain state.
   *
   * @param entry The signed entry to apply.
   * @param signerPublicKey The public key that the caller claims signed
   *   `entry`. The chain verifies that this key matches
   *   `entry.signerKeyId` (via {@link SerializePublicKey}) AND that it
   *   actually signed the payload.
   */
  async ingestEntry(
    entry: ACLEntry<ChangesType>,
    signerPublicKey: PublicKey,
  ): Promise<ACLChainVerifyResult> {
    return this._runExclusive(() =>
      this._ingestEntryInternal(entry, signerPublicKey),
    );
  }

  /**
   * Implementation of {@link ingestEntry} that assumes the caller already
   * holds the mutation queue. Do not call this directly from outside the
   * class.
   */
  private async _ingestEntryInternal(
    entry: ACLEntry<ChangesType>,
    signerPublicKey: PublicKey,
  ): Promise<ACLChainVerifyResult> {
    const index = this._entries.length;

    // 0. Structural validation. Network-supplied entries may have entirely
    //    wrong shapes (missing fields, wrong types, oversized buffers);
    //    catch these up front so subsequent steps can rely on field types
    //    and we never throw on hostile input.
    const shapeError = validateEntryShape(entry);
    if (shapeError !== null) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: shapeError,
        index,
      };
    }

    // 1. Caller-supplied key must match the canonical key bytes in the entry.
    //    `entry.signerKeyId` holds the canonical serialized public key
    //    (produced by `serializeKey`); it is *not* a hash. The genuine
    //    SHA-256 hash field on entries is `parentHash`. Don't confuse the
    //    two.
    const declared = entry.signerKeyId;
    let actual: Uint8Array;
    try {
      actual = await this._config.serializeKey(signerPublicKey);
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `serializeKey threw on supplied public key: ${(err as Error).message}`,
        index,
      };
    }
    if (!bytesEqual(declared, actual)) {
      return {
        ok: false,
        reason: 'unknown-signer-key',
        message:
          'supplied public key does not match the entry.signerKeyId field',
        index,
      };
    }

    // 2. Sequence numbers must be strictly increasing and contiguous.
    if (entry.sequenceNumber !== index) {
      return {
        ok: false,
        reason: 'sequence-out-of-order',
        message: `expected sequenceNumber=${index}, got ${entry.sequenceNumber}`,
        index,
      };
    }

    // 3. Parent hash must match the current head.
    const head = this.headHash;
    if (head === undefined) {
      if (entry.parentHash !== undefined) {
        return {
          ok: false,
          reason: 'parent-hash-mismatch',
          message: 'genesis entry must not declare a parentHash',
          index,
        };
      }
    } else {
      if (entry.parentHash === undefined) {
        return {
          ok: false,
          reason: 'parent-hash-mismatch',
          message: 'non-genesis entry is missing a parentHash',
          index,
        };
      }
      if (!bytesEqual(head, entry.parentHash)) {
        return {
          ok: false,
          reason: 'parent-hash-mismatch',
          message: `parentHash does not match the current chain head`,
          index,
        };
      }
    }

    // 4. Canonical-encode and hash the payload. Bound the size up front so
    //    a hostile peer cannot force a large allocation via an oversized
    //    `change`.
    //
    //    Defense-in-depth, in order:
    //
    //    (a) **Pre-serialize gate.** If `entry.change` is itself a
    //        `Uint8Array` -- which is the common case (e.g. Yjs encodes
    //        changes as raw bytes and uses an identity serializer) -- we
    //        check its `byteLength` *before* calling `_serializeChange`.
    //        This catches the hostile-peer DoS case where an attacker
    //        delivers a multi-megabyte buffer: we reject without copying
    //        or re-encoding it. We do NOT inspect non-`Uint8Array` shapes
    //        here because that would require walking caller-supplied
    //        structures of unknown cost.
    //
    //    (b) **Post-serialize gate.** For opaque `ChangesType` values
    //        (e.g. Automerge `BinaryChange[]`, or arbitrary JSON payloads
    //        for the test serializer) we cannot meaningfully size them
    //        until they have been serialized. The post-serialize check on
    //        `changeBytes.byteLength` is the second line of defense for
    //        those shapes: the allocation has already happened, but the
    //        chain still refuses to assemble the full header+payload
    //        buffer (~2x the size) and refuses to verify a signature or
    //        append the entry. This bounds the worst-case allocation at
    //        roughly one `MAX_CHANGE_BYTES` buffer per ingestion attempt
    //        rather than two.
    //
    //    `serializeChange` runs over the (still opaque) change here; if
    //    it throws on hostile input we surface it as a structured error
    //    rather than letting the exception escape.
    //
    //    We do not separately deduplicate by hash: any two entries with the
    //    same canonical payload would necessarily share a `sequenceNumber`,
    //    and the sequence check in step 2 already requires
    //    `entry.sequenceNumber === this._entries.length`. A re-ingested
    //    entry therefore can never reach this point with a matching hash.
    if (
      entry.change instanceof Uint8Array &&
      entry.change.byteLength > MAX_CHANGE_BYTES
    ) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `change exceeds maximum size (${entry.change.byteLength} > ${MAX_CHANGE_BYTES} bytes)`,
        index,
      };
    }
    let entryHash: Uint8Array;
    let changeBytes: Uint8Array;
    try {
      changeBytes = this._serializeChange(entry.change);
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `failed to serialize change: ${(err as Error).message}`,
        index,
      };
    }
    if (!(changeBytes instanceof Uint8Array)) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: 'serializeChange did not return a Uint8Array',
        index,
      };
    }
    if (changeBytes.byteLength > MAX_CHANGE_BYTES) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `serialized change exceeds maximum size (${changeBytes.byteLength} > ${MAX_CHANGE_BYTES} bytes)`,
        index,
      };
    }
    let payloadBytes: Uint8Array;
    try {
      payloadBytes = canonicalEntryPayloadFromBytes(entry, changeBytes);
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `failed to canonically encode entry: ${(err as Error).message}`,
        index,
      };
    }
    if (payloadBytes.byteLength > MAX_CHANGE_BYTES + 1024) {
      // 1 KiB slack for the fixed header + parent/signer fields. The
      // `change` byte length was already gated above; this catches a
      // pathological `parentHash` / `signerKeyId` combination.
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `encoded entry payload exceeds maximum size (${payloadBytes.byteLength} > ${MAX_CHANGE_BYTES + 1024} bytes)`,
        index,
      };
    }
    try {
      const digest = await crypto.subtle.digest('SHA-256', payloadBytes as BufferSource);
      entryHash = new Uint8Array(digest);
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `failed to hash entry payload: ${(err as Error).message}`,
        index,
      };
    }

    // 5. Signature must verify against the canonical payload.
    let signatureOk: boolean;
    try {
      signatureOk = await this._config.auth.verify(
        payloadBytes,
        signerPublicKey,
        entry.signature,
      );
    } catch (err) {
      return {
        ok: false,
        reason: 'bad-signature',
        message: `signature verification threw: ${(err as Error).message}`,
        index,
      };
    }
    if (!signatureOk) {
      return {
        ok: false,
        reason: 'bad-signature',
        message: 'signature does not verify against the declared signer',
        index,
      };
    }

    // 6. Authorization: signer must be a writer in the state *before* this
    //    entry. For the genesis entry, the bootstrap set defines who can
    //    sign.
    let priorState: ACLState<ChangesType, PublicKey>;
    try {
      priorState = this._state ?? this._config.ops.emptyState();
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `ops.emptyState threw: ${(err as Error).message}`,
        index,
      };
    }
    let authorized: boolean;
    try {
      if (this._entries.length === 0) {
        authorized = await this._isInBootstrapSet(signerPublicKey);
      } else {
        authorized = await this._config.ops.isWriter(
          priorState,
          signerPublicKey,
        );
      }
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `authorization check threw: ${(err as Error).message}`,
        index,
      };
    }
    if (!authorized) {
      return {
        ok: false,
        reason: 'unauthorized-signer',
        message:
          this._entries.length === 0
            ? 'genesis signer is not in genesisAuthorizedKeys'
            : 'signer was not a writer at the time this entry was authored',
        index,
      };
    }

    // 7. All checks passed -- apply the change and commit. If applyChange
    //    throws (e.g. malformed change semantics that slipped past the
    //    signature check because the signer happened to also be malicious),
    //    surface as malformed-entry so chain state is not partially updated.
    let newState: ACLState<ChangesType, PublicKey>;
    try {
      newState = await this._config.ops.applyChange(priorState, entry.change);
    } catch (err) {
      return {
        ok: false,
        reason: 'malformed-entry',
        message: `ops.applyChange threw: ${(err as Error).message}`,
        index,
      };
    }
    this._state = newState;
    // Store an immutable snapshot rather than the caller-owned entry
    // reference. `authorAndAppend` returns the entry it just built, and
    // `ingestEntry` callers also still hold the same object. Mutating it
    // afterwards -- e.g. flipping a byte in `signature` or `parentHash` --
    // would otherwise corrupt the chain's recorded state. Deep-copy the
    // byte fields we own; `change` is opaque (its concrete type belongs
    // to the CRDT adapter) so we clone it only when it is itself a
    // `Uint8Array`, otherwise we rely on the spread to at least isolate
    // the property slot on our entry object from the caller's.
    const snapshot: ACLEntry<ChangesType> = {
      ...entry,
      parentHash:
        entry.parentHash === undefined
          ? undefined
          : new Uint8Array(entry.parentHash),
      signerKeyId: new Uint8Array(entry.signerKeyId),
      signature: new Uint8Array(entry.signature),
      change:
        entry.change instanceof Uint8Array
          ? (new Uint8Array(entry.change) as unknown as ChangesType)
          : entry.change,
    };
    this._entries.push(snapshot);
    // `entryHash` is freshly allocated locally above (from `crypto.subtle`
    // output), so no defensive copy is needed.
    this._entryHashes.push(entryHash);

    return { ok: true };
  }

  /**
   * Re-verify the entire chain from genesis. Used at load time when
   * receiving a chain snapshot from a peer.
   *
   * Stops at the first invalid entry and returns its index. On success
   * the chain has the same `state` as if every entry had been ingested
   * individually.
   *
   * Runs under the mutation queue, so concurrent `ingestEntry` /
   * `authorAndAppend` / `replay` calls observe a consistent chain
   * throughout the replay.
   *
   * Partial-success contract: `replay()` first resets `_entries`,
   * `_entryHashes`, and `_state`, then ingests the supplied entries in
   * order. If verification fails at entry `i`, the method returns early
   * with that failure result and the chain is left containing the valid
   * prefix `entries[0..i-1]` along with the corresponding `_state`. The
   * prior chain contents are *not* restored. Callers who need transactional
   * "all-or-nothing" semantics should snapshot the chain before calling
   * `replay()` and decide what to do based on the returned result.
   *
   * @param entries The full chain to verify. Each entry's signer key must
   *   be resolvable via `resolveKey(signerKeyId)`. If `resolveKey`
   *   returns `undefined`, the entry is rejected with
   *   `'unknown-signer-key'`.
   */
  async replay(
    entries: ReadonlyArray<ACLEntry<ChangesType>>,
    resolveKey: (signerKeyId: Uint8Array) => Promise<PublicKey | undefined>,
  ): Promise<ACLChainVerifyResult> {
    return this._runExclusive(async () => {
      // Reset internal state so callers can use replay() as a "load from
      // scratch" primitive without constructing a new chain.
      this._entries.length = 0;
      this._entryHashes.length = 0;
      this._state = null;

      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        // Pre-validate the full entry shape *before* calling resolveKey.
        // A hostile snapshot could otherwise supply an arbitrarily large
        // `signerKeyId` and force `resolveKey` (often a lookup keyed by
        // that bytestring) to perform expensive work or allocate large
        // amounts of memory. `validateEntryShape` enforces the
        // `MAX_SIGNER_KEY_BYTES` bound (along with all other field
        // bounds), so resolveKey only ever sees a key id of plausible
        // size. `_ingestEntryInternal` re-runs the same check below; the
        // redundancy is intentional so this entry point is safe even if
        // resolveKey misbehaves on hostile input.
        const shapeError = validateEntryShape(entry);
        if (shapeError !== null) {
          return {
            ok: false,
            reason: 'malformed-entry',
            message: shapeError,
            index: i,
          };
        }
        let signerKey: PublicKey | undefined;
        try {
          signerKey = await resolveKey(entry.signerKeyId);
        } catch (err) {
          return {
            ok: false,
            reason: 'unknown-signer-key',
            message: `resolveKey threw at entry ${i}: ${(err as Error).message}`,
            index: i,
          };
        }
        if (!signerKey) {
          return {
            ok: false,
            reason: 'unknown-signer-key',
            message: `no public key available for signerKeyId at entry ${i}`,
            index: i,
          };
        }
        const result = await this._ingestEntryInternal(entry, signerKey);
        if (!result.ok) {
          return result;
        }
      }
      return { ok: true };
    });
  }

  /**
   * Current state of the ACL after applying every entry in the chain.
   * `undefined` if the chain is empty (no entries have been applied yet).
   */
  get state(): ACLState<ChangesType, PublicKey> | undefined {
    return this._state ?? undefined;
  }

  /**
   * Check whether `candidate` matches any key in the bootstrap set.
   * Compared via the canonical {@link SerializePublicKey} encoding so
   * imported / re-imported key objects compare equal.
   */
  private async _isInBootstrapSet(candidate: PublicKey): Promise<boolean> {
    const candidateBytes = await this._config.serializeKey(candidate);
    for (const allowed of this._config.genesisAuthorizedKeys) {
      const allowedBytes = await this._config.serializeKey(allowed);
      if (bytesEqual(candidateBytes, allowedBytes)) {
        return true;
      }
    }
    return false;
  }
}
