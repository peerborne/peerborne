import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import {
  evaluateBeeKEMWelcome,
  WelcomeValidationDeps,
} from './beekem-welcome-handler.js';
import { EPOCH_ID_LENGTH } from './epoch.js';
import {
  PendingWelcomeBuffer,
  PendingWelcomeBodyLimitError,
  PENDING_WELCOME_MAX_BODY_BYTES,
  PENDING_WELCOMES_MAX_ENTRIES,
  PENDING_WELCOMES_MAX_RETAINED_BYTES,
  PENDING_WELCOMES_TTL_MS,
} from './pending-welcome-buffer.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';

/**
 * Unit-level coverage for the pending-welcomes buffer + drain semantics
 * that close the readers-ACL / Welcome reordering race.
 *
 * The buffer itself lives on `PeerborneDocument` (and depends on a full
 * libp2p/Helia stack to instantiate), so this file mirrors the buffer +
 * drain state machine against a minimal in-memory harness. The mirror
 * matches:
 *
 *   - `_bufferPendingWelcome`: keyed by `hex(welcomeEpochId)`, with exact
 *     serialized-byte and entry limits plus oldest-first eviction.
 *   - `_drainPendingWelcomes`: replay each entry through
 *     `evaluateBeeKEMWelcome`; remove on `accept`; discard entries past
 *     TTL (5 min); leave others in place.
 *   - `_mergeReaders`: after a readers-ACL merge, drain the buffer.
 *
 * If you change buffer semantics in production, mirror the change here.
 */

type ChangesType = Uint8Array;
type PublicKey = { id: string };

const stubSerializer: SyncMessageSerializer<ChangesType, PublicKey> = {
  serializeSyncMessage(message: CRDTSyncMessage<ChangesType, PublicKey>) {
    return new TextEncoder().encode(
      JSON.stringify(message, (_key, value) =>
        value instanceof Uint8Array
          ? { __testBytes: Base64.fromUint8Array(value) }
          : value,
      ),
    );
  },
  deserializeSyncMessage(data: Uint8Array) {
    return JSON.parse(
      new TextDecoder().decode(data),
      (_key, value) =>
        value &&
        typeof value === 'object' &&
        typeof value.__testBytes === 'string'
          ? Base64.toUint8Array(value.__testBytes)
          : value,
    ) as CRDTSyncMessage<ChangesType, PublicKey>;
  },
} as unknown as SyncMessageSerializer<ChangesType, PublicKey>;

function hex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/**
 * Minimal mirror of the recipient-side pending-welcomes buffer +
 * drain machinery on `PeerborneDocument`.
 */
class PendingWelcomesHarness {
  pendingWelcomes = new PendingWelcomeBuffer();
  appliedEpochs: Uint8Array[] = [];
  /** Local clock; tests can advance it to exercise TTL. */
  nowMs = 0;
  /** Whether the local user is currently in the readers ACL. */
  isReader = false;
  signatureResult: unknown = true;
  verificationCalls = 0;

  private depsFor(): WelcomeValidationDeps<ChangesType, PublicKey> {
    return {
      documentPath: '/doc/welcome',
      localUserPublicKey: { id: 'me' },
      serializePublicKey: async (pk) => pk.id,
      isReader: async () => this.isReader,
      // Welcomes are unconditionally writer-authenticated; the test
      // messages below always carry a `signature` field so this stub
      // verifier just returns `true` for any signed payload.
      verifyWriterSignature: async () => {
        this.verificationCalls++;
        return this.signatureResult as boolean;
      },
      syncMessageSerializer: stubSerializer,
    };
  }

  /**
   * Mirror of `_evaluateAndApplyBeeKEMWelcome`.
   * Returns `true` iff the Welcome was accepted (applied).
   */
  async evaluateAndApply(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    opts: { fromBuffer: boolean },
  ): Promise<boolean> {
    const decision = await evaluateBeeKEMWelcome(message, this.depsFor());
    if (decision.kind !== 'accept') {
      if (
        decision.kind === 'drop-unauthorized' &&
        decision.reason === 'not-in-readers-acl' &&
        !opts.fromBuffer &&
        decision.message?.welcomeEpochId !== undefined &&
        decision.message.welcomeEpochId.byteLength === EPOCH_ID_LENGTH
      ) {
        this.bufferPendingWelcome(decision.message);
      }
      return false;
    }
    this.appliedEpochs.push(decision.message.welcomeEpochId as Uint8Array);
    return true;
  }

  /** Mirror of `_bufferPendingWelcome`. */
  bufferPendingWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): boolean {
    const epochId = message.welcomeEpochId;
    if (!epochId || epochId.byteLength !== EPOCH_ID_LENGTH) return false;
    const key = hex(epochId);
    try {
      this.pendingWelcomes.storeMessage(
        key,
        message,
        stubSerializer,
        this.nowMs,
      );
      return true;
    } catch (error) {
      if (!(error instanceof PendingWelcomeBodyLimitError)) throw error;
      return false;
    }
  }

  /** Mirror of `_drainPendingWelcomes`. */
  async drainPendingWelcomes(): Promise<void> {
    if (this.pendingWelcomes.size === 0) return;
    const now = this.nowMs;
    const keys = this.pendingWelcomes.keysSnapshot();
    for (const key of keys) {
      const entry = this.pendingWelcomes.get(key);
      if (entry === undefined) continue;
      if (now - entry.bufferedAtMs > PENDING_WELCOMES_TTL_MS) {
        this.pendingWelcomes.delete(key);
        continue;
      }
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = stubSerializer.deserializeSyncMessage(entry.body);
      } catch {
        this.pendingWelcomes.delete(key);
        continue;
      }
      const accepted = await this.evaluateAndApply(
        message,
        { fromBuffer: true },
      );
      if (accepted) this.pendingWelcomes.delete(key);
    }
  }

  /** Mirror of `_mergeReaders` (drain on every readers-ACL merge). */
  async mergeReadersAddingLocal(): Promise<void> {
    this.isReader = true;
    await this.drainPendingWelcomes();
  }
}

function welcomeFor(
  epochByte: number,
  recipient = 'me',
): CRDTSyncMessage<ChangesType, PublicKey> {
  return {
    documentId: '/doc/welcome',
    signatureContext: 'beekem-welcome-v2',
    welcomeEpochId: new Uint8Array(EPOCH_ID_LENGTH).fill(epochByte),
    welcomeRecipient: recipient,
    // Recipient KEM binding + sealed payload presence are both
    // structurally required by the validator post-encryption. The
    // pending-welcomes buffer is concerned with reordering only --
    // the seal/open round-trip is exercised by
    // `beekem-welcome-encryption.test.ts`.
    welcomeRecipientKemPublicKey: new Uint8Array(65).fill(0xaa),
    eciesSealed: new Uint8Array([1, 2, 3]),
    // Welcomes are unconditionally writer-authenticated; the stub
    // `verifyWriterSignature` in `depsFor` returns `true` for any
    // signed payload, so this string just satisfies the signature
    // presence gate in `evaluateBeeKEMWelcome`.
    signature: 'good-sig',
  };
}

describe('PendingWelcomeBuffer byte accounting', () => {
  test('accepts the exact per-body boundary and preserves an existing duplicate when replacement is oversized', () => {
    const buffer = new PendingWelcomeBuffer();
    const original = new Uint8Array([1, 2, 3]);
    buffer.store('epoch', original, 1);

    expect(() =>
      buffer.store(
        'epoch',
        new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES + 1),
        2,
      ),
    ).toThrow(PendingWelcomeBodyLimitError);
    expect(buffer.size).toBe(1);
    expect(buffer.retainedBytes).toBe(original.byteLength);
    expect(buffer.get('epoch')?.body).toEqual(original);

    expect(() =>
      buffer.store(
        'boundary',
        new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES),
        3,
      ),
    ).not.toThrow();
    expect(buffer.retainedBytes).toBe(
      original.byteLength + PENDING_WELCOME_MAX_BODY_BYTES,
    );
  });

  test('accounts duplicate replacement exactly and refreshes its recency', () => {
    const buffer = new PendingWelcomeBuffer();
    buffer.store('first', new Uint8Array(11), 1);
    buffer.store('second', new Uint8Array(23), 2);

    const result = buffer.store('first', new Uint8Array(37), 3);

    expect(result.replaced).toBe(true);
    expect(result.evictedKeys).toEqual([]);
    expect(buffer.keysSnapshot()).toEqual(['second', 'first']);
    expect(buffer.size).toBe(2);
    expect(buffer.retainedBytes).toBe(23 + 37);
  });

  test('evicts by aggregate bytes before the entry-count limit is reached', () => {
    const buffer = new PendingWelcomeBuffer();
    for (let index = 0; index < 4; index++) {
      buffer.store(
        `epoch-${index}`,
        new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES),
        index,
      );
    }
    expect(buffer.size).toBe(4);
    expect(buffer.retainedBytes).toBe(
      PENDING_WELCOMES_MAX_RETAINED_BYTES,
    );

    const result = buffer.store('epoch-4', new Uint8Array(1), 4);

    expect(result.evictedKeys).toEqual(['epoch-0']);
    expect(buffer.size).toBe(4);
    expect(buffer.size).toBeLessThan(PENDING_WELCOMES_MAX_ENTRIES);
    expect(buffer.retainedBytes).toBe(
      3 * PENDING_WELCOME_MAX_BODY_BYTES + 1,
    );
    expect(buffer.retainedBytes).toBeLessThanOrEqual(
      PENDING_WELCOMES_MAX_RETAINED_BYTES,
    );
  });

  test('owns retained bytes and returns detached replay copies', () => {
    const buffer = new PendingWelcomeBuffer();
    const callerBody = new Uint8Array([1, 2, 3]);
    buffer.store('epoch', callerBody, 0);
    callerBody.fill(9);
    const replayBody = buffer.get('epoch')!.body;
    replayBody.fill(8);

    expect(buffer.get('epoch')!.body).toEqual(new Uint8Array([1, 2, 3]));
    expect(buffer.retainedBytes).toBe(3);
  });
});

describe('BeeKEM pending-welcomes buffer (readers-ACL / Welcome reordering)', () => {
  test('buffers a Welcome dropped only because the local user is not yet a reader', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;

    const accepted = await h.evaluateAndApply(welcomeFor(7), {
      fromBuffer: false,
    });

    // Welcome is dropped on the live path but parked in the buffer for
    // replay once the ACL update lands.
    expect(accepted).toBe(false);
    expect(h.appliedEpochs).toHaveLength(0);
    expect(h.pendingWelcomes.size).toBe(1);
    expect(h.pendingWelcomes.retainedBytes).toBeGreaterThan(0);
    expect(h.verificationCalls).toBe(1);
  });

  test('drains and applies buffered Welcome when readers ACL adds the local user', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    expect(h.pendingWelcomes.size).toBe(1);

    await h.mergeReadersAddingLocal();

    expect(h.pendingWelcomes.size).toBe(0);
    expect(h.pendingWelcomes.retainedBytes).toBe(0);
    expect(h.appliedEpochs).toHaveLength(1);
    // The serialized buffer is not an authentication cache: replay verifies
    // the writer signature again before applying any state.
    expect(h.verificationCalls).toBe(2);
    expect(Array.from(h.appliedEpochs[0])).toEqual(
      Array.from(new Uint8Array(EPOCH_ID_LENGTH).fill(7)),
    );
  });

  test('does NOT buffer Welcomes addressed to another recipient (drop-not-for-us)', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    // Welcome is addressed to someone else; it never reaches the
    // not-in-readers-acl gate and must not enter the buffer.
    await h.evaluateAndApply(welcomeFor(7, 'someone-else'), {
      fromBuffer: false,
    });
    expect(h.pendingWelcomes.size).toBe(0);
  });

  test('does NOT buffer malformed Welcomes (missing epoch id)', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    const msg: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: '/doc/welcome',
      welcomeRecipient: 'me',
      welcomeRecipientKemPublicKey: new Uint8Array(65).fill(0xaa),
      eciesSealed: new Uint8Array([1, 2, 3]),
      // welcomeEpochId omitted
    };
    await h.evaluateAndApply(msg, { fromBuffer: false });
    expect(h.pendingWelcomes.size).toBe(0);
  });

  test.each([EPOCH_ID_LENGTH - 1, EPOCH_ID_LENGTH + 1])(
    'does NOT buffer a Welcome with a %i-byte epoch id',
    async (length) => {
      const h = new PendingWelcomesHarness();
      const message = welcomeFor(7);
      message.welcomeEpochId = new Uint8Array(length).fill(7);

      await h.evaluateAndApply(message, { fromBuffer: false });

      expect(h.pendingWelcomes.size).toBe(0);
    },
  );

  test('coalesces duplicate Welcomes for the same epoch into a single entry', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    expect(h.pendingWelcomes.size).toBe(1);
  });

  test('authenticates but does not retain an oversized pending Welcome or apply state', async () => {
    const h = new PendingWelcomesHarness();
    const message = welcomeFor(7);
    message.eciesSealed = new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES);
    expect(
      stubSerializer.serializeSyncMessage(message).byteLength,
    ).toBeGreaterThan(PENDING_WELCOME_MAX_BODY_BYTES);

    const accepted = await h.evaluateAndApply(message, { fromBuffer: false });

    expect(accepted).toBe(false);
    expect(h.verificationCalls).toBe(1);
    expect(h.pendingWelcomes.size).toBe(0);
    expect(h.pendingWelcomes.retainedBytes).toBe(0);
    expect(h.appliedEpochs).toHaveLength(0);
  });

  test('does not impose the pending-buffer cap on an already-authorized live Welcome', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = true;
    const message = welcomeFor(7);
    message.eciesSealed = new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES);
    expect(
      stubSerializer.serializeSyncMessage(message).byteLength,
    ).toBeGreaterThan(PENDING_WELCOME_MAX_BODY_BYTES);

    const accepted = await h.evaluateAndApply(message, { fromBuffer: false });

    expect(accepted).toBe(true);
    expect(h.verificationCalls).toBe(1);
    expect(h.pendingWelcomes.size).toBe(0);
    expect(h.pendingWelcomes.retainedBytes).toBe(0);
    expect(h.appliedEpochs).toHaveLength(1);
  });

  test('refreshes an authenticated duplicate before insertion-order eviction', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    for (let epoch = 1; epoch <= PENDING_WELCOMES_MAX_ENTRIES; epoch++) {
      h.nowMs = epoch;
      await h.evaluateAndApply(welcomeFor(epoch), { fromBuffer: false });
    }

    const refreshedKey = hex(new Uint8Array(EPOCH_ID_LENGTH).fill(1));
    h.nowMs = 100;
    await h.evaluateAndApply(welcomeFor(1), { fromBuffer: false });
    expect(h.pendingWelcomes.get(refreshedKey)?.bufferedAtMs).toBe(100);

    await h.evaluateAndApply(
      welcomeFor(PENDING_WELCOMES_MAX_ENTRIES + 1),
      { fromBuffer: false },
    );

    const formerlySecondOldest = hex(
      new Uint8Array(EPOCH_ID_LENGTH).fill(2),
    );
    expect(h.pendingWelcomes.has(refreshedKey)).toBe(true);
    expect(h.pendingWelcomes.has(formerlySecondOldest)).toBe(false);
  });

  test('unsigned and truthy-nonboolean forged duplicates cannot replace a valid buffered Welcome', async () => {
    const h = new PendingWelcomesHarness();
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    const key = hex(new Uint8Array(EPOCH_ID_LENGTH).fill(7));
    const originalPayload = h.pendingWelcomes.get(key)!.body;
    const retainedBytes = h.pendingWelcomes.retainedBytes;

    const unsigned = welcomeFor(7);
    delete unsigned.signature;
    await h.evaluateAndApply(unsigned, { fromBuffer: false });
    h.signatureResult = {};
    const forged = welcomeFor(7);
    forged.eciesSealed = new Uint8Array([9, 9, 9]);
    await h.evaluateAndApply(forged, { fromBuffer: false });

    expect(h.pendingWelcomes.size).toBe(1);
    expect(h.pendingWelcomes.get(key)!.body).toEqual(originalPayload);
    expect(h.pendingWelcomes.retainedBytes).toBe(retainedBytes);
  });

  test('buffers the authenticated detached Welcome when the input mutates during validation', async () => {
    const h = new PendingWelcomesHarness();
    const message = welcomeFor(7);
    const pending = h.evaluateAndApply(message, { fromBuffer: false });
    message.welcomeEpochId!.fill(9);
    message.eciesSealed![0] = 0xff;
    await pending;

    const key = hex(new Uint8Array(EPOCH_ID_LENGTH).fill(7));
    const mutatedKey = hex(new Uint8Array(EPOCH_ID_LENGTH).fill(9));
    const retained = stubSerializer.deserializeSyncMessage(
      h.pendingWelcomes.get(key)!.body,
    );
    expect(h.pendingWelcomes.has(mutatedKey)).toBe(false);
    expect(retained.welcomeEpochId).toEqual(
      new Uint8Array(EPOCH_ID_LENGTH).fill(7),
    );
    expect(retained.eciesSealed).toEqual(new Uint8Array([1, 2, 3]));
  });

  test('evicts the oldest entry when the buffer is at capacity', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    // Fill the buffer to capacity with distinct epoch IDs.
    for (let i = 0; i < PENDING_WELCOMES_MAX_ENTRIES; i++) {
      await h.evaluateAndApply(welcomeFor(i + 1), { fromBuffer: false });
    }
    expect(h.pendingWelcomes.size).toBe(PENDING_WELCOMES_MAX_ENTRIES);
    const retainedBytesAtCapacity = h.pendingWelcomes.retainedBytes;
    // The oldest entry corresponds to epoch byte 1.
    const oldestKey = hex(new Uint8Array(EPOCH_ID_LENGTH).fill(1));
    expect(h.pendingWelcomes.has(oldestKey)).toBe(true);

    // One more push -- the oldest must be evicted, the newest must
    // be present.
    await h.evaluateAndApply(welcomeFor(PENDING_WELCOMES_MAX_ENTRIES + 1), {
      fromBuffer: false,
    });
    expect(h.pendingWelcomes.size).toBe(PENDING_WELCOMES_MAX_ENTRIES);
    expect(h.pendingWelcomes.retainedBytes).toBe(retainedBytesAtCapacity);
    expect(h.pendingWelcomes.retainedBytes).toBeLessThanOrEqual(
      PENDING_WELCOMES_MAX_RETAINED_BYTES,
    );
    expect(h.pendingWelcomes.has(oldestKey)).toBe(false);
    const newestKey = hex(
      new Uint8Array(EPOCH_ID_LENGTH).fill(
        PENDING_WELCOMES_MAX_ENTRIES + 1,
      ),
    );
    expect(h.pendingWelcomes.has(newestKey)).toBe(true);
  });

  test('discards entries past the TTL during drain without applying them', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    h.nowMs = 1000;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    expect(h.pendingWelcomes.size).toBe(1);

    // Advance the clock past the TTL.
    h.nowMs = 1000 + PENDING_WELCOMES_TTL_MS + 1;

    // Drain even though the user is now a reader: the stale entry
    // should be discarded outright rather than applied.
    await h.mergeReadersAddingLocal();
    expect(h.pendingWelcomes.size).toBe(0);
    expect(h.pendingWelcomes.retainedBytes).toBe(0);
    expect(h.appliedEpochs).toHaveLength(0);
  });

  test('leaves entries in the buffer when the user is still not in the readers ACL after drain', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    const retainedBytes = h.pendingWelcomes.retainedBytes;

    // Drain without flipping isReader true. The buffer entry must
    // remain so a later (correct) ACL merge can drain it.
    await h.drainPendingWelcomes();
    expect(h.pendingWelcomes.size).toBe(1);
    expect(h.pendingWelcomes.retainedBytes).toBe(retainedBytes);
    expect(h.appliedEpochs).toHaveLength(0);
  });

  test('buffer replay does not re-buffer on persistent not-in-readers-acl', async () => {
    // Regression: replaying a buffered Welcome through the same
    // not-in-readers-acl branch must not push it back into the
    // buffer, otherwise drains would loop forever on a still-stale
    // entry.
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    const sizeBefore = h.pendingWelcomes.size;
    const retainedBytesBefore = h.pendingWelcomes.retainedBytes;

    // Drain (still not a reader). The size must not change due to a
    // re-buffer; it stays the same because the original entry remains
    // parked.
    await h.drainPendingWelcomes();
    expect(h.pendingWelcomes.size).toBe(sizeBefore);
    expect(h.pendingWelcomes.retainedBytes).toBe(retainedBytesBefore);
  });
});


describe('pending Welcome byte view admission', () => {
  test.each([new Uint16Array([1]), new Uint8Array(0)])(
    'rejects an invalid body without replacing a retained Welcome',
    (body) => {
      const buffer = new PendingWelcomeBuffer();
      buffer.store('retained', new Uint8Array([1]), 0);
      expect(() => buffer.store('retained', body, 1)).toThrow();
      expect(buffer.get('retained')?.body).toEqual(new Uint8Array([1]));
      expect(buffer.retainedBytes).toBe(1);
    },
  );
});
