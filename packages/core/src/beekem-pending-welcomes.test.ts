import { describe, expect, test } from '@jest/globals';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import {
  evaluateBeeKEMWelcome,
  WelcomeValidationDeps,
} from './beekem-welcome-handler.js';
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
 *   - `_bufferPendingWelcome`: keyed by `hex(welcomeEpochId)`, capacity
 *     16, oldest-evicted-on-overflow (Map iteration order).
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
    return new TextEncoder().encode(JSON.stringify(message));
  },
  deserializeSyncMessage(_data: Uint8Array) {
    throw new Error('not used in evaluation');
  },
} as unknown as SyncMessageSerializer<ChangesType, PublicKey>;

const PENDING_WELCOMES_MAX_ENTRIES = 16;
const PENDING_WELCOMES_TTL_MS = 5 * 60 * 1000;

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
  pendingWelcomes = new Map<
    string,
    {
      message: CRDTSyncMessage<ChangesType, PublicKey>;
      bufferedAtMs: number;
    }
  >();
  appliedEpochs: Uint8Array[] = [];
  /** Local clock; tests can advance it to exercise TTL. */
  nowMs = 0;
  /** Whether the local user is currently in the readers ACL. */
  isReader = false;

  private depsFor(): WelcomeValidationDeps<ChangesType, PublicKey> {
    return {
      documentPath: '/doc/welcome',
      localUserPublicKey: { id: 'me' },
      serializePublicKey: async (pk) => pk.id,
      isReader: async () => this.isReader,
      // Welcomes are unconditionally writer-authenticated; the test
      // messages below always carry a `signature` field so this stub
      // verifier just returns `true` for any signed payload.
      verifyWriterSignature: async () => true,
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
        message.welcomeEpochId &&
        message.welcomeEpochId.length > 0
      ) {
        this.bufferPendingWelcome(message);
      }
      return false;
    }
    this.appliedEpochs.push(message.welcomeEpochId as Uint8Array);
    return true;
  }

  /** Mirror of `_bufferPendingWelcome`. */
  bufferPendingWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): void {
    const epochId = message.welcomeEpochId;
    if (!epochId || epochId.length === 0) return;
    const key = hex(epochId);
    this.pendingWelcomes.delete(key);
    if (this.pendingWelcomes.size >= PENDING_WELCOMES_MAX_ENTRIES) {
      const oldestKey = this.pendingWelcomes.keys().next().value;
      if (oldestKey !== undefined) this.pendingWelcomes.delete(oldestKey);
    }
    this.pendingWelcomes.set(key, { message, bufferedAtMs: this.nowMs });
  }

  /** Mirror of `_drainPendingWelcomes`. */
  async drainPendingWelcomes(): Promise<void> {
    if (this.pendingWelcomes.size === 0) return;
    const now = this.nowMs;
    const entries = Array.from(this.pendingWelcomes.entries());
    for (const [key, entry] of entries) {
      if (now - entry.bufferedAtMs > PENDING_WELCOMES_TTL_MS) {
        this.pendingWelcomes.delete(key);
        continue;
      }
      const accepted = await this.evaluateAndApply(entry.message, {
        fromBuffer: true,
      });
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
    welcomeEpochId: new Uint8Array(32).fill(epochByte),
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
  });

  test('drains and applies buffered Welcome when readers ACL adds the local user', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    expect(h.pendingWelcomes.size).toBe(1);

    await h.mergeReadersAddingLocal();

    expect(h.pendingWelcomes.size).toBe(0);
    expect(h.appliedEpochs).toHaveLength(1);
    expect(Array.from(h.appliedEpochs[0])).toEqual(
      Array.from(new Uint8Array(32).fill(7)),
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

  test('coalesces duplicate Welcomes for the same epoch into a single entry', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });
    expect(h.pendingWelcomes.size).toBe(1);
  });

  test('evicts the oldest entry when the buffer is at capacity', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    // Fill the buffer to capacity with distinct epoch IDs.
    for (let i = 0; i < PENDING_WELCOMES_MAX_ENTRIES; i++) {
      await h.evaluateAndApply(welcomeFor(i + 1), { fromBuffer: false });
    }
    expect(h.pendingWelcomes.size).toBe(PENDING_WELCOMES_MAX_ENTRIES);
    // The oldest entry corresponds to epoch byte 1.
    const oldestKey = hex(new Uint8Array(32).fill(1));
    expect(h.pendingWelcomes.has(oldestKey)).toBe(true);

    // One more push -- the oldest must be evicted, the newest must
    // be present.
    await h.evaluateAndApply(welcomeFor(PENDING_WELCOMES_MAX_ENTRIES + 1), {
      fromBuffer: false,
    });
    expect(h.pendingWelcomes.size).toBe(PENDING_WELCOMES_MAX_ENTRIES);
    expect(h.pendingWelcomes.has(oldestKey)).toBe(false);
    const newestKey = hex(
      new Uint8Array(32).fill(PENDING_WELCOMES_MAX_ENTRIES + 1),
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
    expect(h.appliedEpochs).toHaveLength(0);
  });

  test('leaves entries in the buffer when the user is still not in the readers ACL after drain', async () => {
    const h = new PendingWelcomesHarness();
    h.isReader = false;
    await h.evaluateAndApply(welcomeFor(7), { fromBuffer: false });

    // Drain without flipping isReader true. The buffer entry must
    // remain so a later (correct) ACL merge can drain it.
    await h.drainPendingWelcomes();
    expect(h.pendingWelcomes.size).toBe(1);
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

    // Drain (still not a reader). The size must not change due to a
    // re-buffer; it stays the same because the original entry remains
    // parked.
    await h.drainPendingWelcomes();
    expect(h.pendingWelcomes.size).toBe(sizeBefore);
  });
});
