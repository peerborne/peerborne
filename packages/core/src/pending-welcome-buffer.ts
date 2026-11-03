import {
  canReplacePendingWelcome,
  firstUnauthenticatedEntry,
} from './policy/maintenance.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import { snapshotSyncMessageForContext } from './sync-message-context.js';
import {
  copyUnsharedUint8Array,
  unsharedUint8ArrayByteLength,
  MAX_SHARED_PROTOCOL_REQUEST_BYTES,
} from './utils.js';
import {
  advancePendingWelcomeClock,
  canAdmitPendingWelcome,
  insertPendingWelcomeValue,
  pendingWelcomeBudget,
  planPendingWelcomeAdmission,
  planPendingWelcomeExpiry,
  planPendingWelcomeRemoval,
  retainPendingWelcomeValues,
  type PendingWelcomeMetadata,
} from './policy/welcome-admission.js';

/**
 * A pending Welcome may be as large as any Welcome the live receive path
 * accepts: senders bound the serialized Welcome by the shared-protocol request
 * limit, so a smaller cap here would permanently drop valid Welcomes for large
 * groups whenever they arrive before the readers-ACL update.
 */
export const PENDING_WELCOME_MAX_BODY_BYTES = MAX_SHARED_PROTOCOL_REQUEST_BYTES;
export const PENDING_WELCOMES_MAX_RETAINED_BYTES =
  2 * PENDING_WELCOME_MAX_BODY_BYTES;
export const PENDING_WELCOMES_MAX_ENTRIES = 16;
export const PENDING_WELCOMES_TTL_MS = 5 * 60 * 1000;

if (PENDING_WELCOMES_MAX_RETAINED_BYTES < PENDING_WELCOME_MAX_BODY_BYTES) {
  throw new Error(
    'Pending Welcome aggregate limit must admit one maximum-size body',
  );
}

const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
)?.get;
if (typeof typedArrayByteLength !== 'function') {
  throw new Error('PendingWelcomeBuffer requires TypedArray.byteLength');
}
const getByteLength = typedArrayByteLength;

export class PendingWelcomeBodyLimitError extends RangeError {
  constructor() {
    super(
      `Pending BeeKEM Welcome body exceeds ${PENDING_WELCOME_MAX_BODY_BYTES} bytes`,
    );
    this.name = 'PendingWelcomeBodyLimitError';
  }
}

interface PendingWelcomeEntry {
  readonly body: Uint8Array;
  readonly authenticated: boolean;
  readonly bufferedAtMs: number;
}

export interface PendingWelcomeStoreResult {
  readonly stored: boolean;
  readonly replaced: boolean;
  readonly evictedKeys: ReadonlyArray<string>;
}

/** Byte-bounded storage for Welcomes awaiting an ACL update. */
export class PendingWelcomeBuffer {
  private _entries = new Map<string, PendingWelcomeEntry>();
  private _retainedBytes = 0;
  private _observedAtMs = 0;

  public get size(): number {
    return this._entries.size;
  }

  public get retainedBytes(): number {
    return this._retainedBytes;
  }

  public has(key: string): boolean {
    return this._entries.has(key);
  }

  /** Return a detached entry so replay code cannot mutate retained bytes. */
  public get(key: string):
    | {
        readonly body: Uint8Array;
        readonly authenticated: boolean;
        readonly bufferedAtMs: number;
      }
    | undefined {
    const entry = this._entries.get(key);
    if (entry === undefined) return undefined;
    return {
      body: new Uint8Array(entry.body),
      authenticated: entry.authenticated,
      bufferedAtMs: entry.bufferedAtMs,
    };
  }

  public keysSnapshot(): string[] {
    return Array.from(this._entries.keys());
  }

  /** Canonically serialize a detached Welcome, then retain its bounded body. */
  public storeMessage<ChangesType>(
    key: string,
    message: CRDTSyncMessage<ChangesType>,
    serializer: SyncMessageSerializer<ChangesType>,
    bufferedAtMs: number,
    authenticated: boolean,
  ): PendingWelcomeStoreResult {
    validateAdmissionInput(key, bufferedAtMs, authenticated);
    if (!canReplacePendingWelcome(this._entries.has(key), authenticated)) {
      return { stored: false, replaced: false, evictedKeys: [] };
    }
    if (!authenticated) {
      if (
        this._entries.size >= PENDING_WELCOMES_MAX_ENTRIES &&
        firstUnauthenticatedEntry(
          [...this._entries.values()].map((entry) => entry.authenticated),
        ) === -1
      ) {
        return { stored: false, replaced: false, evictedKeys: [] };
      }
      const budget = pendingWelcomeBudget(this._metadata(), key);
      if (
        !canAdmitPendingWelcome(
          false,
          false,
          budget.protectedCount,
          budget.protectedBytes,
          1,
          PENDING_WELCOMES_MAX_ENTRIES,
          PENDING_WELCOMES_MAX_RETAINED_BYTES,
        )
      ) {
        return { stored: false, replaced: false, evictedKeys: [] };
      }
    }
    const detached = snapshotSyncMessageForContext<ChangesType>(
      message,
      'beekem-welcome-v2',
    );
    return this.store(
      key,
      serializer.serializeSyncMessage(detached),
      bufferedAtMs,
      authenticated,
    );
  }

  /**
   * Store an owned copy of a non-empty Uint8Array, refreshing duplicate
   * recency and evicting entries until both count and aggregate-byte limits
   * admit the new body. Eviction takes the oldest unauthenticated entry
   * first. Only authenticated arrivals may then evict authenticated entries.
   * An unauthenticated Welcome never replaces
   * a buffered one for the same key: it may be a forged copy of a genuine
   * Welcome that could not be verified yet either. Validation and copying
   * happen before replacement. Rejected admissions do not copy body bytes
   * or change any retained entry. Receipt times use a nondecreasing observed
   * clock so backward samples cannot backdate a new Welcome.
   */
  public store(
    key: string,
    body: unknown,
    bufferedAtMs: number,
    authenticated: boolean,
  ): PendingWelcomeStoreResult {
    validateAdmissionInput(key, bufferedAtMs, authenticated);
    let bodyLength: number;
    try {
      bodyLength = Reflect.apply(getByteLength, body, []);
    } catch {
      throw new TypeError('Pending BeeKEM Welcome body must be a Uint8Array');
    }
    if (bodyLength > PENDING_WELCOME_MAX_BODY_BYTES) {
      throw new PendingWelcomeBodyLimitError();
    }
    unsharedUint8ArrayByteLength(
      body,
      1,
      PENDING_WELCOME_MAX_BODY_BYTES,
      'Pending BeeKEM Welcome body',
    );

    if (!canReplacePendingWelcome(this._entries.has(key), authenticated)) {
      return { stored: false, replaced: false, evictedKeys: [] };
    }

    const plan = planPendingWelcomeAdmission(
      this._metadata(),
      key,
      bodyLength,
      authenticated,
      PENDING_WELCOMES_MAX_ENTRIES,
      PENDING_WELCOMES_MAX_RETAINED_BYTES,
    );
    if (!plan.admitted) {
      return { stored: false, replaced: false, evictedKeys: [] };
    }
    const stableBody = copyUnsharedUint8Array(
      body,
      1,
      PENDING_WELCOME_MAX_BODY_BYTES,
      'Pending BeeKEM Welcome body',
    );
    const observedAtMs = advancePendingWelcomeClock(
      this._observedAtMs,
      bufferedAtMs,
    );
    const retained = retainPendingWelcomeValues(this._entries, plan.kept);
    this._entries = insertPendingWelcomeValue(retained, key, {
      body: stableBody,
      authenticated,
      bufferedAtMs: observedAtMs,
    });
    this._retainedBytes = plan.retainedBytes;
    this._observedAtMs = observedAtMs;
    return {
      stored: true,
      replaced: plan.replaced,
      evictedKeys: plan.evictedKeys,
    };
  }

  /** Remove expired metadata before a replay path copies any retained body. */
  public pruneExpired(now: number): readonly string[] {
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('Pending BeeKEM Welcome clock is invalid');
    }
    const observedAtMs = advancePendingWelcomeClock(this._observedAtMs, now);
    if (this._entries.size === 0) {
      this._observedAtMs = observedAtMs;
      return [];
    }
    const plan = planPendingWelcomeExpiry(
      this._metadata(),
      [...this._entries.values()].map((entry) => entry.bufferedAtMs),
      observedAtMs,
      PENDING_WELCOMES_TTL_MS,
    );
    if (plan.expiredKeys.length !== 0) {
      const retained = retainPendingWelcomeValues(this._entries, plan.kept);
      this._entries = retained;
      this._retainedBytes = plan.retainedBytes;
    }
    this._observedAtMs = observedAtMs;
    return plan.expiredKeys;
  }

  private _metadata(): PendingWelcomeMetadata[] {
    return [...this._entries].map(([key, entry]) => ({
      key,
      bytes: entry.body.byteLength,
      authenticated: entry.authenticated,
    }));
  }

  /** Delete exactly one entry and subtract exactly the bytes it owned. */
  public delete(key: string): boolean {
    if (!this._entries.has(key)) return false;
    const plan = planPendingWelcomeRemoval(this._metadata(), key);
    this._entries = retainPendingWelcomeValues(this._entries, plan.kept);
    this._retainedBytes = plan.retainedBytes;
    return plan.removed;
  }
}

function validateAdmissionInput(
  key: string,
  bufferedAtMs: number,
  authenticated: boolean,
): void {
  if (typeof key !== 'string' || key.length === 0) {
    throw new TypeError(
      'Pending BeeKEM Welcome key must be a non-empty string',
    );
  }
  if (!Number.isSafeInteger(bufferedAtMs) || bufferedAtMs < 0) {
    throw new TypeError('Pending BeeKEM Welcome timestamp is invalid');
  }
  if (typeof authenticated !== 'boolean') {
    throw new TypeError(
      'Pending BeeKEM Welcome authentication flag must be a boolean',
    );
  }
}
