import type { CRDTSyncMessage } from './crdt-sync-message.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import { snapshotSyncMessageForContext } from './sync-message-context.js';
import { copyUnsharedUint8Array } from './utils.js';

export const PENDING_WELCOME_MAX_BODY_BYTES = 1024 * 1024;
export const PENDING_WELCOMES_MAX_RETAINED_BYTES = 4 * 1024 * 1024;
export const PENDING_WELCOMES_MAX_ENTRIES = 16;
export const PENDING_WELCOMES_TTL_MS = 5 * 60 * 1000;

const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), 'byteLength',
)?.get;
if (typeof typedArrayByteLength !== 'function') {
  throw new Error('PendingWelcomeBuffer requires TypedArray.byteLength');
}
const getByteLength = typedArrayByteLength;

export class PendingWelcomeBodyLimitError extends RangeError {
  constructor() {
    super(`Pending BeeKEM Welcome body exceeds ${PENDING_WELCOME_MAX_BODY_BYTES} bytes`);
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
  private readonly _entries = new Map<string, PendingWelcomeEntry>();
  private _retainedBytes = 0;

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
  public storeMessage<ChangesType, PublicKey>(
    key: string,
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    serializer: SyncMessageSerializer<ChangesType, PublicKey>,
    bufferedAtMs: number,
    authenticated: boolean,
  ): PendingWelcomeStoreResult {
    if (this._entries.has(key) && !authenticated) {
      return { stored: false, replaced: false, evictedKeys: [] };
    }
    const detached = snapshotSyncMessageForContext<ChangesType, PublicKey>(
      message,
      'beekem-welcome-v1',
    );
    return this.store(
      key,
      serializer.serializeSyncMessage(detached),
      bufferedAtMs,
      authenticated,
    );
  }

  /**
   * Store an owned copy, refreshing duplicate recency and evicting entries
   * until both count and aggregate-byte limits admit the new body. Eviction
   * takes the oldest unauthenticated entry first, then the oldest entry. An
   * unauthenticated Welcome never replaces a buffered one for the same key:
   * it may be a forged copy of a genuine Welcome that could not be verified
   * yet either. Validation and copying happen before replacement, so a
   * rejected duplicate cannot erase a previously retained Welcome.
   */
  public store(
    key: string,
    body: unknown,
    bufferedAtMs: number,
    authenticated: boolean,
  ): PendingWelcomeStoreResult {
    if (key.length === 0) {
      throw new TypeError('Pending BeeKEM Welcome key must not be empty');
    }
    if (!Number.isSafeInteger(bufferedAtMs) || bufferedAtMs < 0) {
      throw new TypeError('Pending BeeKEM Welcome timestamp is invalid');
    }
    if (Reflect.apply(getByteLength, body, []) > PENDING_WELCOME_MAX_BODY_BYTES) {
      throw new PendingWelcomeBodyLimitError();
    }
    const stableBody = copyUnsharedUint8Array(
      body,
      1,
      PENDING_WELCOME_MAX_BODY_BYTES,
      'Pending BeeKEM Welcome body',
    );

    if (this._entries.has(key) && !authenticated) {
      return { stored: false, replaced: false, evictedKeys: [] };
    }

    const replaced = this.delete(key);
    const evictedKeys: string[] = [];
    while (
      this._entries.size >= PENDING_WELCOMES_MAX_ENTRIES ||
      this._retainedBytes + stableBody.byteLength >
        PENDING_WELCOMES_MAX_RETAINED_BYTES
    ) {
      const evictKey = this._evictionCandidate();
      if (evictKey === undefined) {
        throw new Error('Pending BeeKEM Welcome limits are inconsistent');
      }
      this.delete(evictKey);
      evictedKeys.push(evictKey);
    }

    this._entries.set(key, { body: stableBody, authenticated, bufferedAtMs });
    this._retainedBytes += stableBody.byteLength;
    return { stored: true, replaced, evictedKeys };
  }

  private _evictionCandidate(): string | undefined {
    for (const [key, entry] of this._entries) {
      if (!entry.authenticated) return key;
    }
    return this._entries.keys().next().value;
  }

  /** Delete exactly one entry and subtract exactly the bytes it owned. */
  public delete(key: string): boolean {
    const entry = this._entries.get(key);
    if (entry === undefined) return false;
    if (!this._entries.delete(key)) return false;
    this._retainedBytes -= entry.body.byteLength;
    if (this._retainedBytes < 0) {
      throw new Error('Pending BeeKEM Welcome byte accounting underflowed');
    }
    return true;
  }
}
