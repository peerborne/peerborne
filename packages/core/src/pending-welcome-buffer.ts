import type { CRDTSyncMessage } from './crdt-sync-message.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import { snapshotSyncMessageForContext } from './sync-message-context.js';
import { copyUnsharedUint8Array } from './utils.js';

export const PENDING_WELCOME_MAX_BODY_BYTES = 1024 * 1024;
export const PENDING_WELCOMES_MAX_RETAINED_BYTES = 4 * 1024 * 1024;
export const PENDING_WELCOMES_MAX_ENTRIES = 16;
export const PENDING_WELCOMES_TTL_MS = 5 * 60 * 1000;

if (PENDING_WELCOMES_MAX_RETAINED_BYTES < PENDING_WELCOME_MAX_BODY_BYTES) {
  throw new Error('Pending Welcome aggregate limit must admit one maximum-size body');
}

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
  readonly bufferedAtMs: number;
}

export interface PendingWelcomeStoreResult {
  readonly replaced: boolean;
  readonly evictedKeys: ReadonlyArray<string>;
}

/** Byte-bounded storage for authenticated Welcomes awaiting an ACL update. */
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
  public get(
    key: string,
  ): { readonly body: Uint8Array; readonly bufferedAtMs: number } | undefined {
    const entry = this._entries.get(key);
    if (entry === undefined) return undefined;
    return {
      body: new Uint8Array(entry.body),
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
  ): PendingWelcomeStoreResult {
    const detached = snapshotSyncMessageForContext<ChangesType, PublicKey>(
      message,
      'beekem-welcome-v2',
    );
    return this.store(
      key,
      serializer.serializeSyncMessage(detached),
      bufferedAtMs,
    );
  }

  /**
   * Store an owned copy of a non-empty Uint8Array, refreshing duplicate recency
   * and evicting oldest
   * entries until both count and aggregate-byte limits admit the new body.
   * Validation and copying happen before replacement, so a rejected duplicate
   * cannot erase a previously retained Welcome.
   */
  public store(
    key: string,
    body: unknown,
    bufferedAtMs: number,
  ): PendingWelcomeStoreResult {
    if (key.length === 0) {
      throw new TypeError('Pending BeeKEM Welcome key must not be empty');
    }
    if (!Number.isSafeInteger(bufferedAtMs) || bufferedAtMs < 0) {
      throw new TypeError('Pending BeeKEM Welcome timestamp is invalid');
    }
    let bodyLength: number;
    try {
      bodyLength = Reflect.apply(getByteLength, body, []);
    } catch {
      throw new TypeError('Pending BeeKEM Welcome body must be a Uint8Array');
    }
    if (bodyLength > PENDING_WELCOME_MAX_BODY_BYTES) {
      throw new PendingWelcomeBodyLimitError();
    }
    const stableBody = copyUnsharedUint8Array(
      body,
      1,
      PENDING_WELCOME_MAX_BODY_BYTES,
      'Pending BeeKEM Welcome body',
    );

    const replaced = this.delete(key);
    const evictedKeys: string[] = [];
    while (
      this._entries.size >= PENDING_WELCOMES_MAX_ENTRIES ||
      this._retainedBytes + stableBody.byteLength >
        PENDING_WELCOMES_MAX_RETAINED_BYTES
    ) {
      const oldestKey = this._entries.keys().next().value;
      if (oldestKey === undefined) {
        throw new Error('Pending BeeKEM Welcome limits are inconsistent');
      }
      this.delete(oldestKey);
      evictedKeys.push(oldestKey);
    }

    this._entries.set(key, { body: stableBody, bufferedAtMs });
    this._retainedBytes += stableBody.byteLength;
    return { replaced, evictedKeys };
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
