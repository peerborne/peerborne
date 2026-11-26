import type {
  CRDTReaderChangeNode,
  CRDTWriterChangeNode,
} from './crdt-change-node.js';

/** Held ACL changes one signer may keep in a document. */
export const MAX_HELD_ACL_CHANGES_PER_SIGNER = 64;
/** Serialized bytes of held ACL changes one signer may keep in a document. */
export const MAX_HELD_ACL_BYTES_PER_SIGNER = 4 * 1024 * 1024;
/** Held ACL changes a document keeps across all signers. */
export const MAX_HELD_ACL_CHANGES = 256;
/** Serialized bytes of held ACL changes a document keeps across all signers. */
export const MAX_HELD_ACL_BYTES = 16 * 1024 * 1024;

export type HeldACLKind = CRDTWriterChangeNode | CRDTReaderChangeNode;

export interface HeldACLChange<ChangesType> {
  readonly cid: string;
  readonly kind: HeldACLKind;
  readonly changes: ChangesType;
  readonly signer: string;
  readonly byteLength: number;
  ready?: () => boolean;
}

/**
 * ACL changes that arrived before the history they depend on, outside the
 * live ACL. Each signer holds a bounded number of changes and bytes, and the
 * document a larger bound across signers. Past a bound, the signer holding the
 * most changes or bytes gives up its oldest change, so one signer cannot evict
 * another signer's changes before its own.
 */
export class HeldACLChanges<ChangesType> {
  private readonly _entries = new Map<string, HeldACLChange<ChangesType>>();
  private readonly _signers = new Map<
    string,
    { count: number; bytes: number }
  >();
  private _bytes = 0;

  get size(): number {
    return this._entries.size;
  }

  has(cid: string): boolean {
    return this._entries.has(cid);
  }

  get(cid: string): HeldACLChange<ChangesType> | undefined {
    return this._entries.get(cid);
  }

  /** Hold `entry`, returning the CIDs given up, which may include its own. */
  hold(entry: HeldACLChange<ChangesType>): string[] {
    const existing = this._entries.get(entry.cid);
    if (existing !== undefined) {
      existing.ready = entry.ready;
      return [];
    }
    if (
      entry.byteLength > MAX_HELD_ACL_BYTES_PER_SIGNER ||
      !Number.isSafeInteger(entry.byteLength) ||
      entry.byteLength < 0
    ) {
      return [entry.cid];
    }
    this._entries.set(entry.cid, entry);
    this._bytes += entry.byteLength;
    const usage = this._signers.get(entry.signer) ?? { count: 0, bytes: 0 };
    usage.count++;
    usage.bytes += entry.byteLength;
    this._signers.set(entry.signer, usage);

    const evicted: string[] = [];
    while (
      usage.count > MAX_HELD_ACL_CHANGES_PER_SIGNER ||
      usage.bytes > MAX_HELD_ACL_BYTES_PER_SIGNER
    ) {
      evicted.push(this._evictOldest(entry.signer));
    }
    while (this._entries.size > MAX_HELD_ACL_CHANGES) {
      evicted.push(this._evictOldest(this._largestSigner('count')));
    }
    while (this._bytes > MAX_HELD_ACL_BYTES) {
      evicted.push(this._evictOldest(this._largestSigner('bytes')));
    }
    return evicted;
  }

  release(cid: string): HeldACLChange<ChangesType> | undefined {
    const entry = this._entries.get(cid);
    if (entry === undefined) return undefined;
    this._entries.delete(cid);
    this._bytes -= entry.byteLength;
    const usage = this._signers.get(entry.signer)!;
    usage.count--;
    usage.bytes -= entry.byteLength;
    if (usage.count === 0) this._signers.delete(entry.signer);
    return entry;
  }

  /** Held changes of `kind` whose dependencies may have arrived, oldest first. */
  ready(kind: HeldACLKind): HeldACLChange<ChangesType>[] {
    const ready: HeldACLChange<ChangesType>[] = [];
    for (const entry of this._entries.values()) {
      if (entry.kind === kind && entry.ready?.() !== false) ready.push(entry);
    }
    return ready;
  }

  clear(): void {
    this._entries.clear();
    this._signers.clear();
    this._bytes = 0;
  }

  private _largestSigner(measure: 'count' | 'bytes'): string {
    let largest: string | undefined;
    let largestUsage = -1;
    for (const [signer, usage] of this._signers) {
      if (usage[measure] > largestUsage) {
        largest = signer;
        largestUsage = usage[measure];
      }
    }
    return largest!;
  }

  private _evictOldest(signer: string): string {
    for (const entry of this._entries.values()) {
      if (entry.signer === signer) {
        this.release(entry.cid);
        return entry.cid;
      }
    }
    throw new Error('Held ACL signer has no changes');
  }
}
