import { BloomFilterCRDT } from './bloom-filter-crdt.js';
import { bloomFilterUpdateV1 } from '@peerborne/core';

/**
 * Peer filter state tracked per remote peer.
 */
export interface PeerFilterState {
  peerId: string;
  filter: BloomFilterCRDT;
  lastUpdated: number;
}

/**
 * Configuration for BloomFilterGossip.
 */
export interface BloomFilterGossipConfig {
  /** GossipSub topic for bloom filter exchange. */
  topic: string;
  /** Filter size in bits (default: 65536). */
  filterSizeInBits: number;
  /** Number of hash functions (default: 7). */
  numHashFunctions: number;
  /** Republish interval in ms (default: 30000). */
  republishIntervalMs: number;
}

const DEFAULT_CONFIG: BloomFilterGossipConfig = {
  topic: bloomFilterUpdateV1,
  filterSizeInBits: 65536,
  numHashFunctions: 7,
  republishIntervalMs: 30000,
};

/**
 * Manages GossipSub-based replication of Bloom filters between peers.
 *
 * Each peer maintains:
 * - A local filter containing terms from their own indexed documents
 * - Per-peer filters received from remote peers
 * - A merged "network" filter combining all known peer filters
 */
export class BloomFilterGossip {
  private _localFilter: BloomFilterCRDT;
  private _peerFilters: Map<string, PeerFilterState>;
  private _config: BloomFilterGossipConfig;
  private _republishTimer: ReturnType<typeof setInterval> | null;
  private _started: boolean;

  // Callbacks for pub/sub integration (to be wired to actual GossipSub)
  private _publishFn: ((topic: string, data: Uint8Array) => Promise<void>) | null;
  private _subscribeFn: ((topic: string, handler: (peerId: string, data: Uint8Array) => void) => void) | null;
  private _unsubscribeFn: ((topic: string) => void) | null;

  constructor(config?: Partial<BloomFilterGossipConfig>) {
    this._config = { ...DEFAULT_CONFIG, ...config };
    this._localFilter = new BloomFilterCRDT(
      this._config.filterSizeInBits,
      this._config.numHashFunctions,
    );
    this._peerFilters = new Map();
    this._republishTimer = null;
    this._started = false;
    this._publishFn = null;
    this._subscribeFn = null;
    this._unsubscribeFn = null;
  }

  /** The local peer's Bloom filter. */
  get localFilter(): BloomFilterCRDT { return this._localFilter; }

  /** All known peer filters. */
  get peerFilters(): Map<string, PeerFilterState> { return this._peerFilters; }

  /**
   * Wire up pub/sub functions. Must be called before start().
   */
  setPubSub(
    publishFn: (topic: string, data: Uint8Array) => Promise<void>,
    subscribeFn: (topic: string, handler: (peerId: string, data: Uint8Array) => void) => void,
    unsubscribeFn: (topic: string) => void,
  ): void {
    this._publishFn = publishFn;
    this._subscribeFn = subscribeFn;
    this._unsubscribeFn = unsubscribeFn;
  }

  /**
   * Start gossiping: subscribe to topic and begin periodic republish.
   */
  start(): void {
    if (this._started) return;
    if (!this._publishFn || !this._subscribeFn || !this._unsubscribeFn) {
      throw new Error('setPubSub() must be called before start()');
    }
    this._started = true;

    this._subscribeFn(this._config.topic, (peerId, data) => {
      this.onReceiveFilter(peerId, data);
    });

    this._republishTimer = setInterval(() => {
      this.publishFilter().catch((err) => {
        console.warn('BloomFilterGossip: periodic publish failed', err);
      });
    }, this._config.republishIntervalMs);
    // A background gossip timer should not keep a Node process alive on its
    // own. Browser timers are numeric and do not expose `unref()`.
    const timer = this._republishTimer as ReturnType<typeof setInterval> & {
      unref?: () => void;
    };
    timer.unref?.();
  }

  /**
   * Stop gossiping: unsubscribe and clear timer.
   */
  stop(): void {
    if (!this._started) return;
    this._started = false;

    if (this._unsubscribeFn) {
      this._unsubscribeFn(this._config.topic);
    }

    if (this._republishTimer !== null) {
      clearInterval(this._republishTimer);
      this._republishTimer = null;
    }
  }

  /**
   * Add a term to the local filter.
   */
  addTerm(term: string): void {
    this._localFilter.add(term);
  }

  /**
   * Publish the local filter to the GossipSub topic.
   */
  async publishFilter(): Promise<void> {
    if (!this._publishFn) return;
    const data = this._localFilter.serialize();
    await this._publishFn(this._config.topic, data);
  }

  /**
   * Handle a received filter from a remote peer.
   * Merges into the peer's tracked state.
   */
  onReceiveFilter(peerId: string, data: Uint8Array): void {
    let received: BloomFilterCRDT;
    try {
      received = BloomFilterCRDT.deserialize(
        data,
        this._config.filterSizeInBits,
        this._config.numHashFunctions,
      );
    } catch {
      console.warn(`BloomFilterGossip: ignoring malformed filter from ${peerId}`);
      return;
    }

    const existing = this._peerFilters.get(peerId);
    if (existing) {
      existing.filter.merge(received);
      existing.lastUpdated = Date.now();
    } else {
      this._peerFilters.set(peerId, {
        peerId,
        filter: received,
        lastUpdated: Date.now(),
      });
    }
  }

  /**
   * Query which peers might have documents matching the given terms.
   * Returns peer IDs whose filters indicate a possible match for ALL terms.
   */
  queryPeers(terms: string[]): string[] {
    const matching: string[] = [];
    for (const [peerId, state] of this._peerFilters) {
      const allMatch = terms.every(term => state.filter.has(term));
      if (allMatch) {
        matching.push(peerId);
      }
    }
    return matching;
  }

  /**
   * Get a merged filter combining all known peer filters.
   * Useful for checking if any peer in the network has a term.
   */
  getMergedFilter(): BloomFilterCRDT {
    const merged = new BloomFilterCRDT(
      this._config.filterSizeInBits,
      this._config.numHashFunctions,
    );
    merged.merge(this._localFilter);
    for (const [, state] of this._peerFilters) {
      merged.merge(state.filter);
    }
    return merged;
  }
}
