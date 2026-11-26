/**
 * Automatic catch-up ("anti-entropy") for default, non-coordinated sync.
 *
 * A document asks members for missed updates with the existing signed sync
 * request. It asks when it opens, when a peer subscribed to its topic
 * connects, when the CRDT buffers changes whose dependencies are missing,
 * when a frame names a change that cannot be fetched, when a member
 * advertises a head it does not hold, and periodically with jitter. When a
 * detected gap outlives a request, it loads through the authenticated V4
 * load path, preferring a writer that advertised newer state.
 */

/** Why a catch-up request was scheduled. */
export type AntiEntropyTrigger =
  | 'open'
  | 'peer-subscribed'
  | 'pending-changes'
  | 'missing-change'
  | 'advertised-state'
  | 'periodic';

/** Tuning for automatic catch-up. Every field is optional in `PeerborneConfig`. */
export interface AntiEntropyConfig {
  /** Run automatic catch-up for default documents. Default: true. */
  enabled: boolean;
  /**
   * Mean delay between periodic requests. Each delay is drawn uniformly from
   * two thirds to four thirds of this value. Default: 45 000 ms (30-60 s).
   */
  intervalMs: number;
  /**
   * Minimum delay between this document's requests. It doubles while a
   * detected gap persists, up to `intervalMs`. Default: 5000 ms; at least the
   * 2000 ms sync-request rate limit.
   */
  minRequestIntervalMs: number;
  /**
   * One peer triggers at most one request per kind of signal within this
   * window. Default: 30 000 ms.
   */
  peerCooldownMs: number;
  /** Load once a detected gap outlives a request by this long. Default: 15 000 ms. */
  loadAfterMs: number;
  /**
   * Minimum delay between this document's loads. It doubles after each load
   * that leaves the gap open, up to 16 times. Default: 60 000 ms.
   */
  loadIntervalMs: number;
}

export const defaultAntiEntropyConfig: Readonly<AntiEntropyConfig> =
  Object.freeze({
    enabled: true,
    intervalMs: 45_000,
    minRequestIntervalMs: 5_000,
    peerCooldownMs: 30_000,
    loadAfterMs: 15_000,
    loadIntervalMs: 60_000,
  });

const MIN_REQUEST_INTERVAL_MS = 2_000;

/**
 * How long ordinary sync waits for the change blocks a frame names but does
 * not carry. Changes still missing then are reported to catch-up.
 */
export const MISSING_CHANGE_FETCH_TIMEOUT_MS = 10_000;
const MAX_DELAY_MS = 24 * 60 * 60 * 1000;

/**
 * Validate a partial configuration and merge it over the defaults.
 *
 * @throws {TypeError} If the value is not a plain object, a field is unknown,
 *   or `enabled` is not a boolean.
 * @throws {RangeError} If a delay is not an integer in range.
 */
export function resolveAntiEntropyConfig(
  overrides?: Partial<AntiEntropyConfig>,
): AntiEntropyConfig {
  if (overrides === undefined) return { ...defaultAntiEntropyConfig };
  if (
    typeof overrides !== 'object' ||
    overrides === null ||
    Array.isArray(overrides)
  ) {
    throw new TypeError('antiEntropy must be an object');
  }
  const config: AntiEntropyConfig = { ...defaultAntiEntropyConfig };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) continue;
    if (key === 'enabled') {
      if (typeof value !== 'boolean')
        throw new TypeError('antiEntropy.enabled must be a boolean');
      config.enabled = value;
      continue;
    }
    if (!(key in defaultAntiEntropyConfig))
      throw new TypeError(`Unknown antiEntropy option: ${key}`);
    if (
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      value < 1_000 ||
      value > MAX_DELAY_MS
    )
      throw new RangeError(
        `antiEntropy.${key} must be an integer from 1000 to ${MAX_DELAY_MS}`,
      );
    config[key as Exclude<keyof AntiEntropyConfig, 'enabled'>] = value;
  }
  if (config.minRequestIntervalMs < MIN_REQUEST_INTERVAL_MS)
    throw new RangeError(
      `antiEntropy.minRequestIntervalMs must be at least ${MIN_REQUEST_INTERVAL_MS}`,
    );
  if (config.minRequestIntervalMs > config.intervalMs)
    throw new RangeError(
      'antiEntropy.minRequestIntervalMs must not exceed intervalMs',
    );
  return config;
}

export type AntiEntropyRequestOutcome = 'sent' | 'rate-limited' | 'not-ready';
export type AntiEntropyLoadOutcome = 'loaded' | 'not-served' | 'failed';

/** Something automatic catch-up did. */
export type AntiEntropyEvent =
  | {
      readonly type: 'gap';
      readonly at: number;
      readonly trigger: AntiEntropyTrigger;
    }
  | {
      readonly type: 'request';
      readonly at: number;
      readonly triggers: readonly AntiEntropyTrigger[];
      readonly outcome: AntiEntropyRequestOutcome | 'failed';
    }
  | {
      readonly type: 'load';
      readonly at: number;
      readonly peer?: string;
      readonly outcome: AntiEntropyLoadOutcome;
    }
  | {
      readonly type: 'repaired';
      readonly at: number;
      readonly afterMs: number;
    };

/** A point-in-time view of automatic catch-up for one document. */
export interface AntiEntropyStatus {
  readonly enabled: boolean;
  readonly running: boolean;
  readonly phase: 'idle' | 'requesting' | 'loading';
  /** A detected gap (missing dependencies, unfetched changes or newer advertised state) is open. */
  readonly gap: boolean;
  readonly requests: number;
  readonly loads: number;
  /** Signals dropped by a cooldown, and periodic requests postponed by an equivalent request. */
  readonly suppressed: number;
  readonly lastRequestAt?: number;
  readonly lastLoad?: Readonly<{
    at: number;
    peer?: string;
    outcome: AntiEntropyLoadOutcome;
  }>;
  readonly nextRunAt?: number;
}

export type AntiEntropyHandler = (
  event: AntiEntropyEvent,
  status: AntiEntropyStatus,
) => void;

export const disabledAntiEntropyStatus: AntiEntropyStatus = Object.freeze({
  enabled: false,
  running: false,
  phase: 'idle',
  gap: false,
  requests: 0,
  loads: 0,
  suppressed: 0,
});

/** Document operations that automatic catch-up drives. */
export interface AntiEntropyHost {
  /** Publish one signed sync request through the existing rate limit. */
  request(): Promise<AntiEntropyRequestOutcome>;
  /** The CRDT holds remote changes waiting for missing dependencies. */
  hasPendingChanges(): boolean;
  /** The change CID is recorded locally. */
  isKnown(cid: string): boolean;
  /** An authenticated load can be attempted. */
  canLoad(): boolean;
  isConnected(peer: string): boolean;
  /** Run the authenticated load, preferring `peer`. */
  load(peer: string | undefined): Promise<boolean>;
}

export interface AntiEntropyClock {
  now(): number;
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  random(): number;
}

const systemClock: AntiEntropyClock = {
  now: () => Date.now(),
  setTimeout(callback, ms) {
    const handle = setTimeout(callback, ms) as unknown as { unref?(): void };
    handle.unref?.();
    return handle;
  },
  clearTimeout: (handle) =>
    clearTimeout(handle as ReturnType<typeof setTimeout>),
  random: () => Math.random(),
};

/**
 * Work shared by every document of one Peerborne instance: a token bucket for
 * catch-up requests and a bound on concurrent loads and per-peer load rate.
 */
export class AntiEntropyBudget {
  private tokens: number;
  private refilledAt?: number;
  private loads = 0;
  private readonly peerLoads = new Map<string, number>();

  constructor(
    private readonly requestsPerSecond = 4,
    private readonly burst = 16,
    private readonly maxConcurrentLoads = 1,
    private readonly peerLoadSpacingMs = 10_000,
  ) {
    this.tokens = burst;
  }

  takeRequest(now: number): boolean {
    if (this.refilledAt !== undefined && now > this.refilledAt) {
      this.tokens = Math.min(
        this.burst,
        this.tokens + ((now - this.refilledAt) * this.requestsPerSecond) / 1000,
      );
    }
    this.refilledAt = now;
    if (this.tokens < 1) return false;
    this.tokens--;
    return true;
  }

  acquireLoad(peer: string | undefined, now: number): (() => void) | undefined {
    if (this.loads >= this.maxConcurrentLoads) return;
    if (peer !== undefined) {
      const last = this.peerLoads.get(peer);
      if (last !== undefined && now - last < this.peerLoadSpacingMs) return;
      remember(this.peerLoads, peer, now, MAX_TRACKED_PEERS);
    }
    this.loads++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.loads--;
    };
  }
}

const budgets = new WeakMap<object, AntiEntropyBudget>();

/** The budget shared by the documents of `owner`, usually a Peerborne instance. */
export function antiEntropyBudgetFor(owner: object): AntiEntropyBudget {
  let budget = budgets.get(owner);
  if (budget === undefined) {
    budget = new AntiEntropyBudget();
    budgets.set(owner, budget);
  }
  return budget;
}

const MAX_TRACKED_PEERS = 256;
const MAX_ADVERTISED_PEERS = 32;
const MAX_MISSING_CHANGES = 64;
const MAX_REQUEST_BACKOFF = 8;
const MAX_LOAD_BACKOFF = 16;
const MAX_ADVERTISEMENT_CHECKS = 4;
const ADVERTISEMENT_CHECK_REFILL_MS = 2_000;
const GAP_TRIGGERS: readonly AntiEntropyTrigger[] = [
  'pending-changes',
  'missing-change',
  'advertised-state',
];

function remember<V>(
  map: Map<string, V>,
  key: string,
  value: V,
  limit: number,
): void {
  map.delete(key);
  map.set(key, value);
  if (map.size > limit) map.delete(map.keys().next().value!);
}

/** Schedules automatic catch-up for one open document. */
export class AntiEntropy {
  private closed = false;
  private timer: unknown;
  private timerAt?: number;
  private phase: AntiEntropyStatus['phase'] = 'idle';
  private readonly triggers = new Set<AntiEntropyTrigger>();
  private triggerReadyAt = 0;
  private periodicAt = 0;
  private periodicPostponed = false;
  private lastRequestAt?: number;
  private requestBackoff = 0;
  private readonly peerSignals = new Map<string, number>();
  private readonly advertised = new Map<
    string,
    { readonly head: string; readonly writer: boolean }
  >();
  private readonly missing = new Set<string>();
  private gapSince?: number;
  private gapRequestAt?: number;
  private gapTrigger: AntiEntropyTrigger = 'periodic';
  private loadNotBefore = 0;
  private loadBackoff = 1;
  private requests = 0;
  private loads = 0;
  private suppressed = 0;
  private lastLoad?: AntiEntropyStatus['lastLoad'];
  private advertisementTokens = MAX_ADVERTISEMENT_CHECKS;
  private advertisementCheckedAt?: number;
  private readonly closeCallbacks: Array<() => void> = [];

  constructor(
    private readonly config: AntiEntropyConfig,
    private readonly host: AntiEntropyHost,
    private readonly budget: AntiEntropyBudget,
    private readonly onEvent: (event: AntiEntropyEvent) => void = () => {},
    private readonly clock: AntiEntropyClock = systemClock,
  ) {}

  /** Schedule the first request and the periodic cycle. */
  start(): void {
    if (this.closed) return;
    this.periodicAt = this.clock.now() + this.jitteredInterval();
    this.trigger('open');
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearTimer();
    this.triggers.clear();
    this.advertised.clear();
    this.missing.clear();
    for (const callback of this.closeCallbacks.splice(0)) callback();
  }

  /** Run `callback` once when catch-up closes, for example to remove listeners. */
  onClose(callback: () => void): void {
    if (this.closed) callback();
    else this.closeCallbacks.push(callback);
  }

  status(): AntiEntropyStatus {
    return Object.freeze({
      enabled: true,
      running: !this.closed,
      phase: this.phase,
      gap: this.gapSince !== undefined,
      requests: this.requests,
      loads: this.loads,
      suppressed: this.suppressed,
      ...(this.lastRequestAt === undefined
        ? {}
        : { lastRequestAt: this.lastRequestAt }),
      ...(this.lastLoad === undefined ? {} : { lastLoad: this.lastLoad }),
      ...(this.timerAt === undefined ? {} : { nextRunAt: this.timerAt }),
    });
  }

  /** A peer subscribed to the document topic, for example after reconnecting. */
  peerSubscribed(peer: string): void {
    this.trigger('peer-subscribed', peer);
  }

  /** Remote state was applied; check whether the CRDT is waiting for dependencies. */
  remoteStateApplied(): void {
    if (this.closed) return;
    if (this.gapSince === undefined) {
      if (this.host.hasPendingChanges()) this.gap('pending-changes');
      return;
    }
    if (this.refreshGap() && this.host.hasPendingChanges())
      this.trigger('pending-changes');
    else this.arm();
  }

  /** A frame named a change that could not be fetched. */
  missingChange(cid: string): void {
    if (this.closed || this.host.isKnown(cid)) return;
    this.missing.delete(cid);
    this.missing.add(cid);
    if (this.missing.size > MAX_MISSING_CHANGES)
      this.missing.delete(this.missing.values().next().value!);
    this.gap('missing-change');
  }

  /**
   * Whether an advertisement of `head` by `peer` should be verified and
   * recorded. Callers ask before spending a signature verification; at most
   * four are admitted at once, refilled at one per two seconds.
   */
  admitAdvertisement(peer: string, head: string): boolean {
    if (this.closed || this.host.isKnown(head)) return false;
    if (this.advertised.get(peer)?.head === head) return false;
    const now = this.clock.now();
    if (!this.peerSignalAllowed('advertised-state', peer, now)) return false;
    if (this.advertisementCheckedAt !== undefined)
      this.advertisementTokens = Math.min(
        MAX_ADVERTISEMENT_CHECKS,
        this.advertisementTokens +
          Math.max(0, now - this.advertisementCheckedAt) /
            ADVERTISEMENT_CHECK_REFILL_MS,
      );
    this.advertisementCheckedAt = now;
    if (this.advertisementTokens < 1) {
      this.suppressed++;
      return false;
    }
    this.advertisementTokens--;
    return true;
  }

  /** A verified member request from `peer` named a head this replica lacks. */
  advertisement(peer: string, head: string, writer: boolean): void {
    if (this.closed || this.host.isKnown(head)) return;
    remember(this.advertised, peer, { head, writer }, MAX_ADVERTISED_PEERS);
    this.gap('advertised-state', peer);
  }

  /**
   * Another member asked with the same head. Writers answer on the shared
   * topic, so this replica postpones its next periodic request once.
   */
  equivalentRequest(): void {
    if (
      this.closed ||
      this.periodicPostponed ||
      this.triggers.size > 0 ||
      this.gapSince !== undefined
    )
      return;
    this.periodicPostponed = true;
    this.periodicAt = this.clock.now() + this.jitteredInterval();
    this.suppressed++;
    this.arm();
  }

  /** The application sent a request itself. */
  manualRequest(): void {
    if (this.closed) return;
    const now = this.clock.now();
    this.lastRequestAt = now;
    this.periodicAt = now + this.jitteredInterval();
    this.arm();
  }

  private trigger(reason: AntiEntropyTrigger, peer?: string): void {
    if (this.closed) return;
    const now = this.clock.now();
    if (peer !== undefined) {
      if (!this.peerSignalAllowed(reason, peer, now)) {
        this.suppressed++;
        return;
      }
      remember(this.peerSignals, `${reason}\0${peer}`, now, MAX_TRACKED_PEERS);
    }
    if (this.triggers.size === 0)
      this.triggerReadyAt = now + 500 + this.clock.random() * 1000;
    this.triggers.add(reason);
    this.arm();
  }

  private peerSignalAllowed(
    reason: AntiEntropyTrigger,
    peer: string,
    now: number,
  ): boolean {
    const last = this.peerSignals.get(`${reason}\0${peer}`);
    return last === undefined || now - last >= this.config.peerCooldownMs;
  }

  private gap(reason: AntiEntropyTrigger, peer?: string): void {
    if (this.closed) return;
    if (this.gapSince === undefined) {
      const now = this.clock.now();
      this.gapSince = now;
      this.gapTrigger = reason;
      this.emit({ type: 'gap', at: now, trigger: reason });
    }
    this.trigger(reason, peer);
  }

  /** Drop resolved signals. Returns whether a gap remains open. */
  private refreshGap(): boolean {
    for (const [peer, { head }] of this.advertised)
      if (this.host.isKnown(head)) this.advertised.delete(peer);
    for (const cid of this.missing)
      if (this.host.isKnown(cid)) this.missing.delete(cid);
    const open =
      this.advertised.size > 0 ||
      this.missing.size > 0 ||
      this.host.hasPendingChanges();
    const now = this.clock.now();
    if (open) {
      if (this.gapSince === undefined) {
        this.gapSince = now;
        this.gapTrigger = 'pending-changes';
        this.emit({ type: 'gap', at: now, trigger: 'pending-changes' });
      }
    } else if (this.gapSince !== undefined) {
      const afterMs = now - this.gapSince;
      this.gapSince = undefined;
      this.gapRequestAt = undefined;
      this.requestBackoff = 0;
      this.loadBackoff = 1;
      for (const reason of GAP_TRIGGERS) this.triggers.delete(reason);
      this.emit({ type: 'repaired', at: now, afterMs });
    }
    return open;
  }

  private jitteredInterval(): number {
    return Math.round(
      this.config.intervalMs * (2 / 3 + (this.clock.random() * 2) / 3),
    );
  }

  private nextRequestAt(): number {
    const spacing = Math.min(
      this.config.intervalMs,
      this.config.minRequestIntervalMs * 2 ** this.requestBackoff,
    );
    const earliest =
      this.lastRequestAt === undefined ? 0 : this.lastRequestAt + spacing;
    const wanted =
      this.triggers.size > 0
        ? this.triggerReadyAt
        : this.gapSince !== undefined
          ? earliest
          : this.periodicAt;
    return Math.max(wanted, earliest);
  }

  private nextLoadAt(): number | undefined {
    if (this.gapRequestAt === undefined) return;
    return Math.max(
      this.gapRequestAt + this.config.loadAfterMs,
      this.loadNotBefore,
    );
  }

  private clearTimer(): void {
    if (this.timer !== undefined) this.clock.clearTimeout(this.timer);
    this.timer = undefined;
    this.timerAt = undefined;
  }

  private arm(): void {
    if (this.closed || this.phase !== 'idle') return;
    const requestAt = this.nextRequestAt();
    const loadAt = this.nextLoadAt();
    const at = loadAt === undefined ? requestAt : Math.min(requestAt, loadAt);
    if (this.timer !== undefined && this.timerAt === at) return;
    this.clearTimer();
    this.timerAt = at;
    this.timer = this.clock.setTimeout(
      () => void this.fire(),
      Math.max(0, at - this.clock.now()),
    );
  }

  private async fire(): Promise<void> {
    this.timer = undefined;
    this.timerAt = undefined;
    if (this.closed || this.phase !== 'idle') return;
    try {
      if (this.gapSince !== undefined) this.refreshGap();
      const now = this.clock.now();
      const loadAt = this.nextLoadAt();
      if (loadAt !== undefined && now >= loadAt) await this.runLoad(now);
      else if (now >= this.nextRequestAt()) await this.runRequest(now);
    } finally {
      this.arm();
    }
  }

  private async runRequest(now: number): Promise<void> {
    if (!this.budget.takeRequest(now)) {
      const retryAt = now + 250 + this.clock.random() * 1000;
      if (this.triggers.size > 0) this.triggerReadyAt = retryAt;
      else this.periodicAt = retryAt;
      return;
    }
    const triggers: AntiEntropyTrigger[] =
      this.triggers.size > 0
        ? [...this.triggers]
        : [this.gapSince !== undefined ? this.gapTrigger : 'periodic'];
    this.triggers.clear();
    this.phase = 'requesting';
    let outcome: AntiEntropyRequestOutcome | 'failed';
    try {
      outcome = await this.host.request();
    } catch {
      outcome = 'failed';
    } finally {
      this.phase = 'idle';
    }
    if (this.closed) return;
    const at = this.clock.now();
    if (outcome === 'sent') this.requests++;
    this.lastRequestAt = at;
    this.periodicAt = at + this.jitteredInterval();
    this.periodicPostponed = false;
    if (this.refreshGap()) {
      if (outcome !== 'not-ready') this.gapRequestAt ??= at;
      this.requestBackoff = Math.min(
        this.requestBackoff + 1,
        MAX_REQUEST_BACKOFF,
      );
    }
    this.emit({ type: 'request', at, triggers, outcome });
  }

  private loadTarget(): string | undefined {
    const peers = [...this.advertised].reverse();
    for (const [peer, { writer }] of peers)
      if (writer && this.host.isConnected(peer)) return peer;
    return undefined;
  }

  private async runLoad(now: number): Promise<void> {
    if (!this.host.canLoad()) {
      // Without the load path, an unfetched change escalates no further; a
      // later frame that names it again reports it again.
      this.missing.clear();
      this.refreshGap();
      this.loadNotBefore = now + this.config.loadIntervalMs * this.loadBackoff;
      return;
    }
    const peer = this.loadTarget();
    const localGap = this.missing.size > 0 || this.host.hasPendingChanges();
    if (peer === undefined && !localGap) {
      // Only readers, or disconnected writers, advertised the newer state;
      // keep asking over gossip until a writer can serve it.
      this.loadNotBefore = now + this.config.loadIntervalMs * this.loadBackoff;
      return;
    }
    const release = this.budget.acquireLoad(peer, now);
    if (release === undefined) {
      this.loadNotBefore = now + 1_000 + this.clock.random() * 2_000;
      return;
    }
    this.phase = 'loading';
    let outcome: AntiEntropyLoadOutcome;
    try {
      outcome = (await this.host.load(peer)) ? 'loaded' : 'not-served';
    } catch {
      outcome = 'failed';
    } finally {
      release();
      this.phase = 'idle';
    }
    if (this.closed) return;
    const at = this.clock.now();
    this.loads++;
    if (peer !== undefined) this.advertised.delete(peer);
    // Each unfetched change escalates once; a later frame reports it again.
    this.missing.clear();
    const open = this.refreshGap();
    if (open || outcome !== 'loaded')
      this.loadBackoff = Math.min(this.loadBackoff * 2, MAX_LOAD_BACKOFF);
    this.loadNotBefore = at + this.config.loadIntervalMs * this.loadBackoff;
    this.lastLoad = Object.freeze({
      at,
      ...(peer === undefined ? {} : { peer }),
      outcome,
    });
    this.emit({
      type: 'load',
      at,
      ...(peer === undefined ? {} : { peer }),
      outcome,
    });
  }

  private emit(event: AntiEntropyEvent): void {
    try {
      this.onEvent(Object.freeze(event));
    } catch {
      // Observers cannot interrupt catch-up.
    }
  }
}
