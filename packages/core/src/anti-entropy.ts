/**
 * Automatic catch-up ("anti-entropy") for default, non-coordinated sync.
 *
 * A document asks members for missed updates with the existing signed sync
 * request. It asks when it opens, when a peer subscribed to its topic
 * connects, when the CRDT buffers changes whose dependencies are missing,
 * when a frame names a change that cannot be fetched, when a member
 * advertises a head it does not hold, and periodically with jitter. When a
 * detected gap outlives a request and the evidence is strong enough, it
 * loads through the authenticated V4 load path, preferring a writer that
 * advertised newer state. A request also follows a frame that added a
 * change, so that its author learns a member holds it.
 */

/** Why a catch-up request was scheduled. */
export type AntiEntropyTrigger =
  | 'open'
  | 'peer-subscribed'
  | 'pending-changes'
  | 'missing-change'
  | 'advertised-state'
  | 'acknowledgment'
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
   * detected gap persists, up to `intervalMs`. A request that acknowledges
   * an applied change waits only the 2000 ms sync-request rate limit.
   * Default: 5000 ms; at least that rate limit.
   */
  minRequestIntervalMs: number;
  /**
   * One member, or one peer seen as a member, triggers at most one request
   * per kind of signal within this window; all other peers share one window.
   * Default: 30 000 ms.
   */
  peerCooldownMs: number;
  /** Load once a detected gap outlives a request by this long. Default: 15 000 ms. */
  loadAfterMs: number;
  /**
   * Minimum delay between this document's loads. It doubles after each load
   * that leaves the gap open, up to 64 times, and is reset only by a repair.
   * Default: 60 000 ms.
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
  /** Every signal of the gap was resolved: its heads and changes are held. */
  | { readonly type: 'repaired'; readonly at: number; readonly afterMs: number }
  /**
   * The gap closed without being resolved: an advertisement expired or a
   * load left its head or change unknown. Backoff is kept.
   */
  | {
      readonly type: 'abandoned';
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
  /** Signals dropped by a cooldown or penalty, and periodic requests postponed by an equivalent request. */
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
  /** The change CID is held or covered by held state. */
  isKnown(cid: string): boolean;
  /** An authenticated load can be attempted. */
  canLoad(): boolean;
  isConnected(peer: string): boolean;
  /** Check that the writer authorization and advertisement are still current. */
  canLoadFromSoleWriter?(writer: SoleWriterAdvertisement): boolean;
  /** Run the authenticated load, preferring `peer`, until `signal` aborts. */
  load(
    peer: string | undefined,
    signal: AbortSignal,
    soleWriter?: SoleWriterAdvertisement,
  ): Promise<boolean>;
}

/** A verified sync request from the document's sole writer. */
export interface SoleWriterAdvertisement {
  readonly member: string;
  readonly peer: string;
  readonly writerVersion: number;
  readonly issuedAtMs: number;
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

// Tokens a periodic request leaves for gap-driven ones.
const RESERVED_REQUEST_TOKENS = 4;
// Share of the request rate that periodic requests are planned for.
const PERIODIC_REQUEST_SHARE = 0.5;
// An acknowledgment follows the first change it covers by one to two seconds.
const ACKNOWLEDGMENT_DELAY_MS = 1_000;

/**
 * Work shared by every document of one Peerborne instance: a token bucket for
 * catch-up requests, the periodic interval scale, and bounds on concurrent
 * loads and per-peer load rate.
 */
export class AntiEntropyBudget {
  private tokens: number;
  private refilledAt?: number;
  private loads = 0;
  private documents = 0;
  private waiting = 0;
  private readonly peerLoads = new Map<string, number>();

  constructor(
    private readonly requestsPerSecond = 4,
    private readonly burst = 16,
    private readonly maxConcurrentLoads = 1,
    private readonly peerLoadSpacingMs = 10_000,
  ) {
    this.tokens = burst;
  }

  /** Count an open document until the returned function is called. */
  register(): () => void {
    this.documents++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.documents--;
    };
  }

  get openDocuments(): number {
    return this.documents;
  }

  /**
   * Factor that stretches each document's periodic interval so all open
   * documents together plan at most half of the request rate.
   */
  periodicScale(intervalMs: number): number {
    const capacity =
      (this.requestsPerSecond * PERIODIC_REQUEST_SHARE * intervalMs) / 1000;
    return Math.max(1, this.documents / capacity);
  }

  /**
   * Take a request token. A periodic request leaves a reserve for requests
   * that a detected gap or a new peer triggered.
   */
  takeRequest(now: number, periodic = false): boolean {
    if (this.refilledAt !== undefined && now > this.refilledAt) {
      this.tokens = Math.min(
        this.burst,
        this.tokens + ((now - this.refilledAt) * this.requestsPerSecond) / 1000,
      );
    }
    this.refilledAt = now;
    if (this.tokens < 1 + (periodic ? RESERVED_REQUEST_TOKENS : 0))
      return false;
    this.tokens--;
    return true;
  }

  /** A document starts or stops waiting for a token. */
  wait(waiting: boolean): void {
    this.waiting = Math.max(0, this.waiting + (waiting ? 1 : -1));
  }

  /** Delay before a waiting document asks again, spread over the queue. */
  retryDelay(random: number): number {
    return Math.max(
      250,
      ((1 + this.waiting) / this.requestsPerSecond) * 1000 * (0.5 + random),
    );
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
const MAX_ADVERTISERS = 32;
const MAX_MISSING_CHANGES = 64;
const MAX_UNRESOLVED_CHANGES = 256;
const MAX_REQUEST_BACKOFF = 8;
const MAX_LOAD_BACKOFF = 64;
const MAX_ADVERTISEMENT_CHECKS = 4;
const ADVERTISEMENT_CHECK_REFILL_MS = 2_000;
// This many equivalent advertisements substitute for local evidence.
const CORROBORATING_MEMBERS = 2;
// Loads one gap may start without corroboration.
const MAX_LOCAL_GAP_LOADS = 3;
const MEMBER_PEER_TTL_MS = 60 * 60 * 1000;
const UNRESOLVED_CHANGE_TTL_MS = 60 * 60 * 1000;
const MEMBER_PENALTY_MS = 5 * 60 * 1000;
const MAX_MEMBER_PENALTY_MS = 2 * 60 * 60 * 1000;
/**
 * A catch-up load is aborted after this long, and its load slot is released
 * even if the load ignores the abort, so other repairs can proceed. Each block
 * a load fetches has its own stall deadline, so this only bounds a load that
 * stops making progress some other way.
 */
export const CATCH_UP_LOAD_DEADLINE_MS = 5 * 60_000;
const UNKNOWN_PEER = '\0unknown';
const GAP_TRIGGERS: readonly AntiEntropyTrigger[] = [
  'pending-changes',
  'missing-change',
  'advertised-state',
];

interface Advertisement {
  readonly peer: string;
  readonly head: string;
  readonly writer: boolean;
  readonly at: number;
  readonly soleWriter?: SoleWriterAdvertisement;
}

/** Settle with `work`, or reject once `signal` aborts, whichever is first. */
function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
    void Promise.resolve(work)
      .then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', onAbort));
  });
}

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

/**
 * Schedules automatic catch-up for one open document.
 *
 * Advertisements are keyed by the verified member that sent them, so one
 * identity counts once however many PeerIds it uses. A head only one member
 * advertises is asked for over gossip but never loaded for; a load needs two
 * members advertising the same head, or local evidence (pending CRDT state or
 * an unfetched change), and at most three loads per gap use local evidence
 * alone. A load that leaves an advertised head or a change unknown penalizes
 * that member, or remembers that change as unresolvable, and closes that part
 * of the gap as abandoned rather than repaired.
 */
export class AntiEntropy {
  private closed = false;
  private timer: unknown;
  private timerAt?: number;
  private phase: AntiEntropyStatus['phase'] = 'idle';
  private readonly triggers = new Set<AntiEntropyTrigger>();
  private triggerReadyAt = 0;
  private periodicAt = 0;
  private periodicPostponed = false;
  private waitingForToken = false;
  private requestRetryAt = 0;
  private lastRequestAt?: number;
  private requestBackoff = 0;
  private acknowledgmentAt?: number;
  private acknowledgments = 0;
  private readonly peerSignals = new Map<string, number>();
  private readonly memberPeers = new Map<string, number>();
  private readonly advertised = new Map<string, Advertisement>();
  private readonly penalties = new Map<
    string,
    { readonly until: number; readonly strikes: number }
  >();
  private readonly missing = new Set<string>();
  private readonly unresolved = new Map<string, number>();
  private gapSince?: number;
  private gapRequestAt?: number;
  private gapTrigger: AntiEntropyTrigger = 'periodic';
  private gapAbandoned = false;
  private localGapLoads = 0;
  private loadNotBefore = 0;
  private loadBackoff = 1;
  private loading?: AbortController;
  private requests = 0;
  private loads = 0;
  private suppressed = 0;
  private lastLoad?: AntiEntropyStatus['lastLoad'];
  private advertisementTokens = MAX_ADVERTISEMENT_CHECKS;
  private advertisementCheckedAt?: number;
  private readonly closeCallbacks: Array<() => void> = [];
  private releaseBudget?: () => void;

  constructor(
    private readonly config: AntiEntropyConfig,
    private readonly host: AntiEntropyHost,
    private readonly budget: AntiEntropyBudget,
    private readonly onEvent: (event: AntiEntropyEvent) => void = () => {},
    private readonly clock: AntiEntropyClock = systemClock,
  ) {}

  /** Schedule the first request and the periodic cycle. */
  start(): void {
    if (this.closed || this.releaseBudget) return;
    this.releaseBudget = this.budget.register();
    this.periodicAt = this.clock.now() + this.jitteredInterval();
    this.trigger('open');
  }

  /** Stop scheduling and abort a load in progress. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearTimer();
    this.loading?.abort(new Error('Document closed'));
    this.releaseBudget?.();
    if (this.waitingForToken) this.budget.wait(false);
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

  /** `peer` sent a verified member request or writer frame. */
  memberPeer(peer: string): void {
    if (this.closed || peer === '') return;
    remember(this.memberPeers, peer, this.clock.now(), MAX_TRACKED_PEERS);
  }

  /**
   * A peer subscribed to the document topic, for example after reconnecting.
   * Topic names are public, so a peer that this node did not dial (`dialed`)
   * and has not recently seen as a member shares one cooldown with every
   * other such peer.
   */
  peerSubscribed(peer: string, dialed = false): void {
    const seen = this.memberPeers.get(peer);
    const known =
      dialed ||
      (seen !== undefined && this.clock.now() - seen < MEMBER_PEER_TTL_MS);
    this.trigger('peer-subscribed', known ? peer : UNKNOWN_PEER);
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

  /**
   * A frame added a change that this replica did not hold. A request follows
   * one to two seconds later, and at least two seconds after the previous
   * request, so the change's author sees a request signed by this member,
   * from its own PeerId, that names the change, even when GossipSub carried
   * the frame only through a relay. Changes applied before that request
   * share it.
   */
  acknowledge(): void {
    if (this.closed) return;
    this.acknowledgments++;
    this.acknowledgmentAt ??=
      this.clock.now() + ACKNOWLEDGMENT_DELAY_MS * (1 + this.clock.random());
    this.arm();
  }

  /** A frame named a change that could not be fetched. */
  missingChange(cid: string): void {
    if (this.closed || this.host.isKnown(cid)) return;
    const unresolvedUntil = this.unresolved.get(cid);
    if (unresolvedUntil !== undefined && unresolvedUntil > this.clock.now()) {
      this.suppressed++;
      return;
    }
    this.missing.delete(cid);
    this.missing.add(cid);
    if (this.missing.size > MAX_MISSING_CHANGES)
      this.missing.delete(this.missing.values().next().value!);
    this.gap('missing-change');
  }

  /**
   * Whether `member`'s advertisement of `head` should be verified and
   * recorded. Callers ask before spending a signature verification. One
   * member is admitted once per cooldown, not while it is penalized, and at
   * most four checks are admitted at once, refilled at one per two seconds.
   */
  admitAdvertisement(member: string, head: string): boolean {
    if (this.closed || this.host.isKnown(head)) return false;
    const previous = this.advertised.get(member);
    if (
      previous?.head === head &&
      (previous.soleWriter === undefined ||
        this.canLoadFromSoleWriter(previous.soleWriter))
    )
      return false;
    const now = this.clock.now();
    const penalty = this.penalties.get(member);
    if (
      (penalty !== undefined && penalty.until > now) ||
      !this.peerSignalAllowed('advertised-state', member, now) ||
      !this.takeAdvertisementCheck(now)
    ) {
      this.suppressed++;
      return false;
    }
    return true;
  }

  /**
   * A verified request from `member`, sent by `peer`, names `head` as its
   * own head, and this replica lacks it. It replaces that member's earlier
   * advertisement.
   */
  advertisement(
    member: string,
    peer: string,
    head: string,
    writer: boolean,
    soleWriter?: Pick<SoleWriterAdvertisement, 'writerVersion' | 'issuedAtMs'>,
  ): void {
    if (this.closed || this.host.isKnown(head)) return;
    remember(
      this.advertised,
      member,
      {
        peer,
        head,
        writer,
        at: this.clock.now(),
        soleWriter:
          writer && soleWriter ? { ...soleWriter, member, peer } : undefined,
      },
      MAX_ADVERTISERS,
    );
    this.gap('advertised-state', member);
  }

  /**
   * Whether a request from `member` naming a head this replica holds should
   * be verified to retract that member's earlier advertisement.
   */
  admitRetraction(member: string): boolean {
    return (
      !this.closed &&
      this.advertised.has(member) &&
      this.takeAdvertisementCheck(this.clock.now())
    );
  }

  /**
   * A verified request shows that `member` no longer advertises an unknown
   * head. The head did not become known, so the gap is not counted repaired.
   */
  retractAdvertisement(member: string): void {
    if (this.closed || !this.advertised.delete(member)) return;
    this.gapAbandoned = true;
    if (this.gapSince !== undefined && !this.refreshGap()) this.arm();
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
    this.acknowledgmentAt = undefined;
    this.lastRequestAt = now;
    this.periodicAt = now + this.jitteredInterval();
    this.arm();
  }

  private takeAdvertisementCheck(now: number): boolean {
    if (this.advertisementCheckedAt !== undefined)
      this.advertisementTokens = Math.min(
        MAX_ADVERTISEMENT_CHECKS,
        this.advertisementTokens +
          Math.max(0, now - this.advertisementCheckedAt) /
            ADVERTISEMENT_CHECK_REFILL_MS,
      );
    this.advertisementCheckedAt = now;
    if (this.advertisementTokens < 1) return false;
    this.advertisementTokens--;
    return true;
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

  private advertisementTtl(): number {
    return 3 * this.config.intervalMs;
  }

  /** Drop resolved and expired signals. Returns whether a gap remains open. */
  private refreshGap(): boolean {
    const now = this.clock.now();
    for (const [member, { head, at }] of this.advertised) {
      if (this.host.isKnown(head)) this.advertised.delete(member);
      else if (now - at >= this.advertisementTtl()) this.penalize(member, now);
    }
    for (const cid of this.missing)
      if (this.host.isKnown(cid)) this.missing.delete(cid);
    const open =
      this.advertised.size > 0 ||
      this.missing.size > 0 ||
      this.host.hasPendingChanges();
    if (open) {
      if (this.gapSince === undefined) {
        this.gapSince = now;
        this.gapTrigger = 'pending-changes';
        this.emit({ type: 'gap', at: now, trigger: 'pending-changes' });
      }
    } else if (this.gapSince !== undefined) {
      const afterMs = now - this.gapSince;
      const abandoned = this.gapAbandoned;
      this.gapSince = undefined;
      this.gapRequestAt = undefined;
      this.gapAbandoned = false;
      this.localGapLoads = 0;
      for (const reason of GAP_TRIGGERS) this.triggers.delete(reason);
      if (abandoned) {
        this.emit({ type: 'abandoned', at: now, afterMs });
      } else {
        this.requestBackoff = 0;
        this.loadBackoff = 1;
        this.emit({ type: 'repaired', at: now, afterMs });
      }
    }
    return open;
  }

  private jitteredInterval(): number {
    return Math.round(
      this.config.intervalMs *
        this.budget.periodicScale(this.config.intervalMs) *
        (2 / 3 + (this.clock.random() * 2) / 3),
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
    const at = Math.max(wanted, earliest, this.requestRetryAt);
    if (this.acknowledgmentAt === undefined) return at;
    return Math.min(
      at,
      Math.max(
        this.acknowledgmentAt,
        this.lastRequestAt === undefined
          ? 0
          : this.lastRequestAt + MIN_REQUEST_INTERVAL_MS,
        this.requestRetryAt,
      ),
    );
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
    const periodic = this.triggers.size === 0 && this.gapSince === undefined;
    if (!this.budget.takeRequest(now, periodic)) {
      if (!this.waitingForToken) {
        this.waitingForToken = true;
        this.budget.wait(true);
      }
      this.requestRetryAt = now + this.budget.retryDelay(this.clock.random());
      return;
    }
    if (this.waitingForToken) {
      this.waitingForToken = false;
      this.budget.wait(false);
    }
    const acknowledging = this.acknowledgmentAt !== undefined;
    const acknowledgments = this.acknowledgments;
    const triggers: AntiEntropyTrigger[] =
      this.triggers.size > 0
        ? [...this.triggers]
        : this.gapSince !== undefined
          ? [this.gapTrigger]
          : acknowledging
            ? []
            : ['periodic'];
    if (acknowledging) triggers.push('acknowledgment');
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
    if (this.acknowledgments === acknowledgments)
      this.acknowledgmentAt = undefined;
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

  /** A head that enough distinct members advertise, with those members. */
  private corroboratedHead(): { head: string; members: string[] } | undefined {
    const byHead = new Map<string, string[]>();
    for (const [member, { head }] of this.advertised) {
      const members = byHead.get(head) ?? [];
      members.push(member);
      byHead.set(head, members);
    }
    for (const [head, members] of byHead)
      if (members.length >= CORROBORATING_MEMBERS) return { head, members };
    return undefined;
  }

  private loadTarget(members: Iterable<string>): string | undefined {
    const candidates = new Set(members);
    const newest = [...this.advertised].reverse();
    for (const [member, { peer, writer }] of newest)
      if (candidates.has(member) && writer && this.host.isConnected(peer))
        return peer;
    return undefined;
  }

  private canLoadFromSoleWriter(writer: SoleWriterAdvertisement): boolean {
    return (
      this.host.isConnected(writer.peer) &&
      this.host.canLoadFromSoleWriter?.(writer) === true
    );
  }

  private async runLoad(now: number): Promise<void> {
    const corroborated = this.corroboratedHead();
    const mayLoadWithoutCorroboration =
      this.localGapLoads < MAX_LOCAL_GAP_LOADS;
    const localGap =
      mayLoadWithoutCorroboration &&
      (this.missing.size > 0 || this.host.hasPendingChanges());
    const soleWriter =
      mayLoadWithoutCorroboration && corroborated === undefined && !localGap
        ? [...this.advertised.values()].find(
            ({ soleWriter }) =>
              soleWriter !== undefined &&
              this.canLoadFromSoleWriter(soleWriter),
          )?.soleWriter
        : undefined;
    if (
      !this.host.canLoad() ||
      (corroborated === undefined && !localGap && soleWriter === undefined)
    ) {
      // Without the load path or enough evidence, unfetched changes escalate
      // no further and advertisements wait for corroboration or expiry.
      if (!this.host.canLoad()) this.abandonMissing(now);
      this.loadNotBefore = now + this.config.loadIntervalMs * this.loadBackoff;
      this.refreshGap();
      return;
    }
    const peer =
      soleWriter?.peer ??
      this.loadTarget(corroborated?.members ?? []) ??
      this.loadTarget(this.advertised.keys());
    const release = this.budget.acquireLoad(peer, now);
    if (release === undefined) {
      this.loadNotBefore = now + 1_000 + this.clock.random() * 2_000;
      return;
    }
    if (corroborated === undefined) this.localGapLoads++;
    const loading = new AbortController();
    this.loading = loading;
    this.phase = 'loading';
    const deadline = this.clock.setTimeout(
      () => loading.abort(new Error('Catch-up load deadline exceeded')),
      CATCH_UP_LOAD_DEADLINE_MS,
    );
    let outcome: AntiEntropyLoadOutcome;
    try {
      outcome = (await untilAborted(
        this.host.load(peer, loading.signal, soleWriter),
        loading.signal,
      ))
        ? 'loaded'
        : 'not-served';
    } catch {
      outcome = 'failed';
    } finally {
      this.clock.clearTimeout(deadline);
      release();
      this.loading = undefined;
      this.phase = 'idle';
    }
    if (this.closed) return;
    const at = this.clock.now();
    this.loads++;
    const penalized = this.penalizeUnresolved(at);
    const unresolved = this.abandonMissing(at) || penalized;
    const open = this.refreshGap();
    if (open || unresolved || outcome !== 'loaded')
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

  /** Members whose advertised head a load did not reveal are penalized. */
  private penalizeUnresolved(now: number): boolean {
    let penalized = false;
    for (const [member, { head }] of this.advertised)
      if (!this.host.isKnown(head)) {
        this.penalize(member, now);
        penalized = true;
      }
    return penalized;
  }

  /**
   * Drop `member`'s advertisement as unresolved and ignore its next ones for
   * five minutes, doubling with each strike up to two hours.
   */
  private penalize(member: string, now: number): void {
    const strikes = (this.penalties.get(member)?.strikes ?? 0) + 1;
    remember(
      this.penalties,
      member,
      {
        strikes,
        until:
          now +
          Math.min(
            MAX_MEMBER_PENALTY_MS,
            MEMBER_PENALTY_MS * 2 ** Math.min(strikes - 1, 16),
          ),
      },
      MAX_TRACKED_PEERS,
    );
    this.advertised.delete(member);
    this.gapAbandoned = true;
  }

  /** Unfetched changes that a load or the lack of one did not reveal are ignored for a while. */
  private abandonMissing(now: number): boolean {
    let abandoned = false;
    for (const cid of this.missing) {
      if (this.host.isKnown(cid)) continue;
      remember(
        this.unresolved,
        cid,
        now + UNRESOLVED_CHANGE_TTL_MS,
        MAX_UNRESOLVED_CHANGES,
      );
      this.gapAbandoned = true;
      abandoned = true;
    }
    this.missing.clear();
    return abandoned;
  }

  private emit(event: AntiEntropyEvent): void {
    try {
      this.onEvent(Object.freeze(event));
    } catch {
      // Observers cannot interrupt catch-up.
    }
  }
}
