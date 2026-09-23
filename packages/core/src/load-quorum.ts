import { tipsHashToHex } from './tips-hash.js';
import { copyUnsharedUint8Array } from './utils.js';

/** One vote after the caller has authenticated and deduplicated its authority. */
export interface PeerTipAdvertisement {
  peerId: string;
  hash: Uint8Array | null;
}

export type LoadQuorumDecision =
  | {
      ok: true;
      kind: 'tip-hash';
      winningHashHex: string;
      agreeingPeerIds: string[];
      respondingCount: number;
      effectiveQ: number;
    }
  | {
      ok: false;
      reason:
        | 'insufficient-responses'
        | 'no-majority'
        | 'conflicting-quorum'
        | 'no-peers-queried';
      respondingCount: number;
      effectiveQ: number;
      agreement: Map<string, number>;
    };

/**
 * Count matching authenticated state digests without lowering the requested
 * Q. An explicit non-majority Q can let two buckets both reach Q; that is a
 * conflict, not an outcome, so the decision fails instead of letting probe
 * order pick a winner.
 */
export function decideLoadQuorum(
  advertisements: readonly PeerTipAdvertisement[],
  q: number,
): LoadQuorumDecision {
  if (!Number.isSafeInteger(q) || q < 1) {
    throw new Error(
      `decideLoadQuorum: q must be a positive integer; got ${String(q)}`,
    );
  }
  const agreement = new Map<string, string[]>();
  let respondingCount = 0;
  const seenPeers = new Set<string>();
  for (const advertisement of advertisements) {
    if (seenPeers.has(advertisement.peerId)) continue;
    let hash: Uint8Array;
    try {
      hash = copyUnsharedUint8Array(
        advertisement.hash,
        32,
        32,
        'load-quorum vote hash',
      );
    } catch {
      continue;
    }
    seenPeers.add(advertisement.peerId);
    respondingCount++;
    const hex = tipsHashToHex(hash);
    const bucket = agreement.get(hex) ?? [];
    bucket.push(advertisement.peerId);
    agreement.set(hex, bucket);
  }
  let winningHashHex = '';
  let agreeingPeerIds: string[] = [];
  let bucketsMeetingQ = 0;
  for (const [hex, peers] of agreement) {
    if (peers.length >= q) bucketsMeetingQ++;
    if (peers.length > agreeingPeerIds.length) {
      winningHashHex = hex;
      agreeingPeerIds = peers;
    }
  }
  if (agreeingPeerIds.length >= q && bucketsMeetingQ === 1) {
    return {
      ok: true,
      kind: 'tip-hash',
      winningHashHex,
      agreeingPeerIds,
      respondingCount,
      effectiveQ: q,
    };
  }
  return {
    ok: false,
    reason:
      advertisements.length === 0
        ? 'no-peers-queried'
        : bucketsMeetingQ > 1
          ? 'conflicting-quorum'
          : respondingCount < q
            ? 'insufficient-responses'
            : 'no-majority',
    respondingCount,
    effectiveQ: q,
    agreement: new Map(
      [...agreement].map(([hex, peers]) => [hex, peers.length]),
    ),
  };
}

/**
 * Compute the default quorum threshold `Q` for a given `K` using the
 * strict-majority rule `Math.floor(K / 2) + 1`. This is only the default
 * configured agreement threshold; callers may explicitly configure a valid
 * non-majority Q. The formula alone supplies neither a consensus protocol nor
 * Sybil resistance, and any fault analysis assumes the counted identities are
 * independently controlled. This is the formula `PeerborneConfig.loadQuorumQ`
 * defaults to when the user does not override it.
 *
 * Worked examples:
 *   - K=1 → Q=1
 *   - K=2 → Q=2
 *   - K=3 → Q=2 (previously K=3 → Q=3 under
 *     `Math.ceil(K/2)+1`, which required all three peers to vote)
 *   - K=4 → Q=3
 *   - K=5 → Q=3
 *   - K=7 → Q=4
 *
 * Pulled out so the loader, the config docstring, and the test matrix all
 * reference one canonical formula.
 */
export function defaultQuorumQ(k: number): number {
  if (k <= 0) return 0;
  return Math.floor(k / 2) + 1;
}

/**
 * Deduplicate a sequence of (peer, peerId) pairs by `peerId`, preserving
 * first-seen order. Used by the loader to collapse multiple open
 * connections to the same remote peer into a single quorum entry — without
 * this, one peer with two connections (e.g. direct + relay-circuit) would
 * cast two votes in the tip-advertise tally, allowing a single malicious
 * peer with multiple connections to single-handedly win an agreement.
 *
 * Pulled out so the dedup behaviour is unit-testable without standing up
 * a libp2p stack. The `T` generic lets the caller dedup either raw peer
 * objects (Multiaddr in `PeerborneDocument.load()`) or test doubles.
 */
export function dedupePeersByPeerId<T>(
  peers: readonly T[],
  peerIdOf: (peer: T) => string,
): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const peer of peers) {
    const id = peerIdOf(peer);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(peer);
  }
  return out;
}

/**
 * Constant-time string equality used by the post-load hash-binding check.
 * Both inputs are expected to be lowercase hex strings (typically 64 chars
 * for SHA-256), but the implementation tolerates differing lengths via the
 * length-XOR + max-loop pattern. Returns `true` if the strings are
 * byte-identical.
 *
 * Pulled out so the comparison logic is reused by `_enforceQuorumHashBinding`
 * and is unit-testable (timing properties are not asserted in unit tests but
 * the equality semantics are).
 */
export function constantTimeHexEquals(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    const av = i < a.length ? a.charCodeAt(i) : 0;
    const bv = i < b.length ? b.charCodeAt(i) : 0;
    diff |= av ^ bv;
  }
  return diff === 0;
}

/**
 * Compute the effective `K` (number of peers to query) given a configured
 * upper bound and the number of currently-known peers. Pulled out so the
 * loader and the quorum decision can share a single source of truth and so
 * the clamp is unit-testable.
 *
 * Defensive against non-finite or fractional inputs as a second line of
 * defence behind {@link validateLoadQuorumConfig} (which runs at
 * `Peerborne.initialize()` time). A misconfigured `loadQuorumK: 1.5`
 * that bypassed startup validation would otherwise produce
 * `peers.slice(0, 1.5)` — slicing only one peer and silently degrading
 * the gate to a single-peer probe even though the `k === 1 && !allowSinglePeer`
 * guard would not fire (`1.5 !== 1`). `NaN`/`Infinity` similarly would
 * produce `Math.min(NaN, 3) === NaN` and a `peers.slice(0, NaN) === []`
 * silent skip. Floor + finiteness guards collapse both classes to 0,
 * which the orchestrator surfaces as `LoadQuorumFailedError(invalid-config)`.
 */
export function effectiveK(
  configuredK: number,
  knownPeersCount: number,
): number {
  // K should be at least 1 (otherwise no probes happen) and at most the
  // number of peers we actually know about (otherwise we'd query the same
  // peer twice or fewer-than-K real peers).
  if (!Number.isFinite(configuredK)) return 0;
  if (configuredK <= 0) return 0;
  if (knownPeersCount <= 0) return 0;
  // Floor so a fractional configuredK (which `validateLoadQuorumConfig`
  // rejects at startup) cannot escape as a non-integer slice index.
  return Math.floor(Math.min(configuredK, knownPeersCount));
}

/**
 * Upper bound (milliseconds) for {@link validateLoadQuorumConfig}'s
 * `loadQuorumTimeoutMs` check. Five minutes is comfortably larger than any
 * realistic per-probe budget on a wide-area mesh (the default is 5 s) but
 * small enough to catch a typo like `5000000` (5 000 s = ~83 min) or a
 * mistakenly-passed nanosecond value before it stalls `open()` for an
 * absurd duration.
 */
export const LOAD_QUORUM_TIMEOUT_MS_MAX = 5 * 60 * 1000;

/** Default `loadQuorumK` when the operator does not configure one. */
export const DEFAULT_LOAD_QUORUM_K = 3;

/**
 * Validate the load-quorum tuning knobs from {@link PeerborneConfig}.
 *
 * Call this before using load-quorum settings so a misconfigured value is
 * surfaced loudly rather than silently degrading a subsequent `load()`.
 * For example, `loadQuorumK: 1.5` previously
 * slipped through `Math.min(configuredK, peersLen)` to produce
 * `peers.slice(0, 1.5)`
 * which probes only 1 peer (silent single-peer load); `loadQuorumQ: NaN`
 * made `bestPeers.length < NaN`
 * evaluate as false (silent single-peer quorum pass). Both classes of
 * misconfig are now rejected here with a clear operator-visible error.
 *
 * `loadQuorumTimeoutMs` is also validated here because the value flows
 * directly into `setTimeout(...)` inside a tip-advertise probe race.
 * `NaN`/`Infinity`/`0`/negative values are coerced to immediate-fire or
 * overflow behaviour by the timer queue. We require a finite positive integer
 * no greater than {@link LOAD_QUORUM_TIMEOUT_MS_MAX} so an operator typo or a
 * misplaced decimal is caught at startup.
 *
 * `loadQuorumEnabled` and `loadQuorumAllowSinglePeer` MUST be booleans when
 * provided. `loadQuorumK` and `loadQuorumQ` MUST be finite positive integers
 * (Number.isInteger(x) && x >= 1).
 * `loadQuorumTimeoutMs` MUST be a finite positive integer in the closed
 * range `[1, LOAD_QUORUM_TIMEOUT_MS_MAX]`.
 *
 * Rejects:
 *   - non-boolean values for `loadQuorumEnabled` /
 *     `loadQuorumAllowSinglePeer`
 *   - NaN / Infinity / -Infinity (all knobs)
 *   - non-integers (e.g. 1.5, 2.7) (all knobs)
 *   - zero and negative values (0, -1) (all knobs)
 *   - `loadQuorumTimeoutMs > LOAD_QUORUM_TIMEOUT_MS_MAX`
 *   - `loadQuorumQ` greater than `loadQuorumK` (or
 *     {@link DEFAULT_LOAD_QUORUM_K} when K is not configured)
 * Accepts:
 *   - `undefined` (operator did not override; the orchestrator's defaults apply)
 *   - any positive integer (1, 2, 3, ...) for K/Q
 *   - integers in `[1, LOAD_QUORUM_TIMEOUT_MS_MAX]` for `loadQuorumTimeoutMs`
 *
 * Throws {@link LoadQuorumFailedError} with `reason: 'invalid-config'` so
 * the existing `instanceof`-based error handling in `PeerborneDocument.load()`
 * continues to work and operators see a structured failure with the
 * offending value.
 *
 * @param config The {@link PeerborneConfig} (or its load-quorum subset)
 *   to validate. Boolean policy switches are validated exactly when this
 *   function is invoked.
 *   Dormant K/Q knobs are ignored when quorum is explicitly disabled; the
 *   timeout is validated on every invocation.
 */
export function validateLoadQuorumConfig(config: {
  loadQuorumEnabled?: boolean;
  loadQuorumK?: number;
  loadQuorumQ?: number;
  loadQuorumTimeoutMs?: number;
  loadQuorumAllowSinglePeer?: boolean;
}): void {
  const checkOptionalBoolean = (
    name: string,
    value: boolean | undefined,
  ): void => {
    if (value === undefined) return;
    if (typeof value !== 'boolean') {
      throw new LoadQuorumFailedError({
        documentPath: '<config>',
        reason: 'invalid-config',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map(),
        detail: `${name} must be a boolean; got ${formatConfigValue(value)}`,
      });
    }
  };
  const checkPositiveInt = (name: string, value: number | undefined): void => {
    if (value === undefined) return;
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
      throw new LoadQuorumFailedError({
        // No document path is available at initialize() time; use a
        // placeholder so the error message remains informative. Callers
        // typically catch this at `initialize()` and surface it to the
        // operator without needing the path.
        documentPath: '<config>',
        reason: 'invalid-config',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map(),
        detail: `${name} must be a positive integer; got ${formatConfigValue(value)}`,
      });
    }
  };
  const checkBoundedPositiveInt = (
    name: string,
    value: number | undefined,
    max: number,
  ): void => {
    if (value === undefined) return;
    if (
      typeof value !== 'number' ||
      !Number.isInteger(value) ||
      value < 1 ||
      value > max
    ) {
      throw new LoadQuorumFailedError({
        documentPath: '<config>',
        reason: 'invalid-config',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map(),
        detail:
          `${name} must be a positive integer no greater than ${max}; ` +
          `got ${formatConfigValue(value)}`,
      });
    }
  };
  checkOptionalBoolean('loadQuorumEnabled', config.loadQuorumEnabled);
  checkOptionalBoolean(
    'loadQuorumAllowSinglePeer',
    config.loadQuorumAllowSinglePeer,
  );
  checkBoundedPositiveInt(
    'loadQuorumTimeoutMs',
    config.loadQuorumTimeoutMs,
    LOAD_QUORUM_TIMEOUT_MS_MAX,
  );
  // K/Q do not participate when quorum is disabled.
  if (config.loadQuorumEnabled === false) return;
  checkPositiveInt('loadQuorumK', config.loadQuorumK);
  checkPositiveInt('loadQuorumQ', config.loadQuorumQ);
  const k = config.loadQuorumK ?? DEFAULT_LOAD_QUORUM_K;
  if (config.loadQuorumQ !== undefined && config.loadQuorumQ > k) {
    throw new LoadQuorumFailedError({
      documentPath: '<config>',
      reason: 'invalid-config',
      respondingCount: 0,
      requiredQ: 0,
      agreement: new Map(),
      detail: `loadQuorumQ (${config.loadQuorumQ}) must not exceed loadQuorumK (${k})`,
    });
  }
}

/**
 * Format a configuration value for inclusion in operator-visible error
 * messages. `JSON.stringify` has no representation for `NaN`, `Infinity`,
 * or `-Infinity` and serializes all three as the literal string `'null'` —
 * so an operator who passed `loadQuorumK: NaN` would see `got null` in the
 * error message, indistinguishable from explicitly passing `null` and
 * actively misleading about the actual misconfiguration. Coerce non-finite
 * numbers via `String(...)` so they render as their JS literal (`'NaN'`,
 * `'Infinity'`, `'-Infinity'`) instead. All other values pass through
 * `JSON.stringify` unchanged so structured values (objects, arrays, the
 * literal `null`, strings) still get quoted/serialized cleanly.
 *
 * Used by `validateLoadQuorumConfig` and `runLoadQuorum`'s post-init guard.
 */
export function formatConfigValue(value: unknown): string {
  if (typeof value === 'number' && !Number.isFinite(value)) {
    return String(value); // 'NaN' | 'Infinity' | '-Infinity'
  }
  // `JSON.stringify` throws on BigInt and circular references; fall back to
  // `String(value)` so an exotic operator value yields a useful error
  // message instead of a raw `TypeError` escaping the validator.
  let json: string | undefined;
  try {
    json = JSON.stringify(value);
  } catch {
    return String(value);
  }
  // `JSON.stringify(undefined)` returns `undefined` (not a string), and
  // the function applies a structured replacer to `function` values that
  // also yields `undefined`. Coerce the result so callers that read this
  // in an error message always get a string (avoiding "got undefined")
  // and so strict-mode TypeScript callers see a well-typed `string`
  // return value.
  return json === undefined ? String(value) : json;
}

/**
 * The set of reasons `LoadQuorumFailedError` can be thrown with.
 *
 *   - `'insufficient-responses'` — fewer than `Q` peers returned a usable
 *     tip-set hash within the configured timeout (timeouts, declines,
 *     decryption failures).
 *   - `'no-majority'` — historical identifier retained for compatibility:
 *     peers responded but no single tip-set hash reached Q. Q may be an
 *     explicitly configured non-majority threshold.
 *   - `'conflicting-quorum'` — more than one distinct tip-set hash reached
 *     Q. Only possible with an explicit non-majority Q; the loader refuses
 *     to let probe order choose between conflicting states.
 *   - `'equivocating-authority'` — one V4 signing authority voted for two
 *     different tip-set hashes in the same round (key compromise or a
 *     fork), so the round fails rather than counting either vote.
 *   - `'no-peers-queried'` — `decideLoadQuorum` was called with an empty
 *     advertisement list; surfaced for defensive completeness.
 *   - `'invalid-config'` — the operator misconfigured the gate (e.g.
 *     `loadQuorumK <= 0`) in a way that would silently disable trust
 *     defences. Surfaced as a configuration error rather than a quorum
 *     failure so the misconfiguration is loud at `open()` time.
 *   - `'bind-check-failed-all-agreeing-peers'` — quorum agreement was
 *     reached, but EVERY peer in the agreeing cohort served a full-load
 *     response whose `tips` array did not hash to `winningHashHex` (or
 *     omitted `tips` entirely). Distinct from `'no-majority'` so callers
 *     can tell "no peer was even willing to vote" apart from "the agreeing
 *     cohort was entirely Byzantine on the load step". Surfaced by
 *     `PeerborneDocument.load()` after exhausting every narrowed peer.
 *     Without the per-peer retry, a single malicious peer in the agreeing
 *     cohort could vote for the agreed hash and then serve a mismatched
 *     full load to unilaterally abort the whole load, preventing the loader
 *     from trying any of the OTHER honest agreeing peers.
 */
export type LoadQuorumFailedReason =
  | 'insufficient-responses'
  | 'no-majority'
  | 'conflicting-quorum'
  | 'equivocating-authority'
  | 'no-peers-queried'
  | 'invalid-config'
  | 'bind-check-failed-all-agreeing-peers'
  | 'agreeing-peers-unreachable';

/**
 * Error thrown by `PeerborneDocument.load()` when the initial-load quorum
 * gate fails -- i.e. fewer than `Q` peers agreed on a tip-set hash within
 * the configured timeout. Applications should catch this and either retry
 * later (peers may converge), surface the failure to the user, or fall
 * back to an explicit `loadQuorumEnabled: false` path if they have an
 * out-of-band trust model.
 *
 * The `'invalid-config'` reason is a special case that surfaces an operator
 * misconfiguration (e.g. `loadQuorumK <= 0`) rather than a runtime quorum
 * failure: retrying without fixing the config will not help. See the
 * docstring on {@link LoadQuorumFailedReason} for the full reason set.
 *
 * Defined here (alongside the pure decision logic) so callers can `instanceof`
 * test without importing the heavy `PeerborneDocument` module.
 */
export class LoadQuorumFailedError extends Error {
  /** The document path the quorum was being computed for. */
  public readonly documentPath: string;
  /** Why quorum failed -- mirrors `LoadQuorumDecision.reason` on the
   *  failure case so callers can branch on the specific failure mode.
   *  See {@link LoadQuorumFailedReason} for the full set. */
  public readonly reason: LoadQuorumFailedReason;
  /** Number of peers that returned any non-null probe result — both
   *  tip-hash votes. Timeouts and
   *  non-disclaim declines do NOT increment this. Used to distinguish
   *  `'insufficient-responses'` (< Q peers responded at all) from
   *  `'no-majority'` (≥ Q responded but no single bucket reached Q). */
  public readonly respondingCount: number;
  /** The effective Q threshold the loader was holding peers to. */
  public readonly requiredQ: number;
  /** Snapshot of (hash hex -> vote count) at the moment of failure, used
   *  for observability. Empty when no peer responded. */
  public readonly agreement: ReadonlyMap<string, number>;
  /** For `reason === 'bind-check-failed-all-agreeing-peers'`: a map from
   *  peer-id (as `_peerIdOf` extracts it) to the advertised tipsHash hex
   *  that peer served on its full-load response (or the sentinel
   *  `'(missing tips)'` when the responder omitted the `tips` array). Lets
   *  callers and operators see WHICH peers in the agreeing cohort
   *  equivocated between the probe round and the load round, and what
   *  they served instead. Empty for all other reasons. */
  public readonly agreeingPeerBindFailures: ReadonlyMap<string, string>;
  /** Structured detail string for the `'invalid-config'` reason (e.g.
   *  `loadQuorumK must be a positive integer; got NaN`). Exposed as a
   *  field so callers (notably `runLoadQuorum`'s post-init guard) can
   *  forward the validator's structured wording into a rethrown error
   *  with a different `documentPath` WITHOUT regex-parsing
   *  `error.message`. Empty/undefined for all other reasons. */
  public readonly detail?: string;

  constructor(opts: {
    documentPath: string;
    reason: LoadQuorumFailedReason;
    respondingCount: number;
    requiredQ: number;
    agreement: ReadonlyMap<string, number>;
    /** Free-form detail string used by the `'invalid-config'` reason to
     *  carry the offending value into the operator-visible error message
     *  (e.g. `loadQuorumK must be a positive integer; got NaN`). Non-finite
     *  numbers render as their JS literal (`'NaN'` / `'Infinity'` /
     *  `'-Infinity'`) via `formatConfigValue`, not the misleading
     *  `'null'` that `JSON.stringify` produces. Ignored for the other
     *  reasons, which compose the detail string from the structured
     *  fields. */
    detail?: string;
    /** Per-peer bind-failure record. Only meaningful when
     *  `reason === 'bind-check-failed-all-agreeing-peers'`; ignored
     *  otherwise. */
    agreeingPeerBindFailures?: ReadonlyMap<string, string>;
  }) {
    const detail =
      opts.reason === 'no-peers-queried'
        ? 'no peers were queried'
        : opts.reason === 'insufficient-responses'
          ? `only ${opts.respondingCount} of the required ${opts.requiredQ} peers responded`
          : opts.reason === 'invalid-config'
            ? (opts.detail ?? 'invalid load-quorum configuration')
            : opts.reason === 'conflicting-quorum'
              ? `more than one tip-set hash reached the required ${opts.requiredQ} votes`
            : opts.reason === 'equivocating-authority'
              ? 'a signing authority voted for conflicting tip-set hashes'
            : opts.reason === 'bind-check-failed-all-agreeing-peers'
              ? `quorum agreed on a tip-set hash but every peer in the agreeing cohort ` +
                `(${opts.agreeingPeerBindFailures?.size ?? 0} peer(s)) served a full-load ` +
                `response whose tips did not hash to the agreed value (or omitted tips entirely); ` +
                `treating as coordinated Byzantine equivocation on the load step`
              : opts.reason === 'agreeing-peers-unreachable'
                ? `quorum agreed on a tip-set hash but every peer in the agreeing ` +
                  `cohort failed to serve a full load (transport / protocol error, ` +
                  `not a bind mismatch); the document is known to exist but cannot ` +
                  `currently be retrieved from this peer set`
                : `no tip-set hash reached the required ${opts.requiredQ}-of-${opts.respondingCount} agreement`;
    super(
      `Initial-load quorum failed for "${opts.documentPath}": ${detail}. ` +
        `Configure PeerborneConfig.loadQuorumK/Q/loadQuorumTimeoutMs, ` +
        `or set loadQuorumEnabled: false to bypass (weakens trust assumptions).`,
    );
    this.name = 'LoadQuorumFailedError';
    this.documentPath = opts.documentPath;
    this.reason = opts.reason;
    this.respondingCount = opts.respondingCount;
    this.requiredQ = opts.requiredQ;
    this.agreement = opts.agreement;
    this.agreeingPeerBindFailures = opts.agreeingPeerBindFailures ?? new Map();
    // Persist the structured detail so callers can forward it across a
    // rethrow without parsing the human-readable `error.message`. Only
    // load-bearing for `reason === 'invalid-config'`; harmless for
    // other reasons (where the constructor composes `detail` from the
    // structured fields and `opts.detail` is ignored).
    this.detail = opts.detail;
  }
}
