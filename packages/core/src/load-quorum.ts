/**
 * Pure quorum-decision logic for the initial-load quorum protocol.
 *
 * Closes the "no quorum protocol for verifying initial document state" gap
 * tracked under issue #189 §5.4 item 2 (also a bullet under #186). The
 * design:
 *
 *   - Loader asks up to K peers in parallel for a `tipsHash` (see
 *     `tips-hash.ts`) advertising their view of the document's tip set.
 *   - Each peer either returns a hash, returns `null` (decline, e.g. unknown
 *     document or unauthorized), or fails to respond before the timeout
 *     (also represented as `null` here).
 *   - This module decides whether enough peers (>= Q) agreed on a single
 *     tip-set hash. If so, the loader proceeds with a normal single-peer
 *     document-load against any peer in the agreeing set. If not, the
 *     loader raises `LoadQuorumFailedError` and the application can decide
 *     how to recover (retry, surface to the user, etc.).
 *
 * The functions in this module are intentionally pure (no I/O, no clock,
 * no network) so the decision logic can be unit-tested in isolation and
 * audited as the trust-critical core of the gate.
 */

import { tipsHashToHex } from './tips-hash.js';

/**
 * A single peer's response to a tip-advertise probe.
 *
 * `hash`:
 *   - `Uint8Array` -- the peer returned a tip-set hash (32 bytes
 *     post-validation; see `tips-hash.ts`).
 *   - `'unknown-doc'` -- the peer explicitly disclaimed the document
 *     (received the 1-byte UNKNOWN_DOC sentinel from the wire). Counted
 *     toward an "unknown-doc" tally that the orchestrator uses to
 *     surface `{ newDoc: true }` when the responding cohort genuinely
 *     does not hold the document -- so a fresh `open()` can create the
 *     document on top of the existing swarm rather than failing with
 *     `LoadQuorumFailedError`.
 *
 *     PRECEDENCE: tip-hash votes take priority over disclaim votes. The
 *     probe samples from `getConnections()`, which is the WHOLE libp2p
 *     mesh -- NOT only peers that hold this specific document. Unrelated
 *     peers in the mesh that have not opened this path legitimately
 *     return `'unknown-doc'`; if they were allowed to outvote a peer
 *     that genuinely holds the document, the loader would silently fork
 *     an existing doc into a new local copy. So when ANY peer returns a
 *     real tip-hash, the `'unknown-doc'` bucket is EXCLUDED from the
 *     agreement vote; the new-doc path is only taken when ZERO peers
 *     reported a real tip-hash. See `Peerborne.tipAdvertiseHandler`
 *     for the wire sentinel and PR #284 r16 / r19 Copilot review for
 *     the precedence rationale.
 *
 *     Worst-case Byzantine exposure for new-doc is identical to the
 *     tip-hash case: Q lying peers can force a wrong outcome, but a
 *     single lying peer cannot.
 *   - `null` -- the peer did not return a usable hash. This covers BOTH
 *     timeouts AND non-disclaim declines (unauthorized, wrong document
 *     id, deserialization failure, etc.). Non-responding peers are NOT
 *     counted toward "disagreement" -- they simply do not vote.
 */
export interface PeerTipAdvertisement {
  peerId: string;
  hash: Uint8Array | 'unknown-doc' | null;
}

/**
 * Reserved key used in the `decideLoadQuorum` agreement tally for peers
 * that disclaimed the document (returned `'unknown-doc'` from the probe).
 * Chosen so the key cannot collide with a real `tipsHashToHex` output:
 * `tipsHashToHex` produces a 64-char lowercase hex string, while this
 * sentinel is a 11-char string containing a hyphen.
 */
export const UNKNOWN_DOC_TALLY_KEY = 'unknown-doc';

/**
 * Result of running `decideLoadQuorum` over a set of peer advertisements.
 *
 * On success, `winningHashHex` identifies the agreeing tip set and
 * `agreeingPeerIds` lists the peers that returned that hash -- the loader
 * should pick any one of these for the follow-up full document-load.
 *
 * On failure, `reason` describes why quorum could not be met (used for
 * error messages and observability) and `agreement` records the
 * per-hash vote counts so callers can log the disagreement pattern.
 */
export type LoadQuorumDecision =
  | {
      ok: true;
      /**
       * Discriminates whether the agreeing peers voted for a tip-set hash
       * (the normal case) or all disclaimed the document via the
       * `'unknown-doc'` sentinel (the new-doc-creation case). Callers
       * branch on `kind` to decide whether to proceed with the full
       * document-load (`'tip-hash'`) or to let the loader return `false`
       * so a fresh `open()` creates the document on top of the swarm
       * (`'new-doc'`). See `Peerborne.tipAdvertiseHandler` and
       * PR #284 r16 Copilot review for the unknown-doc wire signal.
       */
      kind: 'tip-hash' | 'new-doc';
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
        | 'no-peers-queried';
      respondingCount: number;
      effectiveQ: number;
      agreement: Map<string, number>;
    };

/**
 * Decide whether a set of tip-advertise responses meets quorum.
 *
 * @param advertisements One entry per peer queried. `hash: null` represents
 *   a non-vote (timeout or decline). Order is irrelevant.
 * @param q The minimum number of *agreeing* peers required. Already clamped
 *   to `[1, K]` by the caller; this function does not re-clamp.
 * @returns A {@link LoadQuorumDecision} describing the outcome. Pure: same
 *   inputs always yield the same result.
 */
export function decideLoadQuorum(
  advertisements: readonly PeerTipAdvertisement[],
  q: number,
): LoadQuorumDecision {
  // Fail fast on programming errors. `decideLoadQuorum` is exported, so a
  // direct caller (or a future refactor that bypasses `runLoadQuorum`)
  // could otherwise pass `q <= 0` / `NaN` / non-integer and silently
  // disable the quorum gate -- the largest-bucket size would always be
  // `>= 0 >= q` and a single peer's vote would pass. The orchestrator
  // already clamps via `effectiveQ`, but this guard is the load-bearing
  // backstop for any other code path that builds the advertisements list
  // by hand. Coding-guideline rule applies here: throw on programming
  // mistakes (vs. logging warnings for runtime issues) so the failure is
  // loud at the first call site. See PR #284 r12 CodeRabbit review.
  if (!Number.isInteger(q) || q < 1) {
    throw new Error(
      `decideLoadQuorum: q must be a positive integer; got ${String(q)}. ` +
        `Pass the value through effectiveQ() / runLoadQuorum() so the ` +
        `clamp against the responding cohort fires before reaching this ` +
        `function.`,
    );
  }
  if (advertisements.length === 0) {
    return {
      ok: false,
      reason: 'no-peers-queried',
      respondingCount: 0,
      effectiveQ: q,
      agreement: new Map(),
    };
  }

  // Tally agreement keyed by the hex form of each peer's hash (for
  // tip-hash votes) or `UNKNOWN_DOC_TALLY_KEY` (for `'unknown-doc'`
  // disclaim votes). Hex is used as the Map key for tip-hash buckets so
  // two peers returning byte-identical hashes collide on the same bucket;
  // the unknown-doc sentinel uses a non-hex literal key that cannot
  // collide with any real `tipsHashToHex` output (64-char lowercase hex).
  // Mismatches are human-readable in the logged `agreement` snapshot.
  const agreement = new Map<string, string[]>();
  let respondingCount = 0;
  for (const adv of advertisements) {
    if (adv.hash === null) {
      // Non-vote: timeout or non-disclaim decline. Skip without penalty
      // -- a stale `knownPeers` cache that points at offline peers must
      // not be counted as disagreement, otherwise a partition + small
      // mesh would be indistinguishable from active Byzantine behaviour.
      continue;
    }
    respondingCount++;
    // `'unknown-doc'` votes tally under a dedicated reserved key so a
    // Q-of-K majority of disclaims is detectable by the orchestrator
    // exactly like a tip-hash majority. The key is intentionally NOT a
    // hex string so it cannot collide with `tipsHashToHex` output.
    const key =
      adv.hash === 'unknown-doc'
        ? UNKNOWN_DOC_TALLY_KEY
        : tipsHashToHex(adv.hash);
    let bucket = agreement.get(key);
    if (!bucket) {
      bucket = [];
      agreement.set(key, bucket);
    }
    bucket.push(adv.peerId);
  }

  if (respondingCount === 0) {
    // No peer voted -- partition, all timed out, all declined.
    const summary = new Map<string, number>();
    return {
      ok: false,
      reason: 'insufficient-responses',
      respondingCount,
      effectiveQ: q,
      agreement: summary,
    };
  }

  // Tip-hash votes take PRIORITY over `'unknown-doc'` votes when
  // selecting the winning bucket. The probe is racing every peer
  // returned by `getConnections()` -- which is the WHOLE libp2p mesh,
  // not only peers that have specifically opened this document. So an
  // honest peer that legitimately holds a document and votes its
  // `tipsHash` can be outvoted by unrelated peers in the same mesh
  // that simply have not registered the document path (each of which
  // legitimately returns the `'unknown-doc'` sentinel). Without this
  // precedence rule, two such uninvolved peers could outvote the one
  // peer that actually has the document and force the loader into the
  // new-doc-creation path -- forking the document silently. See
  // PR #284 r19 Copilot review.
  //
  // Precedence rule: if ANY peer returned a real tip-hash, the
  // `'unknown-doc'` bucket is excluded from the agreement vote. The
  // tip-hash buckets then decide quorum among themselves (Q-of-respondingCount
  // for the winning hash). The new-doc path is only ever taken when
  // ZERO peers reported a real tip-hash AND the `'unknown-doc'` bucket
  // meets Q -- i.e. the entire responding cohort genuinely disclaims
  // the document.
  //
  // `respondingCount` is intentionally NOT decremented when we exclude
  // the `'unknown-doc'` bucket: it still represents the cohort that
  // responded at all (used for the structured failure reason
  // 'insufficient-responses' versus 'no-majority'). The
  // `unknownDocBucketSize` count is still surfaced in the `agreement`
  // snapshot for operator visibility.
  const hasTipHashVote = [...agreement.keys()].some(
    (k) => k !== UNKNOWN_DOC_TALLY_KEY,
  );
  const eligibleBuckets = hasTipHashVote
    ? [...agreement.entries()].filter(
        ([key]) => key !== UNKNOWN_DOC_TALLY_KEY,
      )
    : [...agreement.entries()];

  // Find the largest bucket among ELIGIBLE buckets. Ties are broken
  // arbitrarily by Map iteration order (insertion order); ties never
  // affect ok/!ok because both buckets would have the same size and we
  // only accept if size >= q.
  let bestKey: string | null = null;
  let bestPeers: string[] = [];
  for (const [key, peers] of eligibleBuckets) {
    if (peers.length > bestPeers.length) {
      bestKey = key;
      bestPeers = peers;
    }
  }

  if (bestKey === null || bestPeers.length < q) {
    // Either no responses (handled above) or the largest agreeing cohort
    // is too small. Build a compact `hash -> count` snapshot for diagnostics.
    const summary = new Map<string, number>();
    for (const [key, peers] of agreement.entries()) {
      summary.set(key, peers.length);
    }
    // Distinguish "we got responses but none agreed enough" from the
    // earlier "no one responded" branch.
    const reason =
      respondingCount < q ? 'insufficient-responses' : 'no-majority';
    return {
      ok: false,
      reason,
      respondingCount,
      effectiveQ: q,
      agreement: summary,
    };
  }

  return {
    ok: true,
    kind: bestKey === UNKNOWN_DOC_TALLY_KEY ? 'new-doc' : 'tip-hash',
    winningHashHex: bestKey,
    agreeingPeerIds: bestPeers,
    respondingCount,
    effectiveQ: q,
  };
}

/**
 * Compute the default quorum threshold `Q` for a given `K` using the
 * strict-majority rule `Math.floor(K / 2) + 1`. This tolerates `floor((K-1)/2)`
 * faulty peers (one fault at K=3, K=4; two at K=5) — the standard BFT
 * threshold — and is the formula `PeerborneConfig.loadQuorumQ` defaults to
 * when the user does not override it.
 *
 * Worked examples:
 *   - K=1 → Q=1
 *   - K=2 → Q=2
 *   - K=3 → Q=2 (one fault tolerated; previously K=3 → Q=3 under
 *     `Math.ceil(K/2)+1`, which made the gate refuse to pass with even a
 *     single non-vote and defeated the fault-tolerance intent)
 *   - K=4 → Q=3
 *   - K=5 → Q=3
 *   - K=7 → Q=4
 *
 * Pulled out so the loader, the config docstring, and the test matrix all
 * reference one canonical formula. Callers must still pass the result
 * through `effectiveQ(q, k)` to handle `K=0` and user overrides.
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
 * See PR #284 r9 Copilot review.
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
 * Compute the effective `Q` (quorum threshold) given a configured value and
 * the effective K. Clamped to `[1, K]` so a misconfigured `Q > K` cannot
 * make quorum unreachable, and `Q <= 0` does not silently bypass the gate.
 *
 * Defensive against non-finite inputs as a second line of defence behind
 * {@link validateLoadQuorumConfig}. Without the `Number.isFinite` guard,
 * `effectiveQ(NaN, 3)` returned `NaN` (all comparisons against `NaN` are
 * false), and `decideLoadQuorum` then evaluated `bestPeers.length < NaN`
 * as false — so the gate passed with a single responding peer. We
 * collapse NaN/Infinity to {@link defaultQuorumQ}(k) here as a fallback
 * that mirrors the orchestrator's `?? defaultQuorumQ(k)` default. See
 * PR #284 r9 Copilot review.
 */
export function effectiveQ(configuredQ: number, k: number): number {
  if (k <= 0) return 0;
  if (!Number.isFinite(configuredQ)) return defaultQuorumQ(k);
  if (configuredQ < 1) return 1;
  if (configuredQ > k) return k;
  // Floor for the same reason as `effectiveK`: a fractional Q would
  // otherwise produce a non-integer threshold that compares strangely
  // against integer vote counts.
  return Math.floor(configuredQ);
}

/**
 * Upper bound (milliseconds) for {@link validateLoadQuorumConfig}'s
 * `loadQuorumTimeoutMs` check. Five minutes is comfortably larger than any
 * realistic per-probe budget on a wide-area mesh (the default is 5 s) but
 * small enough to catch a typo like `5000000` (5 000 s = ~83 min) or a
 * mistakenly-passed nanosecond value before it stalls `open()` for an
 * absurd duration. See PR #284 r15 Copilot review.
 */
export const LOAD_QUORUM_TIMEOUT_MS_MAX = 5 * 60 * 1000;

/**
 * Validate the load-quorum tuning knobs from {@link PeerborneConfig}.
 *
 * Runs at {@link Peerborne.initialize} time so a misconfigured value is
 * surfaced loudly at startup rather than silently degrading every
 * subsequent `load()` call. Required behavior under PR #284 r9 Copilot
 * review (issues #2/#3): `loadQuorumK: 1.5` previously slipped through
 * `Math.min(configuredK, peersLen)` to produce `peers.slice(0, 1.5)`
 * which probes only 1 peer (silent single-peer load); `loadQuorumQ: NaN`
 * propagated through `effectiveQ` to make `bestPeers.length < NaN`
 * evaluate as false (silent single-peer quorum pass). Both classes of
 * misconfig are now rejected here with a clear operator-visible error.
 *
 * `loadQuorumTimeoutMs` is also validated here under PR #284 r15 Copilot
 * review: the value flows directly into `setTimeout(...)` inside the
 * tip-advertise probe race, where `NaN`/`Infinity`/`0`/negative are coerced
 * to immediate-fire / overflow behaviour by the timer queue. Every probe
 * then resolves as a non-vote and quorum fails on every load attempt even
 * with a fully healthy mesh — silently breaking the gate. We require a
 * finite positive integer no greater than
 * {@link LOAD_QUORUM_TIMEOUT_MS_MAX} so an operator typo or a misplaced
 * decimal is caught at startup.
 *
 * `loadQuorumK` and `loadQuorumQ` MUST be finite positive integers
 * (Number.isInteger(x) && x >= 1).
 * `loadQuorumTimeoutMs` MUST be a finite positive integer in the closed
 * range `[1, LOAD_QUORUM_TIMEOUT_MS_MAX]`.
 *
 * Rejects:
 *   - NaN / Infinity / -Infinity (all knobs)
 *   - non-integers (e.g. 1.5, 2.7) (all knobs)
 *   - zero and negative values (0, -1) (all knobs)
 *   - `loadQuorumTimeoutMs > LOAD_QUORUM_TIMEOUT_MS_MAX`
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
 *   to validate. Pass-through fields (`enabled`, `allowSinglePeer`) are
 *   intentionally NOT validated here; only K, Q, and timeoutMs are the
 *   load-bearing trust/timing knobs.
 */
export function validateLoadQuorumConfig(config: {
  loadQuorumK?: number;
  loadQuorumQ?: number;
  loadQuorumTimeoutMs?: number;
}): void {
  const checkPositiveInt = (name: string, value: number | undefined): void => {
    if (value === undefined) return;
    if (
      typeof value !== 'number' ||
      !Number.isInteger(value) ||
      value < 1
    ) {
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
  checkPositiveInt('loadQuorumK', config.loadQuorumK);
  checkPositiveInt('loadQuorumQ', config.loadQuorumQ);
  checkBoundedPositiveInt(
    'loadQuorumTimeoutMs',
    config.loadQuorumTimeoutMs,
    LOAD_QUORUM_TIMEOUT_MS_MAX,
  );
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
 * See PR #284 r10 Copilot review.
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
 *   - `'no-majority'` — peers responded but no single tip-set hash reached
 *     the `Q`-of-respondingCount agreement threshold.
 *   - `'no-peers-queried'` — `decideLoadQuorum` was called with an empty
 *     advertisement list; surfaced for defensive completeness.
 *   - `'invalid-config'` — the operator misconfigured the gate (e.g.
 *     `loadQuorumK <= 0`) in a way that would silently disable trust
 *     defences. Surfaced as a configuration error rather than a quorum
 *     failure so the misconfiguration is loud at `open()` time. See
 *     PR #284 r5 Copilot review.
 *   - `'bind-check-failed-all-agreeing-peers'` — quorum agreement was
 *     reached, but EVERY peer in the agreeing cohort served a full-load
 *     response whose `tips` array did not hash to `winningHashHex` (or
 *     omitted `tips` entirely). Distinct from `'no-majority'` so callers
 *     can tell "no peer was even willing to vote" apart from "the agreeing
 *     cohort was entirely Byzantine on the load step". Surfaced by
 *     `PeerborneDocument.load()` after exhausting every narrowed peer.
 *     See PR #284 r6 Copilot review for the DoS rationale: without the
 *     per-peer retry, a single malicious peer in the agreeing cohort could
 *     vote for the majority hash and then serve a mismatched full load to
 *     unilaterally abort the whole load, preventing the loader from
 *     trying any of the OTHER honest agreeing peers.
 */
export type LoadQuorumFailedReason =
  | 'insufficient-responses'
  | 'no-majority'
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
   *  tip-hash votes AND the `'unknown-doc'` sentinel. Timeouts and
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
   *  they served instead. Empty for all other reasons. See PR #284 r6
   *  Copilot review. */
  public readonly agreeingPeerBindFailures: ReadonlyMap<string, string>;
  /** Structured detail string for the `'invalid-config'` reason (e.g.
   *  `loadQuorumK must be a positive integer; got NaN`). Exposed as a
   *  field so callers (notably `runLoadQuorum`'s post-init guard) can
   *  forward the validator's structured wording into a rethrown error
   *  with a different `documentPath` WITHOUT regex-parsing
   *  `error.message`. Empty/undefined for all other reasons. See PR
   *  #284 r23 Copilot review. */
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
     *  `'-Infinity'`) via {@link formatConfigValue}, not the misleading
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
    this.agreeingPeerBindFailures =
      opts.agreeingPeerBindFailures ?? new Map();
    // Persist the structured detail so callers can forward it across a
    // rethrow without parsing the human-readable `error.message`. Only
    // load-bearing for `reason === 'invalid-config'`; harmless for
    // other reasons (where the constructor composes `detail` from the
    // structured fields and `opts.detail` is ignored).
    this.detail = opts.detail;
  }
}
