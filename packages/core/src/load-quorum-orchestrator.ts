/**
 * Orchestration helper for the initial-load quorum gate (#186 / #189 §5.4.2).
 *
 * The pure quorum decision module (`load-quorum.ts`) is responsible for
 * computing whether a set of tip-advertise responses meets the agreement
 * threshold. It is intentionally I/O-free so the trust-critical decision
 * logic can be audited and unit-tested in isolation.
 *
 * This module sits one layer up: it takes a peer list and a caller-supplied
 * probe function and orchestrates the K-of-Q probe round, returning the
 * narrowed agreeing-cohort peer list plus the winning hash (or throwing
 * `LoadQuorumFailedError` on any failure mode). It is also pure with respect
 * to libp2p/Helia -- the only network coupling lives in the `probeFn`
 * callback that `PeerborneDocument.load()` passes in. That decoupling
 * exists so the production orchestration path can be exercised by unit tests
 * without a real libp2p/Helia stack (the codebase has no precedent for full
 * libp2p test doubles, and the load orchestration is a security gate that
 * needs direct regression coverage).
 *
 * Callers wire this module by:
 *
 *   1. Computing the peer list (already-deduped by libp2p PeerId so a single
 *      peer with multiple open connections cannot cast multiple votes).
 *   2. Passing a `probeFn` that returns either legacy `tipsHash` bytes, a V4
 *      `{ hash, signerAuthority }` vote whose authority the caller has already
 *      authenticated, or `null` for any non-vote outcome (timeout, decline,
 *      decryption failure, etc.).
 *   3. Passing a `peerIdOf` extractor so this module can narrow the peer list
 *      down to the agreeing cohort without knowing about Multiaddrs.
 *
 * The return value is either:
 *   - `{ skipped: true }` — quorum disabled, or no peers (caller falls through
 *     to the legacy single-peer load loop / treats as new document).
 *   - `{ ok: true, narrowedPeers, winningHashHex }` — quorum passed; caller
 *     does the full document-load against `narrowedPeers` with the binding
 *     check pinned to `winningHashHex`.
 *
 * Failures (insufficient responses, no majority, etc.) are thrown as
 * `LoadQuorumFailedError` so the caller's existing `instanceof`-based
 * propagation works unchanged.
 */

import {
  decideLoadQuorum,
  defaultQuorumQ,
  effectiveK,
  LoadQuorumFailedError,
  PeerTipAdvertisement,
  validateLoadQuorumConfig,
} from './load-quorum.js';
import { TIPS_HASH_LENGTH, tipsHashToHex } from './tips-hash.js';
import { copyUnsharedUint8Array } from './utils.js';

/**
 * A V4 vote attributed to a signer authority authenticated by `probeFn`.
 *
 * This orchestrator only validates the returned shape and de-duplicates the
 * authority string. It does not verify a signature or decide whether the
 * authority is trusted; callers MUST do both before returning this object.
 */
export interface SignerAttributedLoadQuorumVote {
  readonly hash: Uint8Array;
  readonly signerAuthority: string;
}

export type LoadQuorumProbeResult =
  | Uint8Array
  | SignerAttributedLoadQuorumVote
  | 'unknown-doc'
  | null;

type NormalizedLoadQuorumProbeResult =
  | {
      readonly kind: 'vote';
      readonly hash: Uint8Array;
      readonly signerAuthority?: string;
    }
  | { readonly kind: 'unknown-doc' }
  | { readonly kind: 'non-vote' };

function normalizeLoadQuorumProbeResult(
  result: unknown,
): NormalizedLoadQuorumProbeResult {
  if (result === 'unknown-doc') return { kind: 'unknown-doc' };

  const legacyHash = snapshotVoteHash(result);
  if (legacyHash !== undefined) {
    return { kind: 'vote', hash: legacyHash };
  }
  if (result === null || typeof result !== 'object') {
    return { kind: 'non-vote' };
  }

  let hashValue: unknown;
  let signerAuthority: unknown;
  try {
    const candidate = result as Partial<SignerAttributedLoadQuorumVote>;
    hashValue = candidate.hash;
    signerAuthority = candidate.signerAuthority;
  } catch {
    return { kind: 'non-vote' };
  }
  if (typeof signerAuthority !== 'string') return { kind: 'non-vote' };
  const hash = snapshotVoteHash(hashValue);
  return hash === undefined
    ? { kind: 'non-vote' }
    : { kind: 'vote', hash, signerAuthority };
}

function snapshotVoteHash(value: unknown): Uint8Array | undefined {
  try {
    return copyUnsharedUint8Array(
      value,
      TIPS_HASH_LENGTH,
      TIPS_HASH_LENGTH,
      'load-quorum vote hash',
    );
  } catch {
    return undefined;
  }
}

/**
 * Config inputs for `runLoadQuorum`. Mirrors the relevant subset of
 * `PeerborneConfig` so the orchestrator does not import the heavy config
 * module.
 */
export interface LoadQuorumOrchestratorConfig {
  enabled?: boolean;
  /** Maximum number of peers to probe. Defaults to 3. */
  k?: number;
  /** Minimum agreement threshold. An explicit value is a hard floor;
   * defaults to `defaultQuorumQ(effectiveK)`. */
  q?: number;
  /** Per-probe timeout in ms (caller-enforced inside `probeFn`). Stored here
   * for symmetry with `PeerborneConfig` and validated alongside K/Q so a
   * `NaN`/`Infinity`/`0`/negative/over-bound value (which would coerce
   * `setTimeout` to immediate-fire / overflow and silently turn every probe
   * into a non-vote) is caught loud-and-early. This module does not consume
   * the value itself — `probeFn` is responsible for the wall-clock timeout
   * — but it MUST flow through {@link validateLoadQuorumConfig} on every
   * load attempt as defence-in-depth against post-`initialize()` mutation. */
  timeoutMs?: number;
  /** Allow a single-peer fallback path when only one peer is reachable. */
  allowSinglePeer?: boolean;
}

/**
 * Result of running the quorum orchestration over a peer list.
 *
 *   - `{ skipped: true }` — gate disabled or no peers known. Caller
 *     falls through to the legacy single-peer load loop.
 *   - `{ newDoc: true }` — a Q-of-K majority of probed peers explicitly
 *     disclaimed the document (returned `'unknown-doc'` from the probe).
 *     Caller should treat as "document does not exist yet" and let
 *     `load()` return `false` so a fresh `open()` creates the document
 *     on top of the existing swarm. The previous design conflated
 *     unknown-doc with partition / timeout and made new-doc creation fail
 *     in an existing mesh.
 *   - `{ ok: true, narrowedPeers, winningHashHex }` — quorum passed on
 *     a tip-set hash; caller does the full document-load against
 *     `narrowedPeers` with the binding check pinned to `winningHashHex`.
 */
export type LoadQuorumOrchestratorResult<T> =
  | { skipped: true }
  | { newDoc: true }
  | { ok: true; narrowedPeers: T[]; winningHashHex: string };

/**
 * Run the initial-load quorum orchestration round.
 *
 * @param peers The de-duplicated list of candidate peers (typically Multiaddrs
 *   from `getConnections()`). Order is preserved into `narrowedPeers` so the
 *   caller's preferred-peer placement survives.
 * @param peerIdOf Extracts a stable peer-id key from each peer entry; used
 *   to match agreeing-cohort PeerIds back to the original peer entries.
 * @param probeFn Probes one peer for a legacy `tipsHash` or a V4 vote whose
 *   signer authority the callback has already authenticated and authorized.
 *   This orchestrator does not verify that claim. Return `null` for any
 *   non-vote outcome (timeout, decline, decryption failure, malformed hash,
 *   etc.). If `probeFn` throws or rejects, the orchestrator catches
 *   it at the boundary, logs the error, and records the peer as a non-vote
 *   so the surrounding `LoadQuorumFailedError` contract is preserved. Even
 *   so, a thrown probe still indicates a bug in the caller's probe
 *   implementation and should be fixed at the source.
 * @param documentPath Used to construct the `LoadQuorumFailedError` on
 *   failure; carries the document name into operator-visible logs.
 * @param config Quorum tuning knobs (see `LoadQuorumOrchestratorConfig`).
 *
 * @returns Either `{ skipped }` (gate disabled or no peers) or
 *   `{ ok: true, narrowedPeers, winningHashHex }` on success. Throws
 *   `LoadQuorumFailedError` on any failure mode (no responses, no majority,
 *   insufficient single-peer probe).
 */
export async function runLoadQuorum<T>(opts: {
  peers: readonly T[];
  peerIdOf: (peer: T) => string;
  probeFn: (peer: T) => Promise<LoadQuorumProbeResult>;
  documentPath: string;
  config?: LoadQuorumOrchestratorConfig;
}): Promise<LoadQuorumOrchestratorResult<T>> {
  const { peers, peerIdOf, probeFn, documentPath, config } = opts;
  const enabled = config?.enabled ?? true;

  // Re-validate booleans/K/Q/timeoutMs on every `runLoadQuorum` call as
  // defence-in-depth against post-`initialize()` mutation of the shared
  // config object (direct mutation, deep-clone reuse with a corrupt
  // field, an operator helper that writes back `NaN`, etc.).
  // `Peerborne.initialize()` runs `validateLoadQuorumConfig` once at
  // startup so the static misconfiguration case (typo, bad cast at
  // config load) is already covered; this second-line check exists for
  // the dynamic case where a previously-valid K, Q, or timeoutMs has
  // since become `NaN`/`Infinity`/0/-1/1.5/over-bound.
  //
  // Without this guard, a mutated `K = NaN` would slip through to
  // `effectiveK(NaN, peers)`, whose floor/finiteness guards return 0;
  // the K=0 branch below would return
  // `{ skipped: true }`, and `PeerborneDocument.load()` would fall
  // through to the legacy unbound load even though `loadQuorumEnabled`
  // is still `true` — silently violating the operator's intent of a
  // quorum-protected load. A mutated `timeoutMs = NaN`/`Infinity`/`0`/
  // negative similarly would flow into `setTimeout(...)` inside the
  // probe race, coerce to immediate-fire, and turn every probe into a
  // non-vote so quorum fails on every load even with a healthy mesh.
  // Throw a structured `invalid-config` `LoadQuorumFailedError` so the
  // failure is loud at the load-attempt boundary instead.
  //
  // The validator's documentPath placeholder (`<config>`) is replaced
  // with the actual `documentPath` here so operator logs surface which
  // document's load attempt tripped the post-init mutation.
  try {
    validateLoadQuorumConfig({
      loadQuorumEnabled: config?.enabled,
      loadQuorumK: config?.k,
      loadQuorumQ: config?.q,
      loadQuorumTimeoutMs: config?.timeoutMs,
      loadQuorumAllowSinglePeer: config?.allowSinglePeer,
    });
  } catch (err) {
    if (
      err instanceof LoadQuorumFailedError &&
      err.reason === 'invalid-config'
    ) {
      // Forward the validator's structured `detail` directly so the
      // rethrown error carries the "<name> must be a positive integer;
      // got <value>" wording without the `'<config>'` placeholder
      // leaking through. The previous implementation regex-parsed
      // `err.message`, which was brittle: any future change to the
      // error-message format (e.g. moving the operator-guidance
      // trailer) would silently degrade the surfaced config error to
      // the generic fallback. The structured field is the load-bearing
      // path now.
      const detail = err.detail ?? 'invalid load-quorum configuration';
      throw new LoadQuorumFailedError({
        documentPath,
        reason: 'invalid-config',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map(),
        detail,
      });
    }
    throw err;
  }

  if (enabled === false) {
    return { skipped: true };
  }

  const configuredK = config?.k ?? 3;
  const allowSinglePeer = config?.allowSinglePeer ?? false;

  const k = effectiveK(configuredK, peers.length);
  // Derive the default Q from the EFFECTIVE K (after limiting K to the
  // currently known peer count), but preserve an explicit Q as a hard trust
  // floor. A network partition must not silently reduce an operator's Q=4
  // policy to Q=2 merely because only two peers remain visible.
  const explicitQ = config?.q;
  const q = explicitQ ?? defaultQuorumQ(k);

  if (k === 0) {
    // No peers known. Treat as "new document" — caller falls through to
    // the legacy "no peer could load" branch.
    return { skipped: true };
  }

  if (explicitQ !== undefined && explicitQ > k) {
    console.warn(
      `[${documentPath}] Initial-load quorum FAILED: only ${k} peer${
        k === 1 ? '' : 's'
      } can be probed, below explicit loadQuorumQ=${explicitQ}. Aborting load.`,
    );
    throw new LoadQuorumFailedError({
      documentPath,
      reason: 'insufficient-responses',
      respondingCount: 0,
      requiredQ: explicitQ,
      agreement: new Map(),
    });
  }

  if (k === 1 && !allowSinglePeer) {
    // Only one peer reachable AND the operator did not opt into the
    // single-peer pass-through. With a lone peer we cannot distinguish
    // "honest solo peer" from "malicious peer serving a forged state",
    // so we refuse on policy grounds rather than on the BFT majority
    // formula -- with `effectiveK = 1`, `defaultQuorumQ(1) = 1`, so
    // surfacing the computed `q` (which is 1) as `requiredQ` would be
    // misleading: it would suggest "the lone peer's vote was sufficient
    // numerically but happened not to land", when the truth is "we
    // explicitly refuse to trust any single peer regardless of how it
    // voted". Surface the load-bearing policy requirement (`requiredQ =
    // 2`, the smallest cohort that gives any Byzantine fault tolerance)
    // so the error message reads as a policy refusal, not a vote-count
    // shortfall. Operators who genuinely want single-peer behaviour
    // must set `loadQuorumAllowSinglePeer: true` explicitly.
    throw new LoadQuorumFailedError({
      documentPath,
      reason: 'insufficient-responses',
      respondingCount: 0,
      requiredQ: 2,
      agreement: new Map(),
    });
  }

  if (k === 1 && allowSinglePeer) {
    // Single-peer pass-through. Probe the one known peer; if it responds at
    // all we proceed with the legacy load. Warn loudly so operators can
    // spot the regression. Q is forced to 1 here.
    //
    // The warning text covers BOTH causes of `k === 1`:
    //   1. peer scarcity — only one peer is reachable in the mesh
    //      (`peers.length === 1`), OR
    //   2. configured K — the operator set `loadQuorumK = 1` even though
    //      more peers ARE known (`peers.length > 1`); `effectiveK` clamps
    //      the slice to 1 and only that one peer is probed.
    // The previous wording "only one peer known" was accurate for case 1
    // but actively misleading for case 2 — operators saw the warning even
    // though their mesh had multiple peers, making it impossible to tell
    // whether the regression was peer-availability (a runtime fact) or a
    // misconfigured K (their own knob). Include the configured K and the
    // actual peer count so both cases read accurately.
    console.warn(
      `[${documentPath}] Initial-load quorum: only one peer will be probed ` +
        `(loadQuorumK=${configuredK}, ${peers.length} peer${peers.length === 1 ? '' : 's'} known; ` +
        `loadQuorumAllowSinglePeer=true); trust assumptions degraded back ` +
        `to single-peer load. ` +
        `${peers.length > 1 ? 'Increase loadQuorumK above 1' : 'Configure additional peers'} ` +
        `to restore Byzantine-fault-tolerant quorum semantics.`,
    );
    const probedPeer = peers[0];
    // Contain probe errors at the orchestrator boundary. The orchestrator
    // contract (see module docstring + the per-peer note above on
    // `probeFn`) is that any non-vote outcome — including a thrown/rejected
    // probe — is surfaced as a non-vote. Without this catch a misbehaving
    // `probeFn` would let the underlying error escape past the orchestrator
    // and bypass the `LoadQuorumFailedError` API contract `load()` callers
    // are written against.
    let probe: LoadQuorumProbeResult;
    try {
      probe = await probeFn(probedPeer);
    } catch {
      console.warn(
        `[${documentPath}] Initial-load quorum single-peer probe threw; ` +
          `recording as non-vote.`,
      );
      probe = null;
    }
    const normalizedProbe = normalizeLoadQuorumProbeResult(probe);
    if (normalizedProbe.kind === 'non-vote') {
      throw new LoadQuorumFailedError({
        documentPath,
        reason: 'insufficient-responses',
        respondingCount: 0,
        requiredQ: 1,
        agreement: new Map(),
      });
    }
    if (normalizedProbe.kind === 'unknown-doc') {
      // The single probed peer explicitly disclaims the document. Treat
      // as new-doc-creation -- `load()` will return `false` so a fresh
      // `open()` can create the document on top of the swarm. This is
      // symmetric with the K-of-Q `kind === 'new-doc'` branch below.
      console.warn(
        `[${documentPath}] Initial-load quorum single-peer probe returned ` +
          `'unknown-doc'; treating as new-document path (load() will return false).`,
      );
      return { newDoc: true };
    }
    const winningHashHex = tipsHashToHex(normalizedProbe.hash);
    // Narrow to ONLY the probed peer. Without this, the subsequent
    // snapshot/doc-load loop would also try the other peers in the original
    // peer list (which were never probed) and bind their served state
    // against THIS peer's hash — a non-sequitur that could either pass the
    // binding by coincidence or fail it even though single-peer mode was
    // opted-into.
    return { ok: true, narrowedPeers: [probedPeer], winningHashHex };
  }

  // Standard K-of-Q quorum path. Probe the first K peers in parallel,
  // decide agreement, narrow.
  //
  // Contain probe errors at the orchestrator boundary. The contract is
  // that any non-vote outcome — including a thrown/rejected `probeFn` —
  // is surfaced as a non-vote (`hash: null`). Without the per-probe
  // catch, a single rejecting `probeFn` would reject the whole
  // `Promise.all`, bubble past the orchestrator, and bypass the
  // `LoadQuorumFailedError` API the caller is written against —
  // surfacing a raw probe error from `load()` instead of the structured
  // `LoadQuorumFailedError(insufficient-responses)` callers expect.
  const probedPeers = peers.slice(0, k);
  const probeResults = await Promise.all(
    probedPeers.map(async (peer) => {
      let result: LoadQuorumProbeResult;
      try {
        result = await probeFn(peer);
      } catch {
        console.warn(
          `[${documentPath}] Initial-load quorum probe for peer ${peerIdOf(
            peer,
          )} threw; recording as non-vote.`,
        );
        result = null;
      }
      return { peer, result: normalizeLoadQuorumProbeResult(result) };
    }),
  );
  // V4 votes are attributed to the signing authority that `probeFn` already
  // verified, not merely to the transport's libp2p PeerId. This orchestrator
  // does not perform that verification. Keep only the first vote from each
  // authority so one credential reused across many Sybil PeerIds cannot
  // satisfy Q by itself. Legacy probes still return bare Uint8Array values and
  // retain their historical PeerId-based tally unchanged.
  const seenSignerAuthorities = new Set<string>();
  const advertisements: PeerTipAdvertisement[] = probeResults.map(
    ({ peer, result }) => {
      let hash: Uint8Array | 'unknown-doc' | null = null;
      if (result.kind === 'vote' && result.signerAuthority !== undefined) {
        if (
          result.signerAuthority.length === 0 ||
          seenSignerAuthorities.has(result.signerAuthority)
        ) {
          hash = null;
        } else {
          seenSignerAuthorities.add(result.signerAuthority);
          hash = result.hash;
        }
      } else if (result.kind === 'vote') {
        hash = result.hash;
      } else if (result.kind === 'unknown-doc') {
        hash = 'unknown-doc';
      }
      return { peerId: peerIdOf(peer), hash };
    },
  );
  const decision = decideLoadQuorum(advertisements, q);
  if (!decision.ok) {
    console.warn(
      `[${documentPath}] Initial-load quorum FAILED: ` +
        `${decision.reason} (${decision.respondingCount} responses, ` +
        `required ${decision.effectiveQ}). Aborting load.`,
    );
    throw new LoadQuorumFailedError({
      documentPath,
      reason: decision.reason,
      respondingCount: decision.respondingCount,
      requiredQ: decision.effectiveQ,
      agreement: decision.agreement,
    });
  }
  if (decision.kind === 'new-doc') {
    // Q-of-K peers all returned the `'unknown-doc'` sentinel: the swarm
    // collectively disclaims the document. Surface as the new-doc path
    // so `PeerborneDocument.load()` returns `false` and a fresh
    // `open()` can create the document on top of the existing swarm.
    // Defense remains Q-Byzantine: a single lying peer in a 3-of-3 mesh
    // whose other peers hold the doc cannot force this branch (their
    // tip-hash bucket wins the tally).
    console.log(
      `[${documentPath}] Initial-load quorum passed (new-doc): ` +
        `${decision.agreeingPeerIds.length}/${decision.respondingCount} ` +
        `peers disclaimed the document; treating as new-document path ` +
        `(load() will return false).`,
    );
    return { newDoc: true };
  }
  console.log(
    `[${documentPath}] Initial-load quorum passed: ` +
      `${decision.agreeingPeerIds.length}/${decision.respondingCount} ` +
      `peers agreed on tipsHash=${decision.winningHashHex.slice(0, 12)}...`,
  );
  // Narrow `peers` to only the agreeing cohort. The caller then asks one of
  // these peers for the full state; with quorum agreement, any single
  // agreeing peer's load is defended by Q-1 other peers attesting to the
  // same tip set. Order is preserved.
  const agreeingSet = new Set(decision.agreeingPeerIds);
  const narrowed = peers.filter((p) => agreeingSet.has(peerIdOf(p)));
  // Defensive: at least one agreeing peer must remain. If peer-id
  // extraction loses every peer (should be impossible because we built
  // `agreeingSet` from `peerIdOf` outputs over the same `peers` array),
  // FAIL CLOSED rather than silently widening the load to ALL peers --
  // which would re-introduce non-agreeing peers into the load path and
  // bypass the very narrowing the quorum gate is meant to enforce. The
  // previous fallback (`narrowed.length > 0 ? narrowed : [...peers]`)
  // expanded trust scope to escape a no-op edge case, which is exactly
  // the kind of silent-degrade-to-unsafe-default that the gate exists to
  // prevent. Surface as a structured `LoadQuorumFailedError` so callers
  // see the same error contract as any other quorum failure.
  if (narrowed.length === 0) {
    throw new LoadQuorumFailedError({
      documentPath,
      reason: 'no-majority',
      respondingCount: decision.respondingCount,
      requiredQ: decision.effectiveQ,
      // Re-derive a `hash -> count` agreement summary from the agreeing
      // cohort so the structured error carries the same observability
      // payload as the normal `'no-majority'` path (decideLoadQuorum's
      // success branch does not expose the full agreement map; we
      // reconstruct just the winning bucket here).
      agreement: new Map([
        [decision.winningHashHex, decision.agreeingPeerIds.length],
      ]),
    });
  }
  return {
    ok: true,
    narrowedPeers: narrowed,
    winningHashHex: decision.winningHashHex,
  };
}
