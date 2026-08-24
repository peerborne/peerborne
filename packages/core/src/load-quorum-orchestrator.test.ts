/**
 * Integration tests for the load-quorum orchestrator (#186 / #189 §5.4.2).
 *
 * The pure helpers in `load-quorum.ts` (decision logic) and `tips-hash.ts`
 * (canonical hashing) have their own unit tests that prove the trust-critical
 * primitives are correct in isolation. Those tests do NOT exercise the
 * orchestration the production loader runs end-to-end -- probe K peers,
 * narrow to the agreeing cohort, surface single-peer fallback with a strict
 * binding, raise `LoadQuorumFailedError` on the right reasons.
 *
 * The orchestration code path lives in
 * `runLoadQuorum` (called by `PeerborneDocument.load()`) and was extracted
 * here specifically so the security gate can be regression-tested without a
 * real libp2p/Helia stack. (The codebase has no precedent for full libp2p
 * test doubles: existing tests in `peerborne.test.ts` replicate logic
 * against mocks rather than instantiating `PeerborneDocument`, since the
 * module's top-level imports drag in ESM-only libp2p packages that Jest's
 * default CommonJS resolver cannot load. Standing up that infrastructure
 * inside this PR is the explicit "stop and report" threshold flagged for
 * load-quorum testing; extracting the orchestration into a pure-ish module
 * gives the equivalent coverage with no new test-infra debt.)
 *
 * This file closes the gap raised by Copilot's PR #284 r4 review: the
 * production quorum path is now covered by a test matrix that exercises all
 * five flagged cases (a) all-agree, (b) majority-agree-with-dissenter,
 * (c) vote-vs-serve mismatch, (d) insufficient responses (timeouts), and
 * (e) single-peer fallback path.
 */

import {
  describe,
  expect,
  test,
  jest,
  beforeEach,
  afterEach,
} from '@jest/globals';
import { runLoadQuorum } from './load-quorum-orchestrator.js';
import { dedupePeersByPeerId, LoadQuorumFailedError } from './load-quorum.js';
import { tipsHashToHex } from './tips-hash.js';

/**
 * Fixture hashes. Each is a 32-byte fixed-byte buffer so the hex form is
 * trivial to compute and assert against. Mirrors the pattern in
 * `load-quorum.test.ts`.
 */
function fixedByteHash(byte: number): Uint8Array {
  const buf = new Uint8Array(32);
  buf.fill(byte);
  return buf;
}
const HASH_X = fixedByteHash(0xaa);
const HASH_Y = fixedByteHash(0xbb);
const HASH_X_HEX = tipsHashToHex(HASH_X);
const HASH_Y_HEX = tipsHashToHex(HASH_Y);

/**
 * Test "peer" type. The orchestrator is generic on `T`; in production T is
 * `Multiaddr` but for tests a string is enough -- the orchestrator only ever
 * passes peers back through the caller-supplied `peerIdOf` extractor and into
 * the caller-supplied `probeFn`.
 */
type TestPeer = string;
const peerIdOf = (p: TestPeer) => p;

/**
 * Mirror of how `PeerborneDocument.load()` uses the orchestrator: probe
 * peers, then perform the full document-load against the narrowed cohort,
 * with the responder's served `tips` hash bound to the quorum's
 * `winningHashHex`. The harness below stands in for the snapshot/doc-load
 * loop so the binding check is exercised against the narrowed peer list
 * this orchestrator produces.
 *
 * Per-peer bind failures are NOT fatal: a peer whose served hash does not
 * match `winningHashHex` is recorded in `agreeingPeerBindFailures` and the
 * harness continues to the NEXT peer in the cohort. Only after EVERY peer
 * in the narrowed cohort has bind-failed (and at least one bind failure
 * was recorded) does the harness throw
 * `LoadQuorumFailedError(reason: 'bind-check-failed-all-agreeing-peers')`.
 * This mirrors the PR #284 r6 DoS fix in production `load()` -- a single
 * malicious peer in the agreeing cohort that votes for the majority hash
 * and then serves a mismatched full load can NOT unilaterally abort the
 * whole load.
 */
async function simulateFullLoad(opts: {
  narrowedPeers: TestPeer[];
  winningHashHex: string;
  serveFn: (peer: TestPeer) => Promise<string>; // returns served-tips hash hex; throw for transport failure
}): Promise<{
  loadedFromPeer: TestPeer | null;
  attempts: TestPeer[];
}> {
  const attempts: TestPeer[] = [];
  const agreeingPeerBindFailures = new Map<string, string>();
  for (const peer of opts.narrowedPeers) {
    attempts.push(peer);
    let servedHashHex: string;
    try {
      servedHashHex = await opts.serveFn(peer);
    } catch {
      // Transport/protocol failure: peer didn't even return a hash.
      // Production `load()` catches transport errors inside the loop and
      // continues to the next peer WITHOUT recording a bind failure.
      // See PR #284 r17 Copilot review for the mixed-cohort distinction.
      continue;
    }
    if (servedHashHex === opts.winningHashHex) {
      return { loadedFromPeer: peer, attempts };
    }
    // Bind check failed for THIS peer. Record it and continue to the
    // next peer in the agreeing cohort. Production `_sendLoadRequestAndSync`
    // throws an internal `_QuorumBindCheckFailedError` here and `load()`
    // catches it inside the loop; we collapse that into a "record + continue"
    // for the harness.
    agreeingPeerBindFailures.set(peer, servedHashHex);
  }
  // Loop exhausted. Failure-reason decision mirrors production
  // `PeerborneDocument.load()` post-r17:
  //
  //   - `bindFailures.size === cohortSize` -- EVERY peer bind-failed
  //     (coordinated Byzantine equivocation). Escalate with the
  //     dedicated reason.
  //   - `bindFailures.size > 0 && < cohortSize` -- MIXED failure (some
  //     bind-failed, others transport-failed). Surface as
  //     `agreeing-peers-unreachable` so callers don't wrongly treat a
  //     transient retrieval failure as coordinated Byzantine behaviour.
  //   - `bindFailures.size === 0` -- all transport-failed; same
  //     `agreeing-peers-unreachable` reason.
  if (opts.narrowedPeers.length === 0) {
    return { loadedFromPeer: null, attempts };
  }
  if (agreeingPeerBindFailures.size === opts.narrowedPeers.length) {
    throw new LoadQuorumFailedError({
      documentPath: '/test',
      reason: 'bind-check-failed-all-agreeing-peers',
      respondingCount: 0,
      requiredQ: 0,
      agreement: new Map([[opts.winningHashHex, 0]]),
      agreeingPeerBindFailures,
    });
  }
  throw new LoadQuorumFailedError({
    documentPath: '/test',
    reason: 'agreeing-peers-unreachable',
    respondingCount: 0,
    requiredQ: 0,
    agreement: new Map([[opts.winningHashHex, 0]]),
    agreeingPeerBindFailures,
  });
}

describe('runLoadQuorum: production orchestration coverage (PR #284 r4)', () => {
  // Typed `any` because Jest's generic `jest.fn()` typings are awkward to
  // satisfy alongside `mockImplementation((peer) => ...)`, and the call
  // sites explicitly annotate `peer: TestPeer` where it matters.
  let probeMock: any;

  beforeEach(() => {
    probeMock = jest.fn();
  });

  test('(a) 3 peers, all vote the same hash and serve a matching load => load succeeds', async () => {
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });

    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.winningHashHex).toBe(HASH_X_HEX);
    expect(result.narrowedPeers).toEqual(['p1', 'p2', 'p3']);
    expect(probeMock).toHaveBeenCalledTimes(3);

    // Drive the simulated full-load step: all agreeing peers serve a
    // matching hash, so the first attempt succeeds.
    const serveFn = jest.fn(async () => HASH_X_HEX);
    const loadOutcome = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    });
    expect(loadOutcome.loadedFromPeer).toBe('p1');
    expect(loadOutcome.attempts).toEqual(['p1']);
  });

  test('(b) 3 peers, 2 vote X / 1 votes Y => agreeing cohort narrowed; disagreeing peer never loaded from', async () => {
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockImplementation(async (peer: TestPeer) => {
      return peer === 'p3' ? HASH_Y : HASH_X;
    });

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });

    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.winningHashHex).toBe(HASH_X_HEX);
    // p3 (the dissenter) must not be in the narrowed cohort.
    expect(result.narrowedPeers).toEqual(['p1', 'p2']);
    expect(result.narrowedPeers).not.toContain('p3');

    // Drive the simulated load: only the narrowed cohort is asked, and the
    // load must never touch p3.
    const serveFn = jest.fn(async () => HASH_X_HEX);
    const loadOutcome = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    });
    expect(loadOutcome.attempts).not.toContain('p3');
    expect(loadOutcome.loadedFromPeer).toBe('p1');
  });

  test('(c) 3 peers all vote X but EVERY peer serves tips hashing to Y => LoadQuorumFailedError(bind-check-failed-all-agreeing-peers)', async () => {
    // The whole cohort is Byzantine on the load step: every agreeing peer
    // voted X in the probe round but serves Y on the full load. The
    // harness must exhaust the cohort BEFORE escalating, so the
    // serveFn is called for every peer and the final error carries the
    // dedicated `bind-check-failed-all-agreeing-peers` reason plus a
    // per-peer `agreeingPeerBindFailures` map. See PR #284 r6.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');

    const serveFn = jest.fn(async () => HASH_Y_HEX);
    const err = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe(
      'bind-check-failed-all-agreeing-peers',
    );
    // Every agreeing peer must have been tried before the escalation.
    expect(serveFn).toHaveBeenCalledTimes(3);
    // Per-peer record of what each Byzantine peer served instead.
    expect(
      (err as LoadQuorumFailedError).agreeingPeerBindFailures,
    ).toEqual(
      new Map([
        ['p1', HASH_Y_HEX],
        ['p2', HASH_Y_HEX],
        ['p3', HASH_Y_HEX],
      ]),
    );
  });

  test('(c2) DoS regression: ONE Byzantine agreeing peer cannot abort the whole load; honest peer is tried next', async () => {
    // Regression for the critical PR #284 r6 finding: previously, if the
    // first peer chosen for the full load was Byzantine on the load
    // step (voted hash X, served tips hashing to Y), the loader threw
    // `LoadQuorumFailedError` and aborted -- never trying the OTHER
    // honest agreeing peers who WOULD have served a matching response.
    // That was a DoS vector: a single malicious peer in the agreeing
    // cohort could unilaterally prevent any load. After the fix, the
    // loader records the bind failure against the offending peer and
    // falls through to the next peer in the cohort.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.narrowedPeers).toEqual(['p1', 'p2', 'p3']);

    // p1 is Byzantine on the load step: voted X, serves Y.
    // p2 is honest: voted X, serves X.
    // p3 should never be reached because p2 succeeds.
    const serveFn = jest.fn(async (peer: TestPeer) => {
      if (peer === 'p1') return HASH_Y_HEX;
      return HASH_X_HEX;
    });
    const loadOutcome = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    });
    // Load succeeded against p2 (the honest peer immediately after
    // the Byzantine p1) -- NOT thrown.
    expect(loadOutcome.loadedFromPeer).toBe('p2');
    // Both p1 (bind-failed) and p2 (success) were attempted in order.
    expect(loadOutcome.attempts).toEqual(['p1', 'p2']);
    // p3 must NOT have been touched -- the load short-circuits on
    // the first successful bind.
    expect(serveFn).toHaveBeenCalledWith('p1');
    expect(serveFn).toHaveBeenCalledWith('p2');
    expect(serveFn).not.toHaveBeenCalledWith('p3');
  });

  test('(c2-missing-tips) PR #284 r9 issue #1: responder omits `tips` on v3 quorum-enabled load => per-peer bind failure; loader tries next agreeing peer', async () => {
    // PR #284 r9 Copilot review (issue #1): the v3 load-response
    // contract requires `tips` to be present on every quorum-enabled
    // load response so the responder commits to an explicit frontier
    // attestation. A v3 responder that omits `tips` previously slipped
    // through the bind path (the `Array.isArray(message.tips)` defense-
    // in-depth branch simply skipped). Now the omission is treated as
    // a per-peer bind failure with the sentinel `'(missing tips)'` so
    // the loader retries the next agreeing peer (mirrors the PR #284
    // r6 DoS fix: one peer cannot unilaterally DoS the load).
    //
    // The simulated harness models the missing-tips case by having the
    // peer's `serveFn` return the `'(missing tips)'` sentinel (which
    // production `_sendLoadRequestAndSync` uses inside
    // `_QuorumBindCheckFailedError.advertisedHex` for the same path).
    // The sentinel is never byte-equal to the `winningHashHex`, so the
    // harness records the peer as bind-failed and continues.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.narrowedPeers).toEqual(['p1', 'p2', 'p3']);

    // p1 voted X but omits `tips` on the load response (v3 protocol
    // violation). p2 is honest: voted X, serves X with tips. p3 should
    // never be touched -- p2 succeeds.
    const MISSING_TIPS = '(missing tips)';
    const serveFn = jest.fn(async (peer: TestPeer) => {
      if (peer === 'p1') return MISSING_TIPS;
      return HASH_X_HEX;
    });
    const loadOutcome = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    });
    expect(loadOutcome.loadedFromPeer).toBe('p2');
    expect(loadOutcome.attempts).toEqual(['p1', 'p2']);
    expect(serveFn).toHaveBeenCalledWith('p1');
    expect(serveFn).toHaveBeenCalledWith('p2');
    expect(serveFn).not.toHaveBeenCalledWith('p3');
  });

  test('(c2-missing-tips-all) PR #284 r9 issue #1: ALL agreeing peers omit `tips` => LoadQuorumFailedError(bind-check-failed-all-agreeing-peers) with `(missing tips)` sentinel', async () => {
    // The whole cohort violates the v3 protocol contract by omitting
    // `tips` on every load response. Loader must exhaust the cohort,
    // escalate with the dedicated reason, and record the
    // `'(missing tips)'` sentinel per peer so operators can tell
    // missing-tips equivocation apart from served-vs-claimed mismatch.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');

    const MISSING_TIPS = '(missing tips)';
    const serveFn = jest.fn(async () => MISSING_TIPS);
    const err = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    const lqfe = err as LoadQuorumFailedError;
    expect(lqfe.reason).toBe('bind-check-failed-all-agreeing-peers');
    expect(serveFn).toHaveBeenCalledTimes(3);
    expect(lqfe.agreeingPeerBindFailures.get('p1')).toBe(MISSING_TIPS);
    expect(lqfe.agreeingPeerBindFailures.get('p2')).toBe(MISSING_TIPS);
    expect(lqfe.agreeingPeerBindFailures.get('p3')).toBe(MISSING_TIPS);
  });

  test('(c3) all agreeing peers Byzantine on load: error carries per-peer agreeingPeerBindFailures with what each served', async () => {
    // Complement of (c2): when EVERY agreeing peer equivocates between
    // probe and load, the loader must escalate -- with the new
    // `bind-check-failed-all-agreeing-peers` reason and a per-peer
    // record of what each Byzantine peer served instead, so callers
    // can tell "the whole cohort lied on the load step" apart from
    // "no peer responded at all".
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');

    // Each Byzantine peer can serve a DIFFERENT mismatched hash; the
    // per-peer record must preserve the distinction.
    const HASH_Z_HEX = 'cc'.repeat(32);
    const serveFn = jest.fn(async (peer: TestPeer) => {
      if (peer === 'p1') return HASH_Y_HEX;
      if (peer === 'p2') return HASH_Z_HEX;
      return HASH_Y_HEX; // p3 mirrors p1, exercising shared-hex case
    });
    const err = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    const lqfe = err as LoadQuorumFailedError;
    expect(lqfe.reason).toBe('bind-check-failed-all-agreeing-peers');
    // Per-peer record carries the specific hash each peer served.
    expect(lqfe.agreeingPeerBindFailures.get('p1')).toBe(HASH_Y_HEX);
    expect(lqfe.agreeingPeerBindFailures.get('p2')).toBe(HASH_Z_HEX);
    expect(lqfe.agreeingPeerBindFailures.get('p3')).toBe(HASH_Y_HEX);
    expect(lqfe.agreeingPeerBindFailures.size).toBe(3);
    // Error message mentions the cohort-wide failure and the count.
    expect(lqfe.message).toMatch(/bind-check|agreeing cohort|3 peer/);
  });

  test('(c4) multi-head honest responder: advertise=served frontier hash binds; loader accepts even when responder has un-served concurrent heads (PR #284 r8)', async () => {
    // Regression for the PR #284 r8 Copilot finding: previously, an
    // honest peer with multiple concurrent heads in `_currentFrontier()`
    // would advertise tipsHash({H1, H2, H3}) in the probe round but
    // only serve a tree rooted at H1 (the wire shape carries one tree).
    // The loader's structural derivation `computeServedFrontier` over
    // the served payload yielded {H1}, hashed differently from the
    // advertise, and rejected the honest peer.
    //
    // The fix advertises the SERVED frontier (the heads of the tree
    // this peer would actually ship), so probe and load round agree
    // for honest responders. This test models a 3-peer cohort where
    // all three peers have un-served concurrent heads but the same
    // served frontier {H1}: all three vote tipsHash({H1}), all three
    // serve a payload whose structural frontier is {H1}, and the bind
    // check accepts.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    // Every honest peer advertises tipsHash(servedFrontier). HASH_X
    // stands in for tipsHash({H1}) here -- the orchestrator is
    // hash-agnostic, so we just need the value to be the same across
    // all three peers (probe round) AND match what each peer serves
    // on the load round.
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });

    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.winningHashHex).toBe(HASH_X_HEX);
    expect(result.narrowedPeers).toEqual(['p1', 'p2', 'p3']);

    // Each peer's load response structurally hashes to HASH_X (the
    // served-frontier hash). Before the fix this would have been
    // tipsHash({served-only}) while the probe was tipsHash({served +
    // un-served}), so the bind check would have rejected. After the
    // fix both sides agree.
    const serveFn = jest.fn(async () => HASH_X_HEX);
    const loadOutcome = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    });
    expect(loadOutcome.loadedFromPeer).toBe('p1');
    // The first honest peer in the cohort serves a matching response;
    // no fallback to subsequent peers was needed.
    expect(loadOutcome.attempts).toEqual(['p1']);
  });

  test('(c5) Byzantine responder that lies about heads: advertises tipsHash(claimed-full-frontier) but serves a tree hashing to served-only => bind check rejects', async () => {
    // Complement to (c4): a peer that DIDN'T apply the PR #284 r8 fix
    // (or is actively malicious) would compute its advertise hash
    // over its full local DAG frontier {H1, H2, H3} but only ship H1's
    // tree. The probe-round hash is HASH_Y_HEX (the bigger set); the
    // load-round structural derivation is HASH_X_HEX (the served-only
    // frontier). If two such liars somehow agreed on the same lie and
    // narrowed the cohort, the loader's bind check still rejects --
    // the structural derivation does not match the agreed-upon
    // advertise. This is the safety guarantee independent of the
    // honest-peer fix.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    // All three peers lie consistently: probe advertises HASH_Y (full
    // local frontier), load serves a tree hashing to HASH_X (served
    // only). Quorum agrees on HASH_Y; bind rejects on every peer.
    probeMock.mockResolvedValue(HASH_Y);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.winningHashHex).toBe(HASH_Y_HEX);

    // The loader's structural derivation produces HASH_X for every
    // served payload (because the served tree only contains H1, and
    // computeServedFrontier yields {H1}). HASH_X != HASH_Y, so every
    // peer's bind check fails.
    const serveFn = jest.fn(async () => HASH_X_HEX);
    const err = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe(
      'bind-check-failed-all-agreeing-peers',
    );
    expect(serveFn).toHaveBeenCalledTimes(3);
  });

  test('(d) 3 peers, only 1 responds in time => LoadQuorumFailedError(insufficient-responses); no full-load attempted', async () => {
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockImplementation(async (peer: TestPeer) => {
      // p1 responds; p2 and p3 simulate timeouts (null = non-vote).
      return peer === 'p1' ? HASH_X : null;
    });

    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe(
      'insufficient-responses',
    );
    expect(probeMock).toHaveBeenCalledTimes(3);
  });

  test('(e) single-peer fallback: K=1 + allowSinglePeer + matching served tips => load succeeds', async () => {
    const peers: TestPeer[] = ['p1'];
    probeMock.mockResolvedValue(HASH_X);

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 1, allowSinglePeer: true },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.winningHashHex).toBe(HASH_X_HEX);
    expect(result.narrowedPeers).toEqual(['p1']);
    expect(probeMock).toHaveBeenCalledTimes(1);

    const serveFn = jest.fn(async () => HASH_X_HEX);
    const loadOutcome = await simulateFullLoad({
      narrowedPeers: result.narrowedPeers,
      winningHashHex: result.winningHashHex,
      serveFn,
    });
    expect(loadOutcome.loadedFromPeer).toBe('p1');
  });

  test('(e2) single-peer fallback: K=1 + allowSinglePeer + probe TIMEOUT => LoadQuorumFailedError', async () => {
    // Complement of (e): the single-peer pass-through is NOT a free pass.
    // If the one probed peer doesn't return a hash within the timeout, the
    // gate must still fail closed.
    const peers: TestPeer[] = ['p1'];
    probeMock.mockResolvedValue(null);

    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 1, allowSinglePeer: true },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe(
      'insufficient-responses',
    );
  });

  test('single-peer fallback DENIED when allowSinglePeer=false (default)', async () => {
    // The orchestrator must refuse to run quorum against a single peer
    // unless the caller opts in. This protects against silently degrading
    // BFT semantics in small/partitioned meshes.
    const peers: TestPeer[] = ['p1'];
    probeMock.mockResolvedValue(HASH_X);

    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 1, allowSinglePeer: false },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    // The probe must NOT have been issued -- we refuse before talking to
    // the lone peer.
    expect(probeMock).not.toHaveBeenCalled();
    // Surfaced `requiredQ` is the load-bearing policy threshold (2 -- the
    // smallest cohort that gives any Byzantine fault tolerance), NOT the
    // numeric `defaultQuorumQ(1) = 1` that would falsely suggest the
    // lone peer's vote was "almost enough". See PR #284 r25 Copilot
    // review.
    expect((err as LoadQuorumFailedError).requiredQ).toBe(2);
    expect((err as LoadQuorumFailedError).respondingCount).toBe(0);
  });

  test('quorum disabled: returns { skipped: true } so caller falls through to legacy load', async () => {
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);
    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: false },
    });
    expect(result).toEqual({ skipped: true });
    expect(probeMock).not.toHaveBeenCalled();
  });

  test('empty peer list: returns { skipped: true } so caller treats as new document', async () => {
    const peers: TestPeer[] = [];
    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3 },
    });
    expect(result).toEqual({ skipped: true });
    expect(probeMock).not.toHaveBeenCalled();
  });

  test('loadQuorumK = 0 throws LoadQuorumFailedError(invalid-config) even with peers connected', async () => {
    // Regression for PR #284 r5: a `loadQuorumK <= 0` previously
    // collapsed `effectiveK(...)` to 0, the orchestrator returned
    // `{ skipped: true }`, and `PeerborneDocument.open()` then treated
    // the load as "new document" and forked any existing copy held by
    // peers. The orchestrator must now refuse loud-and-early on
    // misconfigured K so the fork can never happen silently.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockResolvedValue(HASH_X);
    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 0 },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer; got 0/,
    );
    expect(probeMock).not.toHaveBeenCalled();
  });

  test('loadQuorumK = -1 throws LoadQuorumFailedError(invalid-config)', async () => {
    const peers: TestPeer[] = ['p1', 'p2'];
    probeMock.mockResolvedValue(HASH_X);
    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: -1 },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer; got -1/,
    );
  });

  test('loadQuorumK = 0 with no peers also throws (config error, not founder case)', async () => {
    // The "no peers + K=0" combination is NOT a legitimate founder case:
    // the founder case is "no peers + K=default", which falls through
    // `effectiveK -> 0` -> `{ skipped: true }`. K=0 is always a static
    // operator misconfiguration regardless of peer count, so the
    // orchestrator throws unconditionally rather than silently bypassing
    // the gate.
    const err = await runLoadQuorum({
      peers: [],
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 0 },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect(probeMock).not.toHaveBeenCalled();
  });

  describe('post-init mutation of K/Q is caught as invalid-config (PR #284 r10)', () => {
    // Regression for PR #284 r10 Copilot review issue #2: `runLoadQuorum`
    // previously only rejected `K <= 0`. If a caller's `config.loadQuorumK`
    // was valid at `initialize()` but later mutated to `NaN`/`Infinity`/`-1`
    // BEFORE `load()` ran, `effectiveK(NaN, peers)` returned 0 (per the r9
    // defensive guards), the K=0 branch returned `{ skipped: true }`, and
    // `load()` fell through to the legacy unbound load — but
    // `loadQuorumEnabled` was still `true`, so the operator's intent
    // (quorum-protected load) was silently violated. The defensive
    // re-validation at the top of `runLoadQuorum` now catches this as a
    // hard `invalid-config` error rather than a silent skip.
    //
    // The legitimate `{ skipped: true }` paths (`enabled: false`, zero
    // peers with a valid default K) are NOT config errors and must NOT
    // throw — those are covered by the existing "quorum disabled" and
    // "empty peer list" tests above, plus the explicit re-check below.

    test('K = NaN throws LoadQuorumFailedError(invalid-config) (was: silent skip => legacy unbound load)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: NaN },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      // The error message must show `NaN` (not the misleading `null`
      // produced by `JSON.stringify(NaN)`) — that's the PR #284 r10
      // issue #1 fix for `formatConfigValue`.
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumK must be a positive integer; got NaN/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('K = Infinity throws LoadQuorumFailedError(invalid-config) with operator-visible "Infinity"', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: Infinity },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumK must be a positive integer; got Infinity/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('K = -Infinity throws LoadQuorumFailedError(invalid-config)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: -Infinity },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumK must be a positive integer; got -Infinity/,
      );
    });

    test('K = 1.5 (fractional) throws LoadQuorumFailedError(invalid-config)', async () => {
      // Was a silent single-peer probe (`peers.slice(0, 1.5)` => 1 peer)
      // under the original bug; now refused loud-and-early.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 1.5 },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumK must be a positive integer; got 1\.5/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('Q = NaN throws LoadQuorumFailedError(invalid-config) (was: silent single-peer quorum pass)', async () => {
      // Symmetric case for Q. Without the validator, `effectiveQ(NaN, k)`
      // returned `defaultQuorumQ(k)` via the r9 fallback — so the gate
      // ran with a sensible Q but the operator's *intent* (their
      // explicitly-set Q) had been silently corrupted. Surface the
      // mutation as a hard error instead.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: NaN },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumQ must be a positive integer; got NaN/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('rethrown invalid-config carries the actual documentPath (NOT the validator placeholder)', async () => {
      // `validateLoadQuorumConfig` uses `'<config>'` because it has no
      // doc path at startup. The orchestrator must replace that with the
      // load-attempt's actual `documentPath` so operator logs identify
      // which document's load tripped the post-init mutation.
      const err = await runLoadQuorum({
        peers: ['p1', 'p2'] as TestPeer[],
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/docs/x',
        config: { enabled: true, k: NaN },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).documentPath).toBe('/docs/x');
      expect((err as LoadQuorumFailedError).message).toMatch(/\/docs\/x/);
      expect((err as LoadQuorumFailedError).message).not.toMatch(
        /<config>/,
      );
    });

    test('loadQuorumEnabled: false still returns { skipped: true } even with invalid K (early-exit precedes validation)', async () => {
      // When the operator has explicitly disabled the gate, validation of
      // K/Q is irrelevant — the values won't be consulted at all. The
      // `enabled` short-circuit precedes the validator so an
      // already-disabled gate doesn't suddenly start throwing on a
      // pre-existing bad K.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: false, k: NaN },
      });
      expect(result).toEqual({ skipped: true });
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('valid K with zero peers still returns { skipped: true } (NOT a config error)', async () => {
      // Zero peers with a valid K is the legitimate founder/partition
      // case: `effectiveK(3, 0) === 0` => `{ skipped: true }`. The
      // validator must NOT misfire here because the configured K is
      // perfectly valid; the absence of peers is a runtime fact, not a
      // config error.
      const result = await runLoadQuorum({
        peers: [] as TestPeer[],
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3 },
      });
      expect(result).toEqual({ skipped: true });
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('idempotent: post-init validation is a no-op for already-valid config (matches initialize-time pass)', async () => {
      // Defence-in-depth must not double-throw on the happy path. A
      // config that passed `Peerborne.initialize()`'s validator must
      // continue to pass `runLoadQuorum`'s identical check on every
      // load attempt.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });
      expect('ok' in result && result.ok).toBe(true);
      expect(probeMock).toHaveBeenCalledTimes(3);
    });

    // -----------------------------------------------------------------
    // loadQuorumTimeoutMs post-init mutation guard (PR #284 r15)
    // -----------------------------------------------------------------
    // `loadQuorumTimeoutMs` flows directly into `setTimeout(...)` inside
    // the probe race. A post-init mutation to `NaN`/`Infinity`/`0`/
    // negative would coerce the timer to immediate-fire / overflow,
    // every probe would resolve as a non-vote, and quorum would fail on
    // every load even with a fully healthy mesh — silently breaking the
    // gate without surfacing the root cause as a config error. The
    // orchestrator now re-validates `timeoutMs` alongside K/Q on every
    // call and throws `LoadQuorumFailedError(invalid-config)` so the
    // misconfiguration is loud at the load-attempt boundary.

    test('timeoutMs = NaN throws LoadQuorumFailedError(invalid-config) (was: setTimeout immediate-fire => every probe non-vote)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, timeoutMs: NaN },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumTimeoutMs must be a positive integer.*got NaN/,
      );
      expect((err as LoadQuorumFailedError).message).not.toMatch(/got null/);
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('timeoutMs = Infinity throws LoadQuorumFailedError(invalid-config)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, timeoutMs: Infinity },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumTimeoutMs must be a positive integer.*got Infinity/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('timeoutMs = 0 throws LoadQuorumFailedError(invalid-config) (would fire immediately)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, timeoutMs: 0 },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumTimeoutMs must be a positive integer.*got 0/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('timeoutMs = -1 throws LoadQuorumFailedError(invalid-config)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, timeoutMs: -1 },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumTimeoutMs must be a positive integer.*got -1/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('timeoutMs = 1.5 (fractional) throws LoadQuorumFailedError(invalid-config)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, timeoutMs: 1.5 },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
      expect((err as LoadQuorumFailedError).message).toMatch(
        /loadQuorumTimeoutMs must be a positive integer.*got 1\.5/,
      );
      expect(probeMock).not.toHaveBeenCalled();
    });

    test('timeoutMs = valid integer (5000 ms) passes through and probes run', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2, timeoutMs: 5000 },
      });
      expect('ok' in result && result.ok).toBe(true);
      expect(probeMock).toHaveBeenCalledTimes(3);
    });

    test('timeoutMs = undefined passes through (orchestrator default applies)', async () => {
      // `undefined` means the operator did not override; the orchestrator
      // doesn't use the value directly (the caller does) but the
      // defensive validator must NOT reject `undefined`.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2, timeoutMs: undefined },
      });
      expect('ok' in result && result.ok).toBe(true);
    });

    test('rethrown invalid-config (timeoutMs) carries the actual documentPath', async () => {
      const err = await runLoadQuorum({
        peers: ['p1', 'p2'] as TestPeer[],
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/docs/y',
        config: { enabled: true, k: 2, timeoutMs: NaN },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).documentPath).toBe('/docs/y');
      expect((err as LoadQuorumFailedError).message).toMatch(/\/docs\/y/);
      expect((err as LoadQuorumFailedError).message).not.toMatch(/<config>/);
    });
  });

  // ---------------------------------------------------------------------
  // single-peer warning text (PR #284 r15 Copilot review issue #2)
  // ---------------------------------------------------------------------
  // The legacy wording was "only one peer known", which is accurate when
  // the mesh truly has one peer but actively misleading when the operator
  // configured `loadQuorumK = 1` with more peers available — they would
  // see the warning and assume their mesh had collapsed even though it
  // hadn't. The rewritten message includes both the configured K and the
  // actual peer count so the cause is unambiguous in either case.

  describe('single-peer fallback warning text reflects both cause cases (PR #284 r15)', () => {
    let warnSpy: ReturnType<typeof jest.spyOn>;
    beforeEach(() => {
      warnSpy = jest
        .spyOn(console, 'warn')
        .mockImplementation((() => {}) as never);
    });
    afterEach(() => {
      // Restore so the next test (which re-spies) starts from a clean
      // call history. Without this, `jest.spyOn` returns the SAME spy
      // and `mock.calls[0]` leaks from earlier tests in this describe.
      warnSpy.mockRestore();
    });

    test('case 1: peer scarcity (1 peer in mesh) — message mentions "1 peer known"', async () => {
      const peers: TestPeer[] = ['only-peer'];
      probeMock.mockResolvedValue(HASH_X);
      await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/scarcity',
        config: { enabled: true, k: 1, allowSinglePeer: true },
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      const msg = warnSpy.mock.calls[0][0] as string;
      expect(msg).toMatch(/only one peer will be probed/);
      expect(msg).toMatch(/loadQuorumK=1/);
      expect(msg).toMatch(/1 peer known/);
      expect(msg).toMatch(/loadQuorumAllowSinglePeer=true/);
      expect(msg).toMatch(/Configure additional peers/);
    });

    test('case 2: configured K=1 with multiple peers known — message mentions actual peer count', async () => {
      // The exact bug: 2 peers are in the mesh, but the operator pinned
      // `loadQuorumK = 1` so only one is probed. The previous wording
      // "only one peer known" was a lie — more peers ARE known. The new
      // wording reflects that the cause is the configured K.
      const peers: TestPeer[] = ['p1', 'p2'];
      probeMock.mockResolvedValue(HASH_X);
      await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/configured-k',
        config: { enabled: true, k: 1, allowSinglePeer: true },
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      const msg = warnSpy.mock.calls[0][0] as string;
      expect(msg).toMatch(/only one peer will be probed/);
      expect(msg).toMatch(/loadQuorumK=1/);
      // The actual peer count must be reflected — NOT a misleading "1".
      expect(msg).toMatch(/2 peers known/);
      // Operator guidance should point at the actual remediation
      // (raising K), not at "configure more peers" which is irrelevant.
      expect(msg).toMatch(/Increase loadQuorumK/);
      expect(msg).not.toMatch(/Configure additional peers/);
      // Sanity: must NOT use the misleading legacy "only one peer known"
      // phrasing, which was accurate only for case 1.
      expect(msg).not.toMatch(/only one peer known/);
    });

    test('case 2 (larger): K=1 with 5 peers known — message reports 5', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3', 'p4', 'p5'];
      probeMock.mockResolvedValue(HASH_X);
      await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/big-mesh-k1',
        config: { enabled: true, k: 1, allowSinglePeer: true },
      });
      const msg = warnSpy.mock.calls[0][0] as string;
      expect(msg).toMatch(/5 peers known/);
      expect(msg).toMatch(/Increase loadQuorumK/);
    });

    test('warning includes the documentPath prefix for operator log triage', async () => {
      const peers: TestPeer[] = ['p1'];
      probeMock.mockResolvedValue(HASH_X);
      await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/docs/my-doc',
        config: { enabled: true, k: 1, allowSinglePeer: true },
      });
      const msg = warnSpy.mock.calls[0][0] as string;
      expect(msg).toMatch(/\[\/docs\/my-doc\]/);
    });
  });

  test('multi-peer probe that REJECTS is recorded as a non-vote; other peers still tally', async () => {
    // Contract regression for PR #284 r5: a `probeFn` that throws/rejects
    // must NOT escape the orchestrator. Without the per-probe catch the
    // whole `Promise.all` would reject and bubble past the
    // `LoadQuorumFailedError` API contract `load()` callers are written
    // against. With the catch, the rejected peer is counted as a
    // non-vote and the remaining honest peers can still form quorum.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockImplementation(async (peer: TestPeer) => {
      if (peer === 'p3') throw new Error('synthetic probe failure');
      return HASH_X;
    });
    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.narrowedPeers).toEqual(['p1', 'p2']);
    expect(result.narrowedPeers).not.toContain('p3');
    expect(result.winningHashHex).toBe(HASH_X_HEX);
    // Sanity: probe still called for ALL peers, including the rejecter.
    expect(probeMock).toHaveBeenCalledTimes(3);
  });

  test('multi-peer with ALL probeFns rejecting => LoadQuorumFailedError(insufficient-responses), no raw probe error escapes', async () => {
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockImplementation(async () => {
      throw new Error('synthetic probe failure');
    });
    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe(
      'insufficient-responses',
    );
    // The synthetic probe error MUST NOT escape — only the structured
    // LoadQuorumFailedError surfaces.
    expect((err as Error).message).not.toMatch(/synthetic probe failure/);
  });

  test('single-peer fallback with rejected probeFn => LoadQuorumFailedError(insufficient-responses), not the raw probe error', async () => {
    // Single-peer pass-through must also contain probe errors. The
    // single-peer code path was a separate `await probeFn(...)` (not
    // inside the multi-peer `Promise.all`) — a regression risk if only
    // one of the two paths was fixed.
    const peers: TestPeer[] = ['p1'];
    probeMock.mockImplementation(async () => {
      throw new Error('synthetic single-peer probe failure');
    });
    const err = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 1, allowSinglePeer: true },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe(
      'insufficient-responses',
    );
    expect((err as Error).message).not.toMatch(
      /synthetic single-peer probe failure/,
    );
  });

  test('size-cap-triggered non-vote does NOT poison quorum when honest majority still responds', async () => {
    // Regression for the DoS hardening fix from PR #284 r4: an
    // oversized tip-advertise response is surfaced as `null` (non-vote)
    // by `_probeTipAdvertise`'s outer catch. Verify that a single peer
    // hitting the size cap does not flip the quorum into a Byzantine
    // verdict -- the remaining honest peers must still be able to form
    // a Q-of-K majority.
    const peers: TestPeer[] = ['p1', 'p2', 'p3'];
    probeMock.mockImplementation(async (peer: TestPeer) => {
      // p3 simulates the size-cap RangeError surface (null = non-vote);
      // p1 and p2 vote X honestly.
      return peer === 'p3' ? null : HASH_X;
    });

    const result = await runLoadQuorum({
      peers,
      peerIdOf,
      probeFn: probeMock,
      documentPath: '/test',
      config: { enabled: true, k: 3, q: 2 },
    });
    expect('ok' in result && result.ok).toBe(true);
    if (!('ok' in result)) throw new Error('expected ok=true');
    expect(result.narrowedPeers).toEqual(['p1', 'p2']);
    expect(result.winningHashHex).toBe(HASH_X_HEX);
  });

  describe('legacy load loop preserves un-deduped peer list (PR #284 r7)', () => {
    // Regression for PR #284 r7 Copilot review: the load loop previously
    // deduped peers by peer id UNCONDITIONALLY -- before the quorum probe,
    // affecting BOTH the quorum probe AND the legacy single-peer load
    // loop. When `loadQuorumEnabled: false`, the legacy loop should keep
    // multiple multiaddrs for the same peer id (e.g. direct connection +
    // relay-circuit fallback) so the second can be tried if the first
    // fails. The fix uses `quorumPeers = dedupePeersByPeerId(orderedPeers)`
    // for the probe only; `orderedPeers` (un-deduped) is preserved for
    // the legacy loop.
    //
    // The control-flow snippet under test mirrors the relevant slice of
    // `PeerborneDocument.load()`: build `quorumPeers` for the probe,
    // keep `orderedPeers` for the loop. The tests here do NOT use real
    // multiaddrs -- they use `{ id, addr }` test doubles where `id` is
    // the peer id and `addr` is a per-connection sentinel. The
    // `peerIdOf` extractor returns `id` so dedup collapses entries
    // sharing the same `id` but different `addr`.

    interface MultiAddrPeer {
      id: string;
      addr: string;
    }
    const idOf = (p: MultiAddrPeer) => p.id;

    function simulateLegacyLoop(opts: {
      orderedPeers: MultiAddrPeer[];
      // Per-connection result. Returns `true` if the load succeeded for
      // this connection, `false` to fall through to the next one.
      loadFn: (peer: MultiAddrPeer) => Promise<boolean>;
    }): Promise<{
      attempts: MultiAddrPeer[];
      loadedFromAddr: string | null;
    }> {
      const attempts: MultiAddrPeer[] = [];
      return (async () => {
        for (const peer of opts.orderedPeers) {
          attempts.push(peer);
          const ok = await opts.loadFn(peer);
          if (ok) return { attempts, loadedFromAddr: peer.addr };
        }
        return { attempts, loadedFromAddr: null };
      })();
    }

    test('quorum disabled: legacy loop iterates ALL multiaddrs for the same peer id', async () => {
      // Two connections to the same peer id "alice": a direct dial that
      // fails, and a relay-circuit fallback that succeeds. The legacy
      // loop must try BOTH (the fallback is the whole point of having
      // multiple connections). Under the bug, dedup collapses the two
      // entries to one and the loader gives up after the direct dial
      // fails.
      const orderedPeers: MultiAddrPeer[] = [
        { id: 'alice', addr: '/direct/alice' },
        { id: 'alice', addr: '/p2p-circuit/alice' },
      ];

      // Dedup is for the QUORUM probe only; the legacy loop keeps
      // `orderedPeers` un-deduped (this mirrors the production code in
      // `PeerborneDocument.load()` after the PR #284 r7 fix).
      const quorumPeers = dedupePeersByPeerId(orderedPeers, idOf);
      expect(quorumPeers).toEqual([
        { id: 'alice', addr: '/direct/alice' },
      ]);

      // Quorum disabled => legacy loop walks `orderedPeers` (un-deduped).
      const loadFn = jest.fn(async (peer: MultiAddrPeer) => {
        // Direct fails; circuit succeeds.
        return peer.addr === '/p2p-circuit/alice';
      });
      const outcome = await simulateLegacyLoop({
        orderedPeers,
        loadFn,
      });
      expect(outcome.attempts).toEqual([
        { id: 'alice', addr: '/direct/alice' },
        { id: 'alice', addr: '/p2p-circuit/alice' },
      ]);
      expect(outcome.loadedFromAddr).toBe('/p2p-circuit/alice');
      // Both connections were tried.
      expect(loadFn).toHaveBeenCalledTimes(2);
    });

    test('quorum disabled: prior buggy behaviour (loop over deduped list) would have stopped after the failed direct dial', async () => {
      // Documenting the regression we are guarding against: under the
      // pre-fix code, the loop iterated `dedupePeersByPeerId(orderedPeers)`,
      // i.e. only ONE entry per peer id. The fallback connection was
      // never tried.
      const orderedPeers: MultiAddrPeer[] = [
        { id: 'alice', addr: '/direct/alice' },
        { id: 'alice', addr: '/p2p-circuit/alice' },
      ];
      const dedupedAsBug = dedupePeersByPeerId(orderedPeers, idOf);
      const loadFn = jest.fn(async (peer: MultiAddrPeer) => {
        return peer.addr === '/p2p-circuit/alice';
      });
      const outcome = await simulateLegacyLoop({
        orderedPeers: dedupedAsBug,
        loadFn,
      });
      // Bug behaviour: only the direct dial is attempted, so the load
      // fails even though a valid fallback existed.
      expect(outcome.attempts).toEqual([
        { id: 'alice', addr: '/direct/alice' },
      ]);
      expect(outcome.loadedFromAddr).toBeNull();
      expect(loadFn).toHaveBeenCalledTimes(1);
    });

    test('quorum disabled: distinct peer ids are unaffected', async () => {
      // Sanity check: dedup-by-peer-id is a no-op when each peer id
      // appears once. The fix doesn't regress this path.
      const orderedPeers: MultiAddrPeer[] = [
        { id: 'alice', addr: '/direct/alice' },
        { id: 'bob', addr: '/direct/bob' },
      ];
      const quorumPeers = dedupePeersByPeerId(orderedPeers, idOf);
      expect(quorumPeers).toEqual(orderedPeers);
      const loadFn = jest.fn(async (peer: MultiAddrPeer) => peer.id === 'alice');
      const outcome = await simulateLegacyLoop({ orderedPeers, loadFn });
      expect(outcome.loadedFromAddr).toBe('/direct/alice');
      expect(loadFn).toHaveBeenCalledTimes(1);
    });

    test('quorum enabled: probe-only dedup still applies (single vote per peer id)', async () => {
      // Complementary case: when quorum IS enabled, the probe round uses
      // the deduped list so a peer with two connections can't cast two
      // votes. The narrowed cohort returned by `runLoadQuorum` is a
      // filter of the deduped list, so the subsequent load loop only
      // sees one connection per peer id in the narrowed cohort. This is
      // the intended behaviour for the quorum path.
      const orderedPeers: MultiAddrPeer[] = [
        { id: 'alice', addr: '/direct/alice' },
        { id: 'alice', addr: '/p2p-circuit/alice' },
        { id: 'bob', addr: '/direct/bob' },
        { id: 'carol', addr: '/direct/carol' },
      ];
      const quorumPeers = dedupePeersByPeerId(orderedPeers, idOf);
      expect(quorumPeers.map(idOf)).toEqual(['alice', 'bob', 'carol']);

      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers: quorumPeers,
        peerIdOf: idOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });
      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');
      // Each peer voted exactly once -- alice's duplicate connection did
      // not give her a second vote.
      expect(probeMock).toHaveBeenCalledTimes(3);
      // The narrowed cohort carries one entry per peer id, mirroring the
      // probe input.
      expect(result.narrowedPeers.map(idOf)).toEqual([
        'alice',
        'bob',
        'carol',
      ]);
    });
  });

  describe('default Q is derived from EFFECTIVE K, not configured K (PR #284 r7)', () => {
    // Regression for PR #284 r7 Copilot review: previously `defaultQuorumQ`
    // was passed the CONFIGURED K, so a configured K=7 against a peer list
    // of size 3 required `effectiveQ(defaultQuorumQ(7), effectiveK(7, 3))`
    // = `effectiveQ(4, 3)` = 3 -- i.e. ALL 3 reachable peers had to agree,
    // losing the one-fault tolerance the formula targets. The fix passes
    // the effective K to `defaultQuorumQ`, so the default Q tracks the
    // actual quorum size in use.
    //
    // To prove the default-Q derivation: arrange a setup where exactly
    // `defaultQuorumQ(effective K)` peers vote the same hash and the rest
    // do not respond. Under the fix, the agreeing minority crosses the
    // (lower) threshold and quorum passes. Under the bug, the threshold is
    // higher and quorum fails. The tests below use `q: undefined` so the
    // default kicks in.
    test('configured K=7 but only 3 peers: effective K=3, default Q=2 (was 4 with bug)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockImplementation(async (peer: TestPeer) => {
        // p1 + p2 vote X (2 votes = strict-majority for K=3); p3 times out.
        // Under the BUG, defaultQuorumQ(7) = 4 > 3 votes available => quorum
        // could never pass. Under the FIX, defaultQuorumQ(3) = 2 votes
        // required => quorum passes.
        return peer === 'p3' ? null : HASH_X;
      });

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 7 /* q: undefined => derive from effective K */ },
      });
      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');
      expect(result.winningHashHex).toBe(HASH_X_HEX);
      expect(result.narrowedPeers).toEqual(['p1', 'p2']);
    });

    test('configured K=3 with 3 peers: default Q=2 (unchanged from previous behaviour)', async () => {
      // Sanity: the canonical configured-K matches-effective-K case still
      // resolves to defaultQuorumQ(3) = 2. The bug only fired when
      // configured K > peers.length.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockImplementation(async (peer: TestPeer) => {
        return peer === 'p3' ? null : HASH_X;
      });

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3 },
      });
      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');
      expect(result.narrowedPeers).toEqual(['p1', 'p2']);
    });

    test('configured K=5 with 5 peers: default Q=3 (unchanged)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3', 'p4', 'p5'];
      probeMock.mockImplementation(async (peer: TestPeer) => {
        // 3 vote X (strict majority of 5), 2 time out.
        return peer === 'p4' || peer === 'p5' ? null : HASH_X;
      });

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 5 },
      });
      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');
      expect(result.narrowedPeers).toEqual(['p1', 'p2', 'p3']);
    });

    test('configured K=7 with 7 peers: default Q=4 (unchanged)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7'];
      probeMock.mockImplementation(async (peer: TestPeer) => {
        // 4 vote X (strict majority of 7), 3 time out.
        return ['p5', 'p6', 'p7'].includes(peer) ? null : HASH_X;
      });

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 7 },
      });
      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');
      expect(result.narrowedPeers).toEqual(['p1', 'p2', 'p3', 'p4']);
    });

    test('explicit Q is honoured (??-fallback no-op): configured K=7, 3 peers, explicit Q=3 still requires all 3', async () => {
      // When the operator explicitly sets `loadQuorumQ`, the `??` fallback
      // does not fire and the explicit value flows through `effectiveQ`'s
      // `[1, k]` clamp. Verify the fix did not accidentally clamp the
      // explicit value too aggressively. With explicit Q=3 and effective
      // K=3, all 3 peers must agree.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockImplementation(async (peer: TestPeer) => {
        return peer === 'p3' ? null : HASH_X;
      });

      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 7, q: 3 },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      // 2 votes available but 3 required => insufficient-responses.
      expect((err as LoadQuorumFailedError).reason).toBe(
        'insufficient-responses',
      );
    });
  });

  // PR #284 r17: when the agreeing cohort partly bind-fails and partly
  // transport-fails, the loader must NOT use the
  // `bind-check-failed-all-agreeing-peers` reason -- that reason's public
  // docs explicitly say EVERY peer in the cohort equivocated, and using
  // it for mixed failure modes can make callers wrongly conclude
  // coordinated Byzantine behaviour when the underlying cause was a
  // mixture of one bad actor + transient network errors. Mixed failures
  // surface as `agreeing-peers-unreachable` (still threading the per-peer
  // bind-failure map through for diagnostics).
  describe("mixed bind/transport failure cohort uses 'agreeing-peers-unreachable' (PR #284 r17)", () => {
    test("(c-mixed-1) 1 bind-failure + 2 transport-failures => 'agreeing-peers-unreachable'", async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });
      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');

      // p1 bind-fails (serves Y), p2/p3 transport-fail (throw).
      const serveFn = jest.fn(async (peer: TestPeer) => {
        if (peer === 'p1') return HASH_Y_HEX;
        throw new Error('transport error');
      });
      const err = await simulateFullLoad({
        narrowedPeers: result.narrowedPeers,
        winningHashHex: result.winningHashHex,
        serveFn,
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      // CRITICAL: mixed cohort failures must NOT use the
      // bind-check-failed-all-agreeing-peers reason.
      expect((err as LoadQuorumFailedError).reason).toBe(
        'agreeing-peers-unreachable',
      );
      // Per-peer bind-failure map still surfaces for operator diagnostics.
      expect(
        (err as LoadQuorumFailedError).agreeingPeerBindFailures,
      ).toEqual(new Map([['p1', HASH_Y_HEX]]));
    });

    test("(c-mixed-2) 2 bind-failures + 1 transport-failure => 'agreeing-peers-unreachable'", async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });
      if (!('ok' in result)) throw new Error('expected ok=true');

      // p1, p2 bind-fail; p3 transport-fails. Still mixed; reason stays
      // `agreeing-peers-unreachable` (the bind-failure count < cohort size).
      const serveFn = jest.fn(async (peer: TestPeer) => {
        if (peer === 'p3') throw new Error('transport error');
        return HASH_Y_HEX;
      });
      const err = await simulateFullLoad({
        narrowedPeers: result.narrowedPeers,
        winningHashHex: result.winningHashHex,
        serveFn,
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe(
        'agreeing-peers-unreachable',
      );
      expect(
        (err as LoadQuorumFailedError).agreeingPeerBindFailures.size,
      ).toBe(2);
    });

    test("(c-mixed-3) only when EVERY peer bind-fails does the dedicated reason fire", async () => {
      // Sanity check: the dedicated reason is still reachable when the
      // cohort is fully bind-failed. Regression guard so the fix for the
      // mixed-cohort issue doesn't accidentally suppress the coordinated-
      // Byzantine reason.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });
      if (!('ok' in result)) throw new Error('expected ok=true');

      const serveFn = jest.fn(async () => HASH_Y_HEX);
      const err = await simulateFullLoad({
        narrowedPeers: result.narrowedPeers,
        winningHashHex: result.winningHashHex,
        serveFn,
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe(
        'bind-check-failed-all-agreeing-peers',
      );
    });
  });

  // PR #284 r16: `'unknown-doc'` probe results let the orchestrator
  // detect the new-doc-creation case in an existing swarm. A Q-of-K
  // majority of disclaims surfaces `{ newDoc: true }`; the loader uses
  // this to return `false` so a fresh `open()` can create the document.
  describe("'unknown-doc' new-document-creation path (PR #284 r16)", () => {
    test("3 peers all probe 'unknown-doc' => orchestrator returns { newDoc: true }", async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue('unknown-doc');

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });

      expect('newDoc' in result && result.newDoc).toBe(true);
      // Should NOT surface as ok=true with narrowedPeers (that would
      // drag the loader into a full-load round-trip).
      expect('ok' in result).toBe(false);
      expect('skipped' in result).toBe(false);
      expect(probeMock).toHaveBeenCalledTimes(3);
    });

    test("majority 'unknown-doc' (2 of 3) with 1 tip-hash dissenter => no-majority (tip-hash priority, PR #284 r19)", async () => {
      // r19 Copilot review: tip-hash votes take PRIORITY over
      // unknown-doc disclaims because the probe samples the WHOLE libp2p
      // mesh (`getConnections()`), not only peers that hold this
      // document. Two unrelated peers in the mesh legitimately
      // returning 'unknown-doc' must NOT outvote the one peer that
      // actually has the document and force a fork via new-doc
      // creation. With Q=2 here, the lone HASH_X vote does not meet
      // quorum on its own, so the orchestrator throws no-majority
      // rather than surfacing { newDoc: true }.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockImplementation(async (peer: TestPeer) =>
        peer === 'p3' ? HASH_X : 'unknown-doc',
      );

      const err = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      }).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('no-majority');
    });

    test("single lying 'unknown-doc' in a 3-peer mesh whose other peers have the doc CANNOT force new-doc creation", async () => {
      // Defense: a single Byzantine peer claiming 'unknown-doc' while
      // the others honestly serve HASH_X must lose the tally and let
      // the loader proceed with the normal tip-hash quorum.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockImplementation(async (peer: TestPeer) =>
        peer === 'p3' ? 'unknown-doc' : HASH_X,
      );

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });

      expect('ok' in result && result.ok).toBe(true);
      if (!('ok' in result)) throw new Error('expected ok=true');
      expect(result.winningHashHex).toBe(HASH_X_HEX);
      expect(result.narrowedPeers).toEqual(['p1', 'p2']);
    });

    test("single-peer fallback (k=1, allowSinglePeer=true) with 'unknown-doc' returns { newDoc: true }", async () => {
      // Symmetric with the K-of-Q new-doc path: a single probed peer
      // that disclaims the document still surfaces as new-doc.
      const peers: TestPeer[] = ['p1'];
      probeMock.mockResolvedValue('unknown-doc');

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 1, q: 1, allowSinglePeer: true },
      });

      expect('newDoc' in result && result.newDoc).toBe(true);
      expect(probeMock).toHaveBeenCalledTimes(1);
    });

    test("'unknown-doc' votes alongside null non-votes still reach Q and surface { newDoc: true }", async () => {
      // 2 disclaims + 1 timeout: disclaims meet Q=2 even with one
      // non-vote. Mirrors the tip-hash 2-of-3-with-timeout path.
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockImplementation(async (peer: TestPeer) =>
        peer === 'p3' ? null : 'unknown-doc',
      );

      const result = await runLoadQuorum({
        peers,
        peerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      });

      expect('newDoc' in result && result.newDoc).toBe(true);
    });
  });

  describe('quorum agreement maps to zero peers => fail closed (PR #284 r12)', () => {
    // If `peerIdOf` returns a stable id for the probe round but the post-
    // probe narrowing step somehow loses every agreeing peer (e.g. a bug
    // in `peerIdOf` produces a different id on the second call, or the
    // agreement map references peer ids that are not in the peer list),
    // the orchestrator must FAIL CLOSED rather than silently fall back to
    // probing every original peer -- including the ones that voted for
    // the LOSING hash. The previous behaviour widened trust scope to
    // escape this edge case, defeating the very narrowing the gate
    // exists to enforce. The fix raises a structured
    // `LoadQuorumFailedError(no-majority)` so the caller sees the same
    // contract as any other quorum failure.

    test('unstable peerIdOf that maps probe-round ids to non-existent post-narrowing ids => LoadQuorumFailedError(no-majority)', async () => {
      const peers: TestPeer[] = ['p1', 'p2', 'p3'];
      probeMock.mockResolvedValue(HASH_X);
      // Probe round sees ids `p1/p2/p3`; narrowing round sees totally
      // different ids (`probed-p1`, etc.) so `agreeingSet.has(...)` is
      // never true on any peer. This is the "should-be-impossible-but-
      // happened" branch the fail-closed guard exists for.
      let callCount = 0;
      const unstablePeerIdOf = (p: TestPeer): string => {
        callCount++;
        return callCount <= peers.length ? p : `probed-${p}`;
      };

      const err = await runLoadQuorum({
        peers,
        peerIdOf: unstablePeerIdOf,
        probeFn: probeMock,
        documentPath: '/test',
        config: { enabled: true, k: 3, q: 2 },
      }).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(LoadQuorumFailedError);
      expect((err as LoadQuorumFailedError).reason).toBe('no-majority');
      // Agreement map carries the winning hex + the count of agreeing
      // peers so observability is preserved across the fail-closed path.
      const agreement = (err as LoadQuorumFailedError).agreement;
      expect(agreement.size).toBe(1);
      const [[hex, count]] = [...agreement.entries()];
      expect(hex).toBe(HASH_X_HEX);
      expect(count).toBe(3);
    });
  });
});
