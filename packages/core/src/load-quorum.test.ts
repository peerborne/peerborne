import { describe, expect, test } from '@jest/globals';
import {
  constantTimeHexEquals,
  decideLoadQuorum,
  dedupePeersByPeerId,
  defaultQuorumQ,
  effectiveK,
  effectiveQ,
  formatConfigValue,
  LOAD_QUORUM_TIMEOUT_MS_MAX,
  LoadQuorumFailedError,
  validateLoadQuorumConfig,
} from './load-quorum.js';

function bytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hex must be even-length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const HASH_A = bytes('aa'.repeat(32));
const HASH_B = bytes('bb'.repeat(32));
const HASH_C = bytes('cc'.repeat(32));

describe('decideLoadQuorum (initial-load quorum gate, #189 §5.4.2)', () => {
  test('3-of-3 agreement passes quorum (Q=2)', () => {
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: HASH_A },
        { peerId: 'p2', hash: HASH_A },
        { peerId: 'p3', hash: HASH_A },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.respondingCount).toBe(3);
      expect(decision.agreeingPeerIds).toEqual(['p1', 'p2', 'p3']);
    }
  });

  test('2-of-3 agreement still meets Q=2', () => {
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: HASH_A },
        { peerId: 'p2', hash: HASH_A },
        { peerId: 'p3', hash: HASH_B },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.agreeingPeerIds).toEqual(['p1', 'p2']);
    }
  });

  test('3-way disagreement fails quorum (no-majority)', () => {
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: HASH_A },
        { peerId: 'p2', hash: HASH_B },
        { peerId: 'p3', hash: HASH_C },
      ],
      2,
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe('no-majority');
      expect(decision.respondingCount).toBe(3);
      expect(decision.agreement.size).toBe(3);
    }
  });

  test('timeouts (null hashes) are not counted as disagreement', () => {
    // Two real votes for HASH_A, one timeout. With Q=2 this should pass:
    // the timeout is a non-vote, not a disagreement.
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: HASH_A },
        { peerId: 'p2', hash: HASH_A },
        { peerId: 'p3', hash: null },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.respondingCount).toBe(2);
      expect(decision.agreeingPeerIds).toEqual(['p1', 'p2']);
    }
  });

  test('all timeouts fails with insufficient-responses', () => {
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: null },
        { peerId: 'p2', hash: null },
        { peerId: 'p3', hash: null },
      ],
      2,
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe('insufficient-responses');
      expect(decision.respondingCount).toBe(0);
    }
  });

  test('empty advertisement list fails with no-peers-queried', () => {
    const decision = decideLoadQuorum([], 2);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe('no-peers-queried');
    }
  });

  // PR #284 r12 CodeRabbit review: `decideLoadQuorum` is exported, so a
  // direct caller (or future refactor that bypasses `runLoadQuorum`)
  // passing `q <= 0` or a non-integer would silently disable the quorum
  // gate -- the largest-bucket size is always `>= 0 >= q` and a single
  // peer's vote would pass. Throw on programming errors so the failure
  // is loud at the first call site rather than relying on the docstring
  // precondition.
  test('non-positive q is a programming error and throws', () => {
    expect(() =>
      decideLoadQuorum([{ peerId: 'p1', hash: HASH_A }], 0),
    ).toThrow(/q must be a positive integer.*got 0/);
    expect(() =>
      decideLoadQuorum([{ peerId: 'p1', hash: HASH_A }], -1),
    ).toThrow(/q must be a positive integer.*got -1/);
  });

  test('non-integer q is a programming error and throws', () => {
    expect(() =>
      decideLoadQuorum([{ peerId: 'p1', hash: HASH_A }], 1.5),
    ).toThrow(/q must be a positive integer.*got 1\.5/);
    expect(() =>
      decideLoadQuorum([{ peerId: 'p1', hash: HASH_A }], Number.NaN),
    ).toThrow(/q must be a positive integer.*got NaN/);
    expect(() =>
      decideLoadQuorum(
        [{ peerId: 'p1', hash: HASH_A }],
        Number.POSITIVE_INFINITY,
      ),
    ).toThrow(/q must be a positive integer.*got Infinity/);
  });

  test('single peer with Q=1 (allowSinglePeer path) passes', () => {
    const decision = decideLoadQuorum(
      [{ peerId: 'p1', hash: HASH_A }],
      1,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.agreeingPeerIds).toEqual(['p1']);
    }
  });

  test('single peer with Q=2 (allowSinglePeer false) fails', () => {
    const decision = decideLoadQuorum(
      [{ peerId: 'p1', hash: HASH_A }],
      2,
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe('insufficient-responses');
    }
  });

  test('two byte-identical hashes from different instances collide on the same bucket', () => {
    // Reference inequality, value equality.
    const a1 = bytes('11'.repeat(32));
    const a2 = bytes('11'.repeat(32));
    expect(a1).not.toBe(a2);
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: a1 },
        { peerId: 'p2', hash: a2 },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
  });

  // PR #284 r16: `'unknown-doc'` is a first-class vote alongside tip-hash
  // values. A Q-of-K majority of disclaims surfaces a `kind: 'new-doc'`
  // outcome that the orchestrator translates into `{ newDoc: true }` and
  // the loader translates into a `false` return so a fresh `open()` can
  // create the document on top of an existing swarm. A single lying
  // disclaim cannot force this branch if the other peers actually have
  // the document (their tip-hash bucket wins the tally).
  test("'unknown-doc' majority returns kind='new-doc' with disclaim peers in agreeing cohort", () => {
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: 'unknown-doc' },
        { peerId: 'p2', hash: 'unknown-doc' },
        { peerId: 'p3', hash: 'unknown-doc' },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.kind).toBe('new-doc');
      expect(decision.respondingCount).toBe(3);
      expect(decision.agreeingPeerIds).toEqual(['p1', 'p2', 'p3']);
      // The reserved tally key is non-hex so it cannot collide with a
      // real `tipsHashToHex` output (64-char lowercase hex).
      expect(decision.winningHashHex).toBe('unknown-doc');
    }
  });

  test("majority 'unknown-doc' vs minority tip-hash: tip-hash takes PRIORITY (PR #284 r19)", () => {
    // 2 disclaims, 1 peer reports HASH_A. The probe samples from the
    // WHOLE libp2p mesh, not just peers that hold this document, so
    // peers without the doc (legitimately returning unknown-doc) must
    // NOT outvote the one peer that has it. Otherwise two unrelated
    // peers in the mesh could fork an existing document into a new-doc
    // creation -- silently splitting the swarm.
    //
    // New precedence rule: ANY tip-hash vote suppresses the unknown-doc
    // bucket. With Q=2 here, the lone HASH_A vote does not meet Q on
    // its own, so the decision is `no-majority` (NOT `kind: 'new-doc'`).
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: 'unknown-doc' },
        { peerId: 'p2', hash: 'unknown-doc' },
        { peerId: 'p3', hash: HASH_A },
      ],
      2,
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      // We expect `no-majority` because the tip-hash bucket has size 1
      // and there were 3 responding peers (>= Q).
      expect(decision.reason).toBe('no-majority');
      // The agreement snapshot still records BOTH buckets for operator
      // diagnostics.
      expect(decision.agreement.size).toBe(2);
    }
  });

  test("tip-hash quorum still passes when at least Q peers vote for the same hash, even alongside unknown-doc disclaims", () => {
    // 2 vote HASH_A, 2 disclaim. Tip-hash bucket meets Q=2 and wins;
    // the disclaim bucket is excluded from consideration entirely.
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: HASH_A },
        { peerId: 'p2', hash: HASH_A },
        { peerId: 'p3', hash: 'unknown-doc' },
        { peerId: 'p4', hash: 'unknown-doc' },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.kind).toBe('tip-hash');
      expect(decision.agreeingPeerIds).toEqual(['p1', 'p2']);
    }
  });

  test("majority tip-hash beats minority 'unknown-doc' (single lying peer cannot force new-doc)", () => {
    // 2 honest peers vote HASH_A, 1 malicious peer lies 'unknown-doc'.
    // Tip-hash bucket wins; loader proceeds with normal load.
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: HASH_A },
        { peerId: 'p2', hash: HASH_A },
        { peerId: 'p3', hash: 'unknown-doc' },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.kind).toBe('tip-hash');
      expect(decision.agreeingPeerIds).toEqual(['p1', 'p2']);
    }
  });

  test("'unknown-doc' votes alongside null non-votes still produce kind='new-doc' when they reach Q", () => {
    // 2 disclaims + 1 timeout: disclaims meet Q=2 even with a non-vote.
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: 'unknown-doc' },
        { peerId: 'p2', hash: 'unknown-doc' },
        { peerId: 'p3', hash: null },
      ],
      2,
    );
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.kind).toBe('new-doc');
      expect(decision.respondingCount).toBe(2);
    }
  });

  test("split unknown-doc vs tip-hash with no Q majority fails with no-majority", () => {
    // 1 disclaim, 1 HASH_A, 1 HASH_B, Q=2. No bucket reaches 2.
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: 'unknown-doc' },
        { peerId: 'p2', hash: HASH_A },
        { peerId: 'p3', hash: HASH_B },
      ],
      2,
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe('no-majority');
      // All three buckets show up in the diagnostic snapshot.
      expect(decision.agreement.size).toBe(3);
    }
  });
});

describe('effectiveK / effectiveQ', () => {
  test('effectiveK clamps to known-peer count', () => {
    expect(effectiveK(3, 5)).toBe(3);
    expect(effectiveK(3, 2)).toBe(2);
    expect(effectiveK(3, 0)).toBe(0);
    expect(effectiveK(0, 5)).toBe(0);
  });

  test('effectiveQ clamps to [1, K]', () => {
    expect(effectiveQ(2, 3)).toBe(2);
    expect(effectiveQ(5, 3)).toBe(3); // Q > K -> K
    expect(effectiveQ(0, 3)).toBe(1); // Q < 1 -> 1
    expect(effectiveQ(-1, 3)).toBe(1);
    expect(effectiveQ(2, 0)).toBe(0); // no peers -> no quorum possible
  });

  // PR #284 r9 Copilot review (issue #2): a fractional `configuredK`
  // previously slipped through `Math.min(...)` to produce a non-integer
  // value (e.g. 1.5), which `peers.slice(0, 1.5)` collapsed to a 1-peer
  // probe — silent single-peer load. The `k === 1 && !allowSinglePeer`
  // guard did not fire because `1.5 !== 1`. The defensive `Math.floor`
  // in `effectiveK` now collapses fractional K to an integer.
  describe('effectiveK defensive guards (PR #284 r9)', () => {
    test('fractional K is floored to an integer', () => {
      expect(effectiveK(1.5, 3)).toBe(1);
      expect(effectiveK(2.99, 5)).toBe(2);
      expect(effectiveK(3.7, 5)).toBe(3);
    });

    test('NaN configuredK collapses to 0 (defends against missed startup validation)', () => {
      expect(effectiveK(NaN, 3)).toBe(0);
    });

    test('Infinity configuredK collapses to 0', () => {
      expect(effectiveK(Infinity, 3)).toBe(0);
      expect(effectiveK(-Infinity, 3)).toBe(0);
    });

    test('integer K still flows through unchanged', () => {
      expect(effectiveK(3, 5)).toBe(3);
      expect(effectiveK(1, 5)).toBe(1);
      expect(effectiveK(7, 10)).toBe(7);
    });
  });

  // PR #284 r9 Copilot review (issue #3, suppressed): `effectiveQ(NaN, 3)`
  // previously returned `NaN` because all comparisons against NaN are
  // false (so `configuredQ < 1` and `configuredQ > k` both fell through
  // to `return configuredQ`). `decideLoadQuorum` then evaluated
  // `bestPeers.length < NaN` as false and quorum passed with a single
  // responding peer. The defensive guard collapses NaN/Infinity to
  // `defaultQuorumQ(k)`.
  describe('effectiveQ defensive guards (PR #284 r9)', () => {
    test('NaN configuredQ collapses to defaultQuorumQ(k) (was: returned NaN, gate silently passed)', () => {
      expect(effectiveQ(NaN, 3)).toBe(defaultQuorumQ(3)); // 2
      expect(effectiveQ(NaN, 5)).toBe(defaultQuorumQ(5)); // 3
      expect(effectiveQ(NaN, 1)).toBe(defaultQuorumQ(1)); // 1
    });

    test('Infinity configuredQ collapses to defaultQuorumQ(k)', () => {
      expect(effectiveQ(Infinity, 3)).toBe(defaultQuorumQ(3));
      expect(effectiveQ(-Infinity, 5)).toBe(defaultQuorumQ(5));
    });

    test('fractional Q is floored', () => {
      expect(effectiveQ(2.5, 3)).toBe(2);
      expect(effectiveQ(1.9, 3)).toBe(1);
    });

    test('integer Q still flows through unchanged', () => {
      expect(effectiveQ(2, 3)).toBe(2);
      expect(effectiveQ(3, 3)).toBe(3);
    });
  });
});

describe('validateLoadQuorumConfig (startup input validation, PR #284 r9)', () => {
  // The validator runs at `Peerborne.initialize()` time so a
  // misconfigured `loadQuorumK`/`loadQuorumQ` surfaces immediately
  // rather than silently degrading every subsequent `load()` call.
  // Must reject all non-finite-positive-integer values; must accept
  // `undefined` (operator did not override; orchestrator defaults apply).

  test('accepts undefined (no operator override)', () => {
    expect(() => validateLoadQuorumConfig({})).not.toThrow();
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumK: undefined, loadQuorumQ: undefined }),
    ).not.toThrow();
  });

  test('accepts positive integers', () => {
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumK: 1, loadQuorumQ: 1 }),
    ).not.toThrow();
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumK: 3, loadQuorumQ: 2 }),
    ).not.toThrow();
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumK: 7, loadQuorumQ: 4 }),
    ).not.toThrow();
  });

  test('rejects fractional loadQuorumK with invalid-config error (issue #2)', () => {
    // The exact bug: `loadQuorumK: 1.5` slipped through to
    // `peers.slice(0, 1.5)` and silently probed only 1 peer.
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumK: 1.5 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer/,
    );
    expect((err as LoadQuorumFailedError).message).toMatch(/1\.5/);
  });

  test('rejects NaN loadQuorumK with "got NaN" in message (PR #284 r10 issue #1: not "got null")', () => {
    // PR #284 r10 Copilot review (issue #1): `JSON.stringify(NaN)` is
    // the literal string `'null'`, so the previous error message read
    // `got null` for a `NaN` input — indistinguishable from explicitly
    // passing `null` and actively misleading. The fix renders non-finite
    // numbers via `String(...)` so they show their JS literal.
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumK: NaN });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer; got NaN/,
    );
    // Defence: the misleading legacy `got null` rendering must NOT appear.
    expect((err as LoadQuorumFailedError).message).not.toMatch(
      /got null/,
    );
  });

  test('rejects Infinity loadQuorumK with "got Infinity" in message (PR #284 r10 issue #1)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumK: Infinity });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer; got Infinity/,
    );
    expect((err as LoadQuorumFailedError).message).not.toMatch(/got null/);
  });

  test('rejects -Infinity loadQuorumK with "got -Infinity" in message (PR #284 r10 issue #1)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumK: -Infinity });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer; got -Infinity/,
    );
    expect((err as LoadQuorumFailedError).message).not.toMatch(/got null/);
  });

  test('rejects loadQuorumK = 0', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumK: 0 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumK must be a positive integer/,
    );
  });

  test('rejects negative loadQuorumK', () => {
    expect(() => validateLoadQuorumConfig({ loadQuorumK: -1 })).toThrow(
      LoadQuorumFailedError,
    );
  });

  test('rejects fractional loadQuorumQ with invalid-config error (issue #3)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumQ: 1.5 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumQ must be a positive integer/,
    );
  });

  test('rejects NaN loadQuorumQ with "got NaN" in message (was: silent single-peer quorum pass; PR #284 r10 issue #1: not "got null")', () => {
    // The exact bug: `effectiveQ(NaN, k)` returned `NaN`,
    // `decideLoadQuorum` evaluated `bestPeers.length < NaN` as false,
    // and quorum passed with a single responder. Now refused at startup.
    // PR #284 r10: also verify the rendered value is `NaN`, not the
    // misleading `null` from `JSON.stringify(NaN)`.
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumQ: NaN });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumQ must be a positive integer; got NaN/,
    );
    expect((err as LoadQuorumFailedError).message).not.toMatch(/got null/);
  });

  test('rejects Infinity loadQuorumQ with "got Infinity" in message (PR #284 r10 issue #1)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumQ: Infinity });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumQ must be a positive integer; got Infinity/,
    );
    expect((err as LoadQuorumFailedError).message).not.toMatch(/got null/);
  });

  test('rejects loadQuorumQ = 0', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumQ: 0 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
  });

  test('rejects negative loadQuorumQ', () => {
    expect(() => validateLoadQuorumConfig({ loadQuorumQ: -1 })).toThrow(
      LoadQuorumFailedError,
    );
  });

  test('only the FIRST offending knob is reported (K checked before Q)', () => {
    // When both are invalid the validator throws on K first; the
    // operator fixes K, re-runs, and then sees the Q error. Surfacing
    // both at once would require an aggregate error which the existing
    // LoadQuorumFailedError shape doesn't support.
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumK: 0, loadQuorumQ: NaN });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).message).toMatch(/loadQuorumK/);
    expect((err as LoadQuorumFailedError).message).not.toMatch(/loadQuorumQ/);
  });

  // ---------------------------------------------------------------------
  // loadQuorumTimeoutMs validation (PR #284 r15 Copilot review)
  // ---------------------------------------------------------------------
  // The bug: `loadQuorumTimeoutMs` is passed directly into `setTimeout(...)`
  // inside the tip-advertise probe race in `_raceTipAdvertiseProbe`. Values
  // like `NaN`, `Infinity`, `0`, and negative are coerced by the timer queue
  // to immediate-fire / overflow behaviour — every probe then resolves as a
  // non-vote, quorum fails on EVERY load even with a fully healthy mesh, and
  // the operator has no visible signal pointing back at the misconfig. The
  // validator now requires a finite positive integer in
  // `[1, LOAD_QUORUM_TIMEOUT_MS_MAX]` so the misconfig is loud at startup.

  test('accepts undefined loadQuorumTimeoutMs (orchestrator default applies)', () => {
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumTimeoutMs: undefined }),
    ).not.toThrow();
  });

  test('accepts valid integer loadQuorumTimeoutMs (1 ms, default 5 s, max)', () => {
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumTimeoutMs: 1 }),
    ).not.toThrow();
    expect(() =>
      validateLoadQuorumConfig({ loadQuorumTimeoutMs: 5000 }),
    ).not.toThrow();
    expect(() =>
      validateLoadQuorumConfig({
        loadQuorumTimeoutMs: LOAD_QUORUM_TIMEOUT_MS_MAX,
      }),
    ).not.toThrow();
  });

  test('rejects NaN loadQuorumTimeoutMs with "got NaN" in message', () => {
    // Was: silently coerced to immediate-fire setTimeout, every probe
    // recorded as non-vote, quorum failed every load.
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumTimeoutMs: NaN });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumTimeoutMs must be a positive integer.*got NaN/,
    );
    // Defence: must NOT render NaN as the misleading `null` from JSON.stringify.
    expect((err as LoadQuorumFailedError).message).not.toMatch(/got null/);
  });

  test('rejects Infinity loadQuorumTimeoutMs', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumTimeoutMs: Infinity });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumTimeoutMs must be a positive integer.*got Infinity/,
    );
  });

  test('rejects loadQuorumTimeoutMs = 0 (would fire setTimeout immediately)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumTimeoutMs: 0 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumTimeoutMs must be a positive integer.*got 0/,
    );
  });

  test('rejects negative loadQuorumTimeoutMs (-1)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumTimeoutMs: -1 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumTimeoutMs must be a positive integer.*got -1/,
    );
  });

  test('rejects fractional loadQuorumTimeoutMs (1.5)', () => {
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumTimeoutMs: 1.5 });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumTimeoutMs must be a positive integer.*got 1\.5/,
    );
  });

  test('rejects loadQuorumTimeoutMs above the 5-minute upper bound (catches typos)', () => {
    // The upper bound catches typos like `5000000` (5 000 s = 83 min)
    // or mistakenly-passed nanosecond values — far larger than any
    // realistic per-probe budget on a wide-area mesh.
    const tooLarge = LOAD_QUORUM_TIMEOUT_MS_MAX + 1;
    const err = (() => {
      try {
        validateLoadQuorumConfig({ loadQuorumTimeoutMs: tooLarge });
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).reason).toBe('invalid-config');
    expect((err as LoadQuorumFailedError).message).toMatch(
      /loadQuorumTimeoutMs must be a positive integer no greater than/,
    );
    expect((err as LoadQuorumFailedError).message).toMatch(
      new RegExp(String(tooLarge)),
    );
  });

  test('accepts loadQuorumTimeoutMs combined with valid K/Q', () => {
    expect(() =>
      validateLoadQuorumConfig({
        loadQuorumK: 3,
        loadQuorumQ: 2,
        loadQuorumTimeoutMs: 5000,
      }),
    ).not.toThrow();
  });
});

describe('formatConfigValue (PR #284 r10 issue #1: non-finite numbers render as their literal, not "null")', () => {
  // The root cause: `JSON.stringify(NaN)`, `JSON.stringify(Infinity)`,
  // and `JSON.stringify(-Infinity)` all return the literal string
  // `'null'` because JSON has no representation for those values. An
  // operator who set `loadQuorumK: NaN` would then see `got null` in
  // the error message, indistinguishable from explicitly passing
  // `null` and actively misleading about which misconfiguration
  // they triggered. The helper coerces non-finite numbers via
  // `String(...)` so they render as their JS literal.

  test('NaN renders as "NaN" (was: "null" under JSON.stringify)', () => {
    expect(formatConfigValue(NaN)).toBe('NaN');
    expect(formatConfigValue(NaN)).not.toBe('null');
  });

  test('Infinity renders as "Infinity"', () => {
    expect(formatConfigValue(Infinity)).toBe('Infinity');
    expect(formatConfigValue(Infinity)).not.toBe('null');
  });

  test('-Infinity renders as "-Infinity"', () => {
    expect(formatConfigValue(-Infinity)).toBe('-Infinity');
    expect(formatConfigValue(-Infinity)).not.toBe('null');
  });

  test('finite numbers pass through JSON.stringify unchanged', () => {
    expect(formatConfigValue(0)).toBe('0');
    expect(formatConfigValue(-1)).toBe('-1');
    expect(formatConfigValue(1.5)).toBe('1.5');
    expect(formatConfigValue(42)).toBe('42');
  });

  test('explicit null still renders as "null" (distinct from NaN now)', () => {
    // An operator who explicitly passes `null` (e.g. via a YAML parse
    // of an empty value) should see `null` in the error — and the
    // rendered value must now be DISTINGUISHABLE from a NaN input.
    expect(formatConfigValue(null)).toBe('null');
    // Sanity contrast: NaN and null no longer collide.
    expect(formatConfigValue(NaN)).not.toBe(formatConfigValue(null));
  });

  test("undefined coerces to the string 'undefined'", () => {
    // `JSON.stringify(undefined)` returns `undefined` (NOT a string),
    // which would break the function's declared `string` return type
    // under strict-mode TypeScript and also surface as `got undefined`
    // through coercion in operator-visible error messages. PR #284 r18
    // Copilot review tightened the helper to always return a string;
    // for `undefined` we fall back to `String(undefined)` so callers
    // (and the type system) see a clean string. `validateLoadQuorumConfig`
    // still early-returns on `undefined` before calling the helper, so
    // this fallback is defensive — the helper's behaviour is pinned here.
    expect(formatConfigValue(undefined)).toBe('undefined');
  });

  test('strings, objects, arrays still flow through JSON.stringify', () => {
    expect(formatConfigValue('hello')).toBe('"hello"');
    expect(formatConfigValue({ k: 3 })).toBe('{"k":3}');
    expect(formatConfigValue([1, 2, 3])).toBe('[1,2,3]');
    expect(formatConfigValue(true)).toBe('true');
    expect(formatConfigValue(false)).toBe('false');
  });

  // `JSON.stringify` raises a `TypeError` on BigInt values and another on
  // any object that contains a cycle. Before guarding with try/catch those
  // raw errors would escape the validator and surface to operators as a
  // bare `TypeError`, masking the actual config-validation message. The
  // helper now catches and falls back to `String(value)` so the surrounding
  // `LoadQuorumFailedError(invalid-config, ...)` message stays well-formed.
  test('BigInt falls back to String() instead of throwing TypeError', () => {
    expect(() => formatConfigValue(BigInt(42))).not.toThrow();
    expect(formatConfigValue(BigInt(42))).toBe('42');
  });

  test('circular object falls back to String() instead of throwing', () => {
    const cyclic: Record<string, unknown> = { name: 'cycle' };
    cyclic['self'] = cyclic;
    expect(() => formatConfigValue(cyclic)).not.toThrow();
    // `String({})` is `'[object Object]'`; we only pin that the helper
    // returns *some* string and does not crash on a cycle.
    expect(typeof formatConfigValue(cyclic)).toBe('string');
  });
});

describe('defaultQuorumQ (strict-majority formula, #189 §5.4.2)', () => {
  // The PR description and config docstring require strict majority — i.e.
  // `Math.floor(K/2) + 1`, NOT `Math.ceil(K/2) + 1`. The earlier ceil-based
  // default produced Q=3 at K=3, which made the gate refuse to pass with
  // even one non-vote and silently defeated the BFT intent ("tolerate one
  // fault"). These tests pin the formula so a future change has to
  // explicitly justify breaking the matrix.
  test('K=1 -> Q=1', () => {
    expect(defaultQuorumQ(1)).toBe(1);
  });
  test('K=2 -> Q=2', () => {
    expect(defaultQuorumQ(2)).toBe(2);
  });
  test('K=3 -> Q=2 (one fault tolerated, NOT three-of-three)', () => {
    expect(defaultQuorumQ(3)).toBe(2);
  });
  test('K=4 -> Q=3', () => {
    expect(defaultQuorumQ(4)).toBe(3);
  });
  test('K=5 -> Q=3', () => {
    expect(defaultQuorumQ(5)).toBe(3);
  });
  test('K=7 -> Q=4', () => {
    expect(defaultQuorumQ(7)).toBe(4);
  });
  test('K=0 -> Q=0 (no peers, no quorum possible)', () => {
    expect(defaultQuorumQ(0)).toBe(0);
  });
  test('K<0 -> Q=0 (clamped)', () => {
    expect(defaultQuorumQ(-1)).toBe(0);
  });

  test('rejects the legacy ceil-based formula at K=3', () => {
    // Math.ceil(3 / 2) + 1 === 3 — would require all three peers to agree,
    // refusing a single timeout. defaultQuorumQ must NOT return 3 here.
    expect(defaultQuorumQ(3)).not.toBe(Math.ceil(3 / 2) + 1);
  });
});

describe('dedupePeersByPeerId (multi-connection vote inflation, #186)', () => {
  // libp2p's `getConnections()` returns one entry per OPEN connection, not
  // per remote peer. A peer with both a direct and a relay-circuit
  // connection shows up twice; without dedup they cast two quorum votes,
  // letting a single malicious peer with two connections out-vote one
  // honest peer.
  test('collapses two entries with the same peerId into one', () => {
    const peers = [
      { addr: '/ip4/1.1.1.1/tcp/1/p2p/A' },
      { addr: '/ip4/2.2.2.2/tcp/2/p2p/A' }, // same peerId A, different multiaddr
      { addr: '/ip4/3.3.3.3/tcp/3/p2p/B' },
    ];
    const out = dedupePeersByPeerId(peers, (p) => {
      const m = [...p.addr.matchAll(/\/p2p\/([^/]+)/g)];
      return m.length > 0 ? m[m.length - 1][1] : p.addr;
    });
    expect(out).toHaveLength(2);
    expect(out[0].addr).toBe('/ip4/1.1.1.1/tcp/1/p2p/A');
    expect(out[1].addr).toBe('/ip4/3.3.3.3/tcp/3/p2p/B');
  });

  test('preserves first-seen order (preferredPeer at index 0 stays first)', () => {
    const peers = ['preferred', 'a', 'preferred', 'b', 'a'];
    const out = dedupePeersByPeerId(peers, (s) => s);
    expect(out).toEqual(['preferred', 'a', 'b']);
  });

  test('treats relay-circuit + direct multiaddrs of one peer as one vote', () => {
    // Real-world case: a peer reachable both directly and via a relay
    // circuit shows up as `.../p2p/<remote>` and `.../p2p/<relay>/p2p-circuit/p2p/<remote>`.
    // `_peerIdOf` extracts the LAST `/p2p/<id>` (the remote peer id), so
    // both entries collapse to the same key.
    const peers = [
      { addr: '/ip4/1.1.1.1/tcp/9000/p2p/Q' },
      { addr: '/ip4/2.2.2.2/tcp/9001/p2p/R/p2p-circuit/p2p/Q' },
    ];
    const out = dedupePeersByPeerId(peers, (p) => {
      const m = [...p.addr.matchAll(/\/p2p\/([^/]+)/g)];
      return m.length > 0 ? m[m.length - 1][1] : p.addr;
    });
    expect(out).toHaveLength(1);
  });

  test('empty input returns empty output', () => {
    expect(dedupePeersByPeerId([], (s: string) => s)).toEqual([]);
  });

  test('does not mutate the input array', () => {
    const input = ['a', 'a', 'b'];
    const out = dedupePeersByPeerId(input, (s) => s);
    expect(input).toEqual(['a', 'a', 'b']);
    expect(out).toEqual(['a', 'b']);
  });
});

describe('founding-case removal (#186, suppressed comment fix)', () => {
  // Regression coverage for the unsafe `_hashes.size === 0` bypass. Before
  // this fix, the loader skipped the quorum gate whenever its local
  // `_hashes` was empty on the theory that an empty set could not be
  // "poisoned" — but `_hashes` is ALSO empty on the very first `open()` of
  // an EXISTING document (before load populates it), which is exactly the
  // case the quorum check is meant to defend. The fix removes the bypass
  // entirely; the gate now runs uniformly. These tests verify that the
  // decision logic does not give the gate any escape hatch keyed on the
  // local hash-set state — the only legitimate "no quorum" paths are
  // `k === 0` (no peers at all) and the explicit `allowSinglePeer` knob.
  test('with K>=2 known peers, decideLoadQuorum still requires Q votes regardless of caller state', () => {
    // Caller passes Q=2; a single agreeing vote (the rest non-votes) is
    // not enough. This holds whether the caller is a fresh founder or
    // a partitioned existing-document opener — `decideLoadQuorum` is
    // stateless w.r.t. the caller, by design.
    const decision = decideLoadQuorum(
      [
        { peerId: 'p1', hash: new Uint8Array(32).fill(0xaa) },
        { peerId: 'p2', hash: null },
        { peerId: 'p3', hash: null },
      ],
      2,
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe('insufficient-responses');
    }
  });

  test('effectiveK + defaultQuorumQ together force the gate on K>=2 even when local state is empty', () => {
    // Simulate "fresh open with peers available": local hashes empty
    // (irrelevant to these pure helpers), known peers = 3, configured K = 3.
    const k = effectiveK(3, 3);
    const q = effectiveQ(defaultQuorumQ(3), k);
    expect(k).toBe(3);
    expect(q).toBe(2); // strict majority; founders no longer get a free pass
  });
});

describe('constantTimeHexEquals (hash-binding comparison)', () => {
  test('equal lowercase hex strings compare equal', () => {
    expect(constantTimeHexEquals('aa'.repeat(32), 'aa'.repeat(32))).toBe(true);
  });

  test('different hex strings of the same length compare unequal', () => {
    expect(constantTimeHexEquals('aa'.repeat(32), 'ab'.repeat(32))).toBe(false);
  });

  test('strings of different lengths compare unequal', () => {
    expect(constantTimeHexEquals('aa', 'aabb')).toBe(false);
  });

  test('empty strings compare equal', () => {
    expect(constantTimeHexEquals('', '')).toBe(true);
  });

  test('case-sensitive (matches `tipsHashToHex` lowercase output)', () => {
    expect(constantTimeHexEquals('aabb', 'AABB')).toBe(false);
  });
});

describe('LoadQuorumFailedError', () => {
  test('carries structured fields for application-level recovery', () => {
    const err = new LoadQuorumFailedError({
      documentPath: '/docs/x',
      reason: 'no-majority',
      respondingCount: 3,
      requiredQ: 2,
      agreement: new Map([
        ['aa', 1],
        ['bb', 1],
        ['cc', 1],
      ]),
    });
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('LoadQuorumFailedError');
    expect(err.documentPath).toBe('/docs/x');
    expect(err.reason).toBe('no-majority');
    expect(err.respondingCount).toBe(3);
    expect(err.requiredQ).toBe(2);
    expect(err.agreement.size).toBe(3);
    expect(err.message).toMatch(/quorum failed/i);
  });

  test("invalid-config reason carries operator-visible detail (PR #284 r5)", () => {
    // The 'invalid-config' variant is surfaced by `runLoadQuorum` when
    // `loadQuorumK <= 0`, where the structured `respondingCount`/
    // `requiredQ` fields are not meaningful (no probes were run). The
    // `detail` constructor field is the surface used to carry the
    // offending value into the operator-visible message.
    const err = new LoadQuorumFailedError({
      documentPath: '/docs/x',
      reason: 'invalid-config',
      respondingCount: 0,
      requiredQ: 0,
      agreement: new Map(),
      detail: 'loadQuorumK must be >= 1; got 0',
    });
    expect(err.reason).toBe('invalid-config');
    expect(err.message).toMatch(/loadQuorumK must be >= 1; got 0/);
  });

  test('bind-check-failed-all-agreeing-peers carries per-peer agreeingPeerBindFailures (PR #284 r6)', () => {
    // The 'bind-check-failed-all-agreeing-peers' variant is surfaced by
    // `PeerborneDocument.load()` after the agreeing cohort is exhausted
    // and every peer failed the post-load tipsHash bind check. The
    // `agreeingPeerBindFailures` field records, per peer, the hex hash
    // the responder's served `tips` actually hashed to (or the sentinel
    // `'(missing tips)'` for an omitted-tips response).
    const failures = new Map<string, string>([
      ['12D3KooWPeer1', 'ff'.repeat(32)],
      ['12D3KooWPeer2', '(missing tips)'],
    ]);
    const err = new LoadQuorumFailedError({
      documentPath: '/docs/x',
      reason: 'bind-check-failed-all-agreeing-peers',
      respondingCount: 0,
      requiredQ: 0,
      agreement: new Map([['aa'.repeat(32), 0]]),
      agreeingPeerBindFailures: failures,
    });
    expect(err.reason).toBe('bind-check-failed-all-agreeing-peers');
    expect(err.agreeingPeerBindFailures).toBe(failures);
    expect(err.agreeingPeerBindFailures.size).toBe(2);
    expect(err.agreeingPeerBindFailures.get('12D3KooWPeer2')).toBe(
      '(missing tips)',
    );
    // The composed message names the cohort size for operator observability.
    expect(err.message).toMatch(/agreeing cohort.*2 peer/);
    expect(err.message).toMatch(/Byzantine equivocation/);
  });

  test('agreeingPeerBindFailures defaults to empty map for non-bind reasons', () => {
    // Reasons other than `bind-check-failed-all-agreeing-peers` do not
    // populate `agreeingPeerBindFailures`; the field must still be a
    // readable empty map (NOT undefined) so callers can iterate
    // unconditionally without a null-check.
    const err = new LoadQuorumFailedError({
      documentPath: '/docs/x',
      reason: 'no-majority',
      respondingCount: 1,
      requiredQ: 2,
      agreement: new Map(),
    });
    expect(err.agreeingPeerBindFailures).toBeInstanceOf(Map);
    expect(err.agreeingPeerBindFailures.size).toBe(0);
  });
});
