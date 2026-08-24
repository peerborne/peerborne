import { describe, expect, test } from '@jest/globals';
import { tipsHash, tipsHashToHex, TIPS_HASH_LENGTH } from './tips-hash.js';
import { constantTimeHexEquals } from './load-quorum.js';

describe('tipsHash (initial-load quorum, #189 §5.4.2)', () => {
  test('returns a 32-byte SHA-256 digest', async () => {
    const hash = await tipsHash(['bafy1', 'bafy2']);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(TIPS_HASH_LENGTH);
  });

  test('is deterministic regardless of input order', async () => {
    const a = await tipsHash(['bafy1', 'bafy2', 'bafy3']);
    const b = await tipsHash(['bafy3', 'bafy1', 'bafy2']);
    expect(tipsHashToHex(a)).toBe(tipsHashToHex(b));
  });

  test('accepts a Set<string> and matches the array form', async () => {
    const fromSet = await tipsHash(new Set(['bafy1', 'bafy2']));
    const fromArr = await tipsHash(['bafy2', 'bafy1']);
    expect(tipsHashToHex(fromSet)).toBe(tipsHashToHex(fromArr));
  });

  test('different tip sets produce different hashes', async () => {
    const a = await tipsHash(['bafy1', 'bafy2']);
    const b = await tipsHash(['bafy1', 'bafy3']);
    expect(tipsHashToHex(a)).not.toBe(tipsHashToHex(b));
  });

  test('empty tip set has a stable hash (founding-member case)', async () => {
    const a = await tipsHash([]);
    const b = await tipsHash(new Set<string>());
    expect(tipsHashToHex(a)).toBe(tipsHashToHex(b));
    expect(a.length).toBe(TIPS_HASH_LENGTH);
  });

  test('boundary-ambiguous inputs do not collide (separator works)', async () => {
    // If the canonicalizer concatenated CIDs without a separator,
    // ["ab", "c"] and ["a", "bc"] would hash identically.
    const a = await tipsHash(['ab', 'c']);
    const b = await tipsHash(['a', 'bc']);
    expect(tipsHashToHex(a)).not.toBe(tipsHashToHex(b));
  });

  test('does not mutate the caller-provided collection', async () => {
    const input = ['z', 'a', 'm'];
    await tipsHash(input);
    expect(input).toEqual(['z', 'a', 'm']);
  });
});

describe('tipsHashToHex', () => {
  test('produces lowercase hex of correct length', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xff, 0xab]);
    expect(tipsHashToHex(bytes)).toBe('000fffab');
  });
});

describe('hash binding: equivocating peer rejection (#186 / #189 §5.4.2)', () => {
  // Models the in-line binding check in
  // `PeerborneDocument._sendLoadRequestAndSync`. The responder includes
  // its own current frontier as `message.tips` on the load response; the
  // loader hashes that and compares to the quorum-agreed `winningHashHex`.
  // A peer that votes for tip set X but serves a load whose `tips` hash
  // to Y is treated as Byzantine equivocation and rejected — without this
  // binding, a malicious peer in the agreeing cohort could vote with the
  // majority and then serve arbitrary state.
  //
  // Hashing the responder's signed `tips` attestation (rather than
  // recomputing `tipsHash(loader._hashes)` post-sync) keeps the binding
  // correct under snapshot-loads (which don't restore ancestor CIDs to
  // `_hashes`) and history compaction.
  test('matching vote and serve passes the binding check', async () => {
    const advertisedTips = ['cidA', 'cidB', 'cidC'];
    const servedTips = ['cidC', 'cidA', 'cidB']; // same set, different order
    const advertisedHex = tipsHashToHex(await tipsHash(advertisedTips));
    const servedHex = tipsHashToHex(await tipsHash(servedTips));
    expect(constantTimeHexEquals(advertisedHex, servedHex)).toBe(true);
  });

  // The same logical case (vote X, serve Y → reject) under a range of
  // adversarial shapes. Table-driven so adding a new attack pattern only
  // needs one row.
  test.each([
    {
      label: 'subset-serve (vote {A,B}, serve {A})',
      advertisedTips: ['cidA', 'cidB'] as string[],
      servedTips: ['cidA'] as string[],
    },
    {
      label: 'extra-cid-injection (vote {A,B}, serve {A,B,evil})',
      advertisedTips: ['cidA', 'cidB'] as string[],
      servedTips: ['cidA', 'cidB', 'cidEvil'] as string[],
    },
    {
      label: 'founding-case-spoof (vote {}, serve {A})',
      advertisedTips: [] as string[],
      servedTips: ['cidA'] as string[],
    },
    {
      label: 'disjoint-set (vote {A}, serve {B})',
      advertisedTips: ['cidA'] as string[],
      servedTips: ['cidB'] as string[],
    },
  ])(
    'mismatched vote vs serve fails the binding check: $label',
    async ({ advertisedTips, servedTips }) => {
      const advertisedHex = tipsHashToHex(await tipsHash(advertisedTips));
      const servedHex = tipsHashToHex(await tipsHash(servedTips));
      expect(constantTimeHexEquals(advertisedHex, servedHex)).toBe(false);
    },
  );
});
