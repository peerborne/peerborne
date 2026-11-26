import { describe, expect, jest, test } from '@jest/globals';
import {
  CompactionConfig,
  defaultCompactionConfig,
} from './compaction-config.js';
import { CRDTSnapshotNode } from './snapshot-node.js';
import { buildSnapshotSignaturePayload } from './snapshot-signature-payload.js';
import {
  isBlockNotFoundError,
  loadChangeBlock,
} from './blockstore-gc.js';

describe('Compaction trigger logic', () => {
  /**
   * Simulates the _maybeCompact() logic without needing the full
   * PeerborneDocument infrastructure. Tests the decision logic only.
   */
  function shouldCompact(
    config: CompactionConfig,
    documentChangeCount: number,
    changesSinceSnapshot: number,
  ): boolean {
    if (!config.enabled) return false;
    if (documentChangeCount < config.minChangesBeforeSnapshot) return false;
    if (changesSinceSnapshot < config.snapshotInterval) return false;
    return true;
  }

  test('does not compact when disabled', () => {
    expect(
      shouldCompact(
        { ...defaultCompactionConfig, enabled: false },
        1000,
        600,
      ),
    ).toBe(false);
  });

  test('does not compact below minimum threshold', () => {
    expect(
      shouldCompact(
        { ...defaultCompactionConfig, enabled: true, minChangesBeforeSnapshot: 100 },
        50,
        500,
      ),
    ).toBe(false);
  });

  test('does not compact before interval reached', () => {
    expect(
      shouldCompact(
        { ...defaultCompactionConfig, enabled: true, snapshotInterval: 500 },
        200,
        499,
      ),
    ).toBe(false);
  });

  test('compacts when all conditions are met', () => {
    expect(
      shouldCompact(
        { ...defaultCompactionConfig, enabled: true, snapshotInterval: 500, minChangesBeforeSnapshot: 100 },
        500,
        500,
      ),
    ).toBe(true);
  });

  test('compacts when well past interval', () => {
    expect(
      shouldCompact(
        { ...defaultCompactionConfig, enabled: true, snapshotInterval: 100, minChangesBeforeSnapshot: 50 },
        1000,
        300,
      ),
    ).toBe(true);
  });

  test('resets counter after compaction', () => {
    // Simulate: after compaction, changesSinceSnapshot resets to 0.
    const config: CompactionConfig = {
      ...defaultCompactionConfig,
      enabled: true,
      snapshotInterval: 100,
      minChangesBeforeSnapshot: 50,
    };

    // Before compaction - should trigger.
    expect(shouldCompact(config, 200, 100)).toBe(true);

    // After compaction - counter resets, should not trigger again.
    expect(shouldCompact(config, 200, 0)).toBe(false);

    // After more changes accumulate past the interval again.
    expect(shouldCompact(config, 300, 100)).toBe(true);
  });
});

describe('Snapshot sign payload construction', () => {
  const DOMAIN = 'peerborne/snapshot-signature/v2\0';
  const PATH = '/docs/alpha';
  const build = (
    stateBytes: Uint8Array,
    lastChangeNodeCID: string,
    timestamp: number,
    compactedCount: number,
    documentPath = PATH,
  ) =>
    buildSnapshotSignaturePayload(
      documentPath,
      stateBytes,
      lastChangeNodeCID,
      timestamp,
      compactedCount,
    );

  test('produces deterministic output for same inputs', () => {
    const state = new Uint8Array([1, 2, 3]);
    const a = build(state, 'bafytest123', 1700000000000, 100);
    const b = build(state, 'bafytest123', 1700000000000, 100);
    expect(a).toEqual(b);
  });

  test('encodes the domain, the length-prefixed path and every field', () => {
    const payload = build(new Uint8Array([7, 8]), 'cid', 0x0102030405, 9);
    const encoder = new TextEncoder();
    const expected = new Uint8Array([
      ...encoder.encode(DOMAIN),
      0, 0, 0, 11, ...encoder.encode(PATH),
      0, 0, 0, 1, 2, 3, 4, 5,
      0, 0, 0, 9,
      0, 0, 0, 3, ...encoder.encode('cid'),
      0, 0, 0, 2, 7, 8,
    ]);
    expect(payload).toEqual(expected);
  });

  test('different inputs produce different payloads', () => {
    const state = new Uint8Array([1, 2, 3]);
    const a = build(state, 'cid-a', 1700000000000, 100);
    const b = build(state, 'cid-b', 1700000000000, 100);
    expect(a).not.toEqual(b);
  });

  test('binds the document path', () => {
    const state = new Uint8Array([1, 2, 3]);
    expect(build(state, 'cid', 1, 1, '/docs/a')).not.toEqual(
      build(state, 'cid', 1, 1, '/docs/b'),
    );
  });

  test('a path cannot absorb bytes from the following fields', () => {
    const state = new Uint8Array([1]);
    const left = build(state, 'cid', 1, 1, '/a');
    const right = build(state, 'cid', 1, 1, '/a\u0000');
    expect(left).not.toEqual(right);
    expect(left.byteLength).not.toBe(right.byteLength);
    const shifted = build(new Uint8Array([]), 'x', 1, 1, '/a');
    const unshifted = build(new Uint8Array([]), '', 1, 1, '/ax');
    expect(shifted).not.toEqual(unshifted);
  });

  test('starts with the versioned domain and no legacy version byte', () => {
    const payload = build(new Uint8Array([42]), 'cid', 1700000000000, 50);
    const domain = new TextEncoder().encode(DOMAIN);
    expect(payload.subarray(0, domain.length)).toEqual(domain);
    expect(payload[0]).not.toBe(1);
  });

  test.each([
    ['empty', ''],
    ['lone surrogate', '/docs/\ud800'],
    ['oversized', `/${'a'.repeat(4096)}`],
  ])('rejects an %s document path', (_name, documentPath) => {
    expect(() => build(new Uint8Array([1]), 'cid', 1000, 1, documentPath)).toThrow(
      /snapshot document path/i,
    );
  });

  test('rejects a non-string document path', () => {
    expect(() =>
      buildSnapshotSignaturePayload(
        42 as unknown as string,
        new Uint8Array([1]),
        'cid',
        1000,
        1,
      ),
    ).toThrow('Invalid snapshot document path');
  });

  test('rejects a non-string CID and non-byte state', () => {
    expect(() =>
      build(new Uint8Array([1]), 7 as unknown as string, 1000, 1),
    ).toThrow('Invalid snapshot lastChangeNodeCID');
    expect(() =>
      build([1] as unknown as Uint8Array, 'cid', 1000, 1),
    ).toThrow('Invalid snapshot state');
  });

  test('rejects non-integer timestamp', () => {
    expect(() => build(new Uint8Array([1]), 'cid', 1.5, 10)).toThrow(
      'Invalid snapshot timestamp',
    );
  });

  test('rejects negative timestamp', () => {
    expect(() => build(new Uint8Array([1]), 'cid', -1, 10)).toThrow(
      'Invalid snapshot timestamp',
    );
  });

  test('rejects NaN timestamp', () => {
    expect(() => build(new Uint8Array([1]), 'cid', NaN, 10)).toThrow(
      'Invalid snapshot timestamp',
    );
  });

  test('rejects non-integer compactedCount', () => {
    expect(() => build(new Uint8Array([1]), 'cid', 1000, 1.5)).toThrow(
      'Invalid snapshot compactedCount',
    );
  });

  test('rejects compactedCount exceeding uint32 max', () => {
    expect(() => build(new Uint8Array([1]), 'cid', 1000, 0x100000000)).toThrow(
      'Invalid snapshot compactedCount',
    );
  });

  test('accepts compactedCount at uint32 max', () => {
    expect(() =>
      build(new Uint8Array([1]), 'cid', 1000, 0xffffffff),
    ).not.toThrow();
  });
});

describe('Snapshot tie-breaking', () => {
  /**
   * Mirrors the snapshot selection logic in PeerborneDocument.sync().
   * Returns true if `incoming` should replace `current`.
   */
  function shouldReplace(
    current: CRDTSnapshotNode<Uint8Array> | undefined,
    incoming: CRDTSnapshotNode<Uint8Array>,
  ): boolean {
    if (!current) return true;
    if (incoming.compactedCount > current.compactedCount) return true;
    if (
      incoming.compactedCount === current.compactedCount &&
      String(incoming.lastChangeNodeCID ?? '') >
        String(current.lastChangeNodeCID ?? '')
    ) {
      return true;
    }
    return false;
  }

  function makeSnapshot(
    compactedCount: number,
    lastChangeNodeCID: string,
  ): CRDTSnapshotNode<Uint8Array> {
    return {
      state: new Uint8Array([1]),
      lastChangeNodeCID,
      compactedCount,
      signature: new Uint8Array([1]),
      timestamp: 1700000000000,
    };
  }

  test('replaces when no existing snapshot', () => {
    expect(shouldReplace(undefined, makeSnapshot(100, 'cid-a'))).toBe(true);
  });

  test('replaces when incoming has higher compactedCount', () => {
    expect(shouldReplace(
      makeSnapshot(100, 'cid-z'),
      makeSnapshot(200, 'cid-a'),
    )).toBe(true);
  });

  test('does not replace when incoming has lower compactedCount', () => {
    expect(shouldReplace(
      makeSnapshot(200, 'cid-a'),
      makeSnapshot(100, 'cid-z'),
    )).toBe(false);
  });

  test('tie-breaks on lastChangeNodeCID when compactedCount is equal', () => {
    expect(shouldReplace(
      makeSnapshot(100, 'cid-a'),
      makeSnapshot(100, 'cid-b'),
    )).toBe(true);

    expect(shouldReplace(
      makeSnapshot(100, 'cid-b'),
      makeSnapshot(100, 'cid-a'),
    )).toBe(false);
  });

  test('does not replace when both fields are equal', () => {
    expect(shouldReplace(
      makeSnapshot(100, 'cid-a'),
      makeSnapshot(100, 'cid-a'),
    )).toBe(false);
  });
});

describe('Lazy load decision logic (simplified sketch)', () => {
  /**
   * Simplified decision sketch for the lazy-load path. It is intentionally
   * coarser than the production `loadChangeBlock` helper:
   *
   *   - It maps ALL `getBlock` throws to 'missing' (production rethrows
   *     non-ERR_NOT_FOUND errors so callers can distinguish decrypt /
   *     deserialize failures from a locally-missing block).
   *   - It also coerces an `undefined` resolution to 'missing' (production
   *     returns whatever the fetcher resolves to).
   *
   * Kept around to document the high-level decision tree readably; production
   * semantics are exercised below in "loadChangeBlock helper (real lazy-load
   * semantics)". See `loadChangeBlock` in `./blockstore-gc.ts` and
   * `PeerborneDocument.loadChangeBlock` for the authoritative behavior.
   */
  async function loadChangeBlockDecision(
    hashes: Set<string>,
    cid: string,
    parseCID: (c: string) => unknown,
    getBlock: (parsed: unknown) => Promise<Uint8Array | undefined>,
  ): Promise<'unknown' | 'invalid' | 'ok' | 'missing'> {
    if (!hashes.has(cid)) return 'unknown';
    let parsed: unknown;
    try {
      parsed = parseCID(cid);
    } catch {
      return 'invalid';
    }
    try {
      const result = await getBlock(parsed);
      return result === undefined ? 'missing' : 'ok';
    } catch {
      return 'missing';
    }
  }

  const validParse = (c: string) => ({ cid: c });
  const okGet = async () => new Uint8Array([1, 2, 3]);
  const throwGet = async () => { throw new Error('blockstore.get failed'); };
  const undefGet = async () => undefined;

  type Case = {
    name: string;
    hashes: string[];
    cid: string;
    parseCID: (c: string) => unknown;
    getBlock: (parsed: unknown) => Promise<Uint8Array | undefined>;
    expected: 'unknown' | 'invalid' | 'ok' | 'missing';
  };

  const cases: Case[] = [
    {
      name: 'unknown CID is rejected without touching blockstore',
      hashes: ['cid-1'],
      cid: 'cid-2',
      parseCID: validParse,
      getBlock: okGet,
      expected: 'unknown',
    },
    {
      name: 'known CID with successful blockstore.get returns ok',
      hashes: ['cid-1'],
      cid: 'cid-1',
      parseCID: validParse,
      getBlock: okGet,
      expected: 'ok',
    },
    {
      name: 'known CID with throwing blockstore.get returns missing',
      hashes: ['cid-1'],
      cid: 'cid-1',
      parseCID: validParse,
      getBlock: throwGet,
      expected: 'missing',
    },
    {
      name: 'known CID with undefined blockstore.get result returns missing',
      hashes: ['cid-1'],
      cid: 'cid-1',
      parseCID: validParse,
      getBlock: undefGet,
      expected: 'missing',
    },
    {
      name: 'malformed CID throws invalid',
      hashes: ['cid-bad'],
      cid: 'cid-bad',
      parseCID: () => { throw new Error('parse error'); },
      getBlock: okGet,
      expected: 'invalid',
    },
    {
      name: 'empty hashes set always reports unknown',
      hashes: [],
      cid: 'cid-1',
      parseCID: validParse,
      getBlock: okGet,
      expected: 'unknown',
    },
  ];

  for (const c of cases) {
    test(c.name, async () => {
      const result = await loadChangeBlockDecision(
        new Set(c.hashes),
        c.cid,
        c.parseCID,
        c.getBlock,
      );
      expect(result).toBe(c.expected);
    });
  }

  test('blockstore is not touched when CID is unknown', async () => {
    let getBlockCalls = 0;
    const spyGet = async () => {
      getBlockCalls++;
      return new Uint8Array([1]);
    };
    const result = await loadChangeBlockDecision(
      new Set(['cid-1']),
      'cid-unknown',
      validParse,
      spyGet,
    );
    expect(result).toBe('unknown');
    expect(getBlockCalls).toBe(0);
  });
});

/**
 * Tests for the actual `loadChangeBlock` helper used by
 * `PeerborneDocument.loadChangeBlock`. The helper lives in `blockstore-gc.ts`
 * so it can be exercised without dragging in libp2p/helia. The document method
 * is a thin delegate, so these tests pin the real semantics that the public
 * API exposes (unknown CID short-circuit, malformed CID rejection, ERR_NOT_FOUND
 * mapped to `undefined`, decrypt/deserialize failures rethrown).
 */
describe('loadChangeBlock helper (real lazy-load semantics)', () => {
  // Valid CIDv1 (sha256, dag-pb) used as a stand-in for a known change block.
  const REAL_CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
  // A second valid CID, distinct from REAL_CID -- used as an "unknown but
  // parseable" CID so we can exercise the unknown-CID short-circuit without
  // having to construct a separate parse-error case.
  const OTHER_CID = 'bafybeibwzifw5kdscvuwbpqdfqzkv6kqgvkfknhomh4l5wuojfqsbm5cyy';

  // Identity parser used when we don't care about CID structure; the helper
  // is generic so the test doesn't need real multiformats.
  const parseAsString = (c: string) => c;
  const parseThrowing = (c: string) => {
    throw new Error(`bad CID ${c}`);
  };

  test('returns undefined for unknown CIDs without touching the fetcher', async () => {
    const fetcher = jest.fn(async () => new Uint8Array([1, 2, 3]));
    const result = await loadChangeBlock<string, Uint8Array>(
      OTHER_CID,
      new Set([REAL_CID]),
      parseAsString,
      fetcher as unknown as (c: string) => Promise<Uint8Array>,
    );
    expect(result).toBeUndefined();
    expect(fetcher).not.toHaveBeenCalled();
  });

  test('returns undefined when _hashes is empty (no change has ever been seen)', async () => {
    const fetcher = jest.fn(async () => new Uint8Array([1]));
    const result = await loadChangeBlock<string, Uint8Array>(
      REAL_CID,
      new Set(),
      parseAsString,
      fetcher as unknown as (c: string) => Promise<Uint8Array>,
    );
    expect(result).toBeUndefined();
    expect(fetcher).not.toHaveBeenCalled();
  });

  test('throws on malformed CID with a descriptive error', async () => {
    await expect(
      loadChangeBlock<string, Uint8Array>(
        'malformed',
        new Set(['malformed']),
        parseThrowing,
        async () => new Uint8Array([1]),
      ),
    ).rejects.toThrow(/Invalid CID/);
  });

  test('throws a useful message when parseCID rejects with a non-Error value', async () => {
    // parseCID is permitted to throw any value. Verify the helper coerces
    // non-Error throws into a useful string instead of "Invalid CID 'x': undefined".
    await expect(
      loadChangeBlock<string, Uint8Array>(
        'malformed',
        new Set(['malformed']),
        () => {
          throw 'string-thrown-value';
        },
        async () => new Uint8Array([1]),
      ),
    ).rejects.toThrow("Invalid CID 'malformed': string-thrown-value");
  });

  test('returns the fetched payload on success', async () => {
    const payload = new Uint8Array([0xaa, 0xbb]);
    const result = await loadChangeBlock<string, Uint8Array>(
      REAL_CID,
      new Set([REAL_CID]),
      parseAsString,
      async () => payload,
    );
    expect(result).toEqual(payload);
  });

  test('returns undefined when the fetcher throws ERR_NOT_FOUND', async () => {
    const notFound = Object.assign(new Error('block not found'), {
      code: 'ERR_NOT_FOUND',
      name: 'NotFoundError',
    });
    const onMissing = jest.fn();
    const result = await loadChangeBlock<string, Uint8Array>(
      REAL_CID,
      new Set([REAL_CID]),
      parseAsString,
      async () => { throw notFound; },
      onMissing,
    );
    expect(result).toBeUndefined();
    // onMissing callback is invoked exactly once with the same cid + error.
    expect(onMissing).toHaveBeenCalledTimes(1);
    expect(onMissing).toHaveBeenCalledWith(REAL_CID, notFound);
  });

  test('returns undefined when the fetcher throws a NotFoundError (name-only match)', async () => {
    // Some backing stores re-throw a generic Error with name set but no code.
    const notFound = Object.assign(new Error('block not found'), {
      name: 'NotFoundError',
    });
    const result = await loadChangeBlock<string, Uint8Array>(
      REAL_CID,
      new Set([REAL_CID]),
      parseAsString,
      async () => { throw notFound; },
    );
    expect(result).toBeUndefined();
  });

  test('does NOT log on missing block (callers opt in via onMissing)', async () => {
    // The helper used to console.warn on every missing block; verify that
    // behavior is gone so probing for missing history blocks does not spam
    // logs.
    const notFound = Object.assign(new Error('block not found'), {
      code: 'ERR_NOT_FOUND',
    });
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await loadChangeBlock<string, Uint8Array>(
        REAL_CID,
        new Set([REAL_CID]),
        parseAsString,
        async () => { throw notFound; },
      );
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });

  test('rethrows decrypt/deserialize failures (does NOT mask as missing)', async () => {
    // The fetcher throws a regular error from _getBlock's decrypt path. This
    // should NOT be mapped to undefined; callers need to see data-integrity
    // failures.
    await expect(
      loadChangeBlock<string, Uint8Array>(
        REAL_CID,
        new Set([REAL_CID]),
        parseAsString,
        async () => { throw new Error('Failed to decrypt block (CID: ...)'); },
      ),
    ).rejects.toThrow(/Failed to decrypt block/);
  });

  test('rethrows other non-not-found errors (e.g. IO failure)', async () => {
    await expect(
      loadChangeBlock<string, Uint8Array>(
        REAL_CID,
        new Set([REAL_CID]),
        parseAsString,
        async () => { throw new Error('I/O failure'); },
      ),
    ).rejects.toThrow(/I\/O failure/);
  });
});

describe('isBlockNotFoundError', () => {
  test('matches the interface-store NotFoundError code', () => {
    expect(isBlockNotFoundError(
      Object.assign(new Error(), { code: 'ERR_NOT_FOUND' }),
    )).toBe(true);
  });

  test('matches by name when code is missing', () => {
    expect(isBlockNotFoundError(
      Object.assign(new Error(), { name: 'NotFoundError' }),
    )).toBe(true);
  });

  test('does not match unrelated errors', () => {
    expect(isBlockNotFoundError(new Error('decrypt failed'))).toBe(false);
    expect(isBlockNotFoundError(
      Object.assign(new Error(), { code: 'ERR_OTHER' }),
    )).toBe(false);
  });

  test('handles non-error values safely', () => {
    expect(isBlockNotFoundError(undefined)).toBe(false);
    expect(isBlockNotFoundError(null)).toBe(false);
    expect(isBlockNotFoundError('string-error')).toBe(false);
    expect(isBlockNotFoundError(42)).toBe(false);
  });
});
