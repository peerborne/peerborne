import { describe, expect, test } from '@jest/globals';
import type { CompactionConfig } from './compaction-config.js';
import {
  defaultCompactionConfig,
  mergeCompactionConfig,
} from './compaction-config.js';

describe('mergeCompactionConfig', () => {
  test('keeps automatic compaction disabled by default', () => {
    expect(defaultCompactionConfig.enabled).toBe(false);
    expect(mergeCompactionConfig().enabled).toBe(false);
  });

  test('returns a copy of the default values', () => {
    const config = mergeCompactionConfig();

    expect(config).toEqual(defaultCompactionConfig);
  });

  test('returns a fresh config object', () => {
    expect(mergeCompactionConfig()).not.toBe(defaultCompactionConfig);
    expect(mergeCompactionConfig()).not.toBe(mergeCompactionConfig());
  });

  test('treats null overrides as no overrides', () => {
    expect(mergeCompactionConfig(null)).toEqual(defaultCompactionConfig);
  });

  test('treats nullish fields as no override', () => {
    const overrides = {
      enabled: undefined,
      snapshotInterval: null,
    } as unknown as Partial<CompactionConfig>;

    expect(mergeCompactionConfig(overrides)).toEqual(defaultCompactionConfig);
  });

  test('applies partial overrides while preserving unspecified defaults', () => {
    const partial: Partial<CompactionConfig> = {
      enabled: true,
      snapshotInterval: 200,
      minChangesBeforeSnapshot: 50,
    };
    const merged = mergeCompactionConfig(partial);

    expect(merged).toEqual({
      ...defaultCompactionConfig,
      ...partial,
    });
  });

  test('applies a complete set of overrides', () => {
    const overrides: CompactionConfig = {
      enabled: true,
      snapshotInterval: 100,
      minChangesBeforeSnapshot: 25,
      pruneAfterSnapshot: false,
      gcAfterPrune: true,
      keepRecentNodes: 10,
    };

    expect(mergeCompactionConfig(overrides)).toEqual(overrides);
  });
});
