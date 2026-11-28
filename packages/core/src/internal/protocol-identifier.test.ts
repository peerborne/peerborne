import { describe, expect, test } from '@jest/globals';
import {
  isCanonicalIdentifier,
  isCanonicalProtocol,
  sameProtocol,
  snapshotCanonicalProtocol,
} from './protocol-identifier.js';

describe('canonical identifiers', () => {
  test.each(['a', 'A0', 'peerborne/mls-1.0', '0_x-y', 'a'.repeat(128)])(
    'accepts %p',
    (value) => {
      expect(isCanonicalIdentifier(value)).toBe(true);
    },
  );

  test.each(['', '-a', '.a', 'a b', 'a\n', 'é', 'a'.repeat(129), 1, null])(
    'rejects %p',
    (value) => {
      expect(isCanonicalIdentifier(value)).toBe(false);
    },
  );

  test('ignores a replaced RegExp.prototype.exec', () => {
    const original = RegExp.prototype.exec;
    RegExp.prototype.exec = () => [] as unknown as RegExpExecArray;
    try {
      expect(isCanonicalIdentifier('not canonical')).toBe(false);
      expect(isCanonicalIdentifier('canonical')).toBe(true);
    } finally {
      RegExp.prototype.exec = original;
    }
  });

  test('protocol versions are unsigned 16-bit integers', () => {
    expect(isCanonicalProtocol('p', 0)).toBe(true);
    expect(isCanonicalProtocol('p', 0xffff)).toBe(true);
    for (const version of [-1, 0x10000, 1.5, Number.NaN, '1', 1n]) {
      expect(isCanonicalProtocol('p', version)).toBe(false);
    }
    expect(isCanonicalProtocol('-p', 1)).toBe(false);
  });
});

describe('protocol objects', () => {
  test('compare by ID and version', () => {
    expect(sameProtocol({ id: 'p', version: 1 }, { id: 'p', version: 1 })).toBe(
      true,
    );
    expect(sameProtocol({ id: 'p', version: 1 }, { id: 'p', version: 2 })).toBe(
      false,
    );
  });

  test('snapshot only exact canonical protocol records', () => {
    expect(
      snapshotCanonicalProtocol({ id: 'p', version: 3 }, 'protocol'),
    ).toEqual({ id: 'p', version: 3 });
    expect(() =>
      snapshotCanonicalProtocol({ id: 'p', version: 3, extra: 1 }, 'protocol'),
    ).toThrow('protocol has unexpected or missing fields');
    expect(() =>
      snapshotCanonicalProtocol({ id: ' p', version: 3 }, 'protocol'),
    ).toThrow('protocol is not a canonical protocol identifier');
  });
});
