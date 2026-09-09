import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  deserializeLoadSecurityCommitmentsFromWire,
  serializeLoadSecurityCommitmentsForWire,
} from './load-security-state-wire.js';
import type { LoadSecurityCommitments } from './load-security-state.js';

const commitments = (): LoadSecurityCommitments => ({
  version: 1,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'group',
  epoch: (1n << 63n) + 7n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});

describe('load security state wire codec', () => {
  test('round-trips bigint and clones binary fields', () => {
    const original = commitments();
    const wire = serializeLoadSecurityCommitmentsForWire(original);
    const decoded = deserializeLoadSecurityCommitmentsFromWire(wire);
    expect(decoded).toEqual(original);
    expect(decoded.controlHead).not.toBe(original.controlHead);
    decoded.controlHead[0] = 99;
    expect(original.controlHead[0]).toBe(1);
  });

  test('emits exactly the versioned wire keys', () => {
    expect(Object.keys(serializeLoadSecurityCommitmentsForWire(commitments())).sort()).toEqual(
      [
        'confirmedTranscriptHash',
        'controlHead',
        'epoch',
        'groupId',
        'treeHash',
        'version',
      ],
    );
  });

  test.each([
    '-1',
    '+1',
    '01',
    '18446744073709551616',
    '9'.repeat(21),
    1,
  ])('rejects non-canonical/out-of-range epoch %p', (epoch) => {
    const wire = { ...serializeLoadSecurityCommitmentsForWire(commitments()), epoch };
    expect(() => deserializeLoadSecurityCommitmentsFromWire(wire)).toThrow(/epoch/);
  });

  test('rejects unknown and missing fields', () => {
    const wire = serializeLoadSecurityCommitmentsForWire(commitments());
    expect(() =>
      deserializeLoadSecurityCommitmentsFromWire({ ...wire, extra: true }),
    ).toThrow(/exactly/);
    const { treeHash: _treeHash, ...missing } = wire;
    expect(() => deserializeLoadSecurityCommitmentsFromWire(missing)).toThrow(/exactly/);
  });

  test.each([new Date(), [], /not-an-object/])(
    'rejects non-plain object %p',
    (value) => {
      expect(() => deserializeLoadSecurityCommitmentsFromWire(value)).toThrow(
        /plain object/,
      );
    },
  );

  test.each(['', 'AQ==', Base64.fromUint8Array(new Uint8Array(31)), '****']) (
    'rejects malformed/wrong-width base64 %p',
    (controlHead) => {
      const wire = {
        ...serializeLoadSecurityCommitmentsForWire(commitments()),
        controlHead,
      };
      expect(() => deserializeLoadSecurityCommitmentsFromWire(wire)).toThrow(
        /controlHead/,
      );
    },
  );
});
