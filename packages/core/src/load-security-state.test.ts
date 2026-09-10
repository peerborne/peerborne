import { describe, expect, jest, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  captureTrustedLoadSecurityCommitments,
  cloneLoadSecurityCommitments,
  encodeLoadSecurityState,
  loadSecurityCommitmentsEqual,
  loadSecurityStateHash,
  loadSecurityStateHashToHex,
  LoadSecurityCommitments,
  LoadSecurityState,
  MAX_LOAD_SECURITY_EPOCH,
  TrustedLoadSecurityCommitmentsError,
  validateLoadSecurityCommitments,
  validateLoadSecurityState,
} from './load-security-state.js';

const bytes = (fill: number) => new Uint8Array(32).fill(fill);
const state = (overrides: Partial<LoadSecurityState> = {}): LoadSecurityState => ({
  version: 1,
  documentId: '/docs/example',
  frontier: ['bafy-z', 'bafy-a'],
  controlHead: bytes(1),
  groupId: 'group-1',
  epoch: 42n,
  treeHash: bytes(2),
  confirmedTranscriptHash: bytes(3),
  ...overrides,
});
const commitments = (
  overrides: Partial<LoadSecurityCommitments> = {},
): LoadSecurityCommitments => {
  const { documentId: _documentId, frontier: _frontier, ...value } = state();
  return { ...value, ...overrides };
};

describe('load security state commitment', () => {
  test('is deterministic across frontier ordering', async () => {
    const first = await loadSecurityStateHash(state());
    const second = await loadSecurityStateHash(
      state({ frontier: ['bafy-a', 'bafy-z'] }),
    );
    expect(second).toEqual(first);
    expect(first).toHaveLength(32);
  });

  test.each([
    ['document', state({ documentId: '/docs/other' })],
    ['control head', state({ controlHead: bytes(9) })],
    ['group', state({ groupId: 'group-2' })],
    ['epoch', state({ epoch: 43n })],
    ['tree hash', state({ treeHash: bytes(9) })],
    ['transcript', state({ confirmedTranscriptHash: bytes(9) })],
    ['frontier', state({ frontier: ['bafy-other'] })],
  ])('binds %s', async (_name, changed) => {
    expect(await loadSecurityStateHash(changed)).not.toEqual(
      await loadSecurityStateHash(state()),
    );
  });

  test('uses an unambiguous canonical encoding', () => {
    expect(encodeLoadSecurityState(state({ frontier: ['ab', 'c'] }))).not.toEqual(
      encodeLoadSecurityState(state({ frontier: ['a', 'bc'] })),
    );
  });

  test('rejects duplicate frontier entries', () => {
    expect(() =>
      validateLoadSecurityState(state({ frontier: ['same', 'same'] })),
    ).toThrow(/duplicate/);
  });

  test.each([-1n, MAX_LOAD_SECURITY_EPOCH + 1n])(
    'rejects out-of-range epoch %s',
    (epoch) => {
      expect(() => validateLoadSecurityState(state({ epoch }))).toThrow(/64-bit/);
    },
  );

  test('rejects wrong-width hashes', () => {
    expect(() =>
      validateLoadSecurityState(state({ treeHash: new Uint8Array(31) })),
    ).toThrow(/32-byte/);
  });

  test('accepts genuine cross-realm hashes and snapshots their intrinsic bytes', () => {
    const crossRealmHash = (fill: number) => {
      const value = runInNewContext(
        'new Uint8Array(32).fill(fill)',
        { fill },
      ) as Uint8Array;
      expect(value instanceof Uint8Array).toBe(false);
      Object.defineProperties(value, {
        byteLength: {
          get: () => {
            throw new Error('shadowed byteLength getter must not run');
          },
        },
        buffer: {
          get: () => {
            throw new Error('shadowed buffer getter must not run');
          },
        },
        length: {
          get: () => {
            throw new Error('shadowed length getter must not run');
          },
        },
        [Symbol.toStringTag]: { value: 'Uint16Array' },
      });
      return value;
    };
    const value = commitments({
      controlHead: crossRealmHash(1),
      treeHash: crossRealmHash(2),
      confirmedTranscriptHash: crossRealmHash(3),
    });

    expect(() => validateLoadSecurityCommitments(value)).not.toThrow();
    expect(loadSecurityCommitmentsEqual(value, commitments())).toBe(true);
    const cloned = cloneLoadSecurityCommitments(value);
    expect(cloned).toEqual(commitments());
    expect(cloned.controlHead instanceof Uint8Array).toBe(true);
    expect(
      encodeLoadSecurityState(
        state({
          controlHead: value.controlHead,
          treeHash: value.treeHash,
          confirmedTranscriptHash: value.confirmedTranscriptHash,
        }),
      ),
    ).toEqual(encodeLoadSecurityState(state()));
    expect(loadSecurityStateHashToHex(crossRealmHash(0xab))).toBe(
      'ab'.repeat(32),
    );
  });

  test('rejects SharedArrayBuffer-backed hashes and Uint8Array lookalikes', () => {
    const lookalike = Object.create(Uint8Array.prototype) as Uint8Array;
    Object.defineProperties(lookalike, {
      byteLength: { value: 32 },
      buffer: { value: new ArrayBuffer(32) },
      [Symbol.toStringTag]: { value: 'Uint8Array' },
    });
    const invalidValues = [lookalike];
    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = runInNewContext(
        'new Uint8Array(new SharedArrayBuffer(32))',
      ) as Uint8Array;
      Object.defineProperty(shared, 'buffer', {
        value: new ArrayBuffer(32),
      });
      invalidValues.push(shared);
    }

    for (const invalid of invalidValues) {
      const value = commitments({ treeHash: invalid });
      expect(() => validateLoadSecurityCommitments(value)).toThrow(/unshared/);
      expect(() => cloneLoadSecurityCommitments(value)).toThrow(/unshared/);
      expect(loadSecurityCommitmentsEqual(commitments(), value)).toBe(false);
      expect(() => loadSecurityStateHashToHex(invalid)).toThrow(/unshared/);
    }
  });

  test.each([
    state({ documentId: '/doc/\ud800' }),
    state({ groupId: 'group-\udfff' }),
    state({ frontier: ['cid-\ud800'] }),
  ])('rejects non-well-formed UTF-16 before canonical encoding', (input) => {
    expect(() => encodeLoadSecurityState(input)).toThrow(/well-formed UTF-16/);
  });

  test('renders a fixed-width lowercase hex digest', async () => {
    expect(loadSecurityStateHashToHex(await loadSecurityStateHash(state()))).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  test('matches only the complete locally trusted commitment tuple', () => {
    const trusted = commitments();
    expect(loadSecurityCommitmentsEqual(trusted, commitments())).toBe(true);
    for (const candidate of [
      commitments({ controlHead: bytes(9) }),
      commitments({ groupId: 'other-group' }),
      commitments({ epoch: trusted.epoch - 1n }),
      commitments({ treeHash: bytes(9) }),
      commitments({ confirmedTranscriptHash: bytes(9) }),
    ]) {
      expect(loadSecurityCommitmentsEqual(trusted, candidate)).toBe(false);
    }
    expect(loadSecurityCommitmentsEqual(trusted, undefined)).toBe(false);
    expect(
      loadSecurityCommitmentsEqual(
        trusted,
        commitments({ treeHash: new Uint8Array(31) }),
      ),
    ).toBe(false);
  });

  test('captures one defensive resolver snapshot for the entire load', async () => {
    const mutable = commitments();
    const resolver = jest.fn(async () => mutable);
    const captured = await captureTrustedLoadSecurityCommitments(
      '/docs/example',
      resolver,
    );

    mutable.groupId = 'mutated-group';
    mutable.epoch = 999n;
    mutable.controlHead.fill(8);
    mutable.treeHash.fill(8);
    mutable.confirmedTranscriptHash.fill(8);

    expect(resolver).toHaveBeenCalledTimes(1);
    expect(resolver).toHaveBeenCalledWith('/docs/example');
    expect(captured).toEqual(commitments());
  });

  test('rejects accessor-backed resolver tuples without invoking getters', async () => {
    const accessor = commitments();
    let getterCalls = 0;
    Object.defineProperty(accessor, 'groupId', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'group-1';
      },
    });

    await expect(
      captureTrustedLoadSecurityCommitments('/docs/example', async () =>
        accessor,
      ),
    ).rejects.toThrow(/invalid tuple/);
    expect(getterCalls).toBe(0);
  });

  test('captures each resolver tuple descriptor once without property reads', async () => {
    const mutable = commitments();
    const descriptorReads = new Map<PropertyKey, number>();
    let propertyReads = 0;
    let groupReads = 0;
    const proxied = new Proxy(mutable, {
      get(target, property, receiver) {
        if (property === 'then') return undefined;
        propertyReads += 1;
        if (property === 'groupId') {
          groupReads += 1;
          return groupReads === 1 ? 'group-1' : 'substituted-group';
        }
        return Reflect.get(target, property, receiver);
      },
      getOwnPropertyDescriptor(target, property) {
        descriptorReads.set(
          property,
          (descriptorReads.get(property) ?? 0) + 1,
        );
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    const captured = await captureTrustedLoadSecurityCommitments(
      '/docs/example',
      async () => proxied,
    );
    expect(propertyReads).toBe(0);
    for (const field of Reflect.ownKeys(mutable)) {
      expect(descriptorReads.get(field)).toBe(1);
    }

    mutable.groupId = 'mutated-group';
    mutable.epoch = 999n;
    mutable.controlHead.fill(8);
    mutable.treeHash.fill(8);
    mutable.confirmedTranscriptHash.fill(8);
    expect(captured).toEqual(commitments());
  });

  test('ignores unknown resolver fields without invoking them', async () => {
    const extended = { ...commitments(), extra: true } as Record<
      PropertyKey,
      unknown
    >;
    let unknownGetterCalls = 0;
    Object.defineProperties(extended, {
      hidden: { value: true },
      accessor: {
        enumerable: true,
        get() {
          unknownGetterCalls += 1;
          return true;
        },
      },
    });
    Object.defineProperty(extended, Symbol('unknown'), {
      get() {
        unknownGetterCalls += 1;
        return true;
      },
    });
    const proxied = new Proxy(extended, {
      ownKeys() {
        throw new Error('unknown fields must not be enumerated');
      },
    });

    const captured = await captureTrustedLoadSecurityCommitments(
      '/docs/example',
      async () => proxied,
    );
    expect(captured).toEqual(commitments());
    expect(Reflect.ownKeys(captured)).toHaveLength(6);
    expect(unknownGetterCalls).toBe(0);
  });

  test('fails closed when the local resolver is missing, undefined, invalid, or rejects', async () => {
    await expect(
      captureTrustedLoadSecurityCommitments('/doc', undefined),
    ).rejects.toBeInstanceOf(TrustedLoadSecurityCommitmentsError);

    const undefinedResolver = jest.fn(async () => undefined);
    await expect(
      captureTrustedLoadSecurityCommitments('/doc', undefinedResolver),
    ).rejects.toThrow(/returned undefined/);
    expect(undefinedResolver).toHaveBeenCalledTimes(1);

    const invalidResolver = jest.fn(async () => ({ epoch: 1n }));
    await expect(
      captureTrustedLoadSecurityCommitments('/doc', invalidResolver),
    ).rejects.toThrow(/invalid tuple/);
    expect(invalidResolver).toHaveBeenCalledTimes(1);

    const rejectedResolver = jest.fn(async () => {
      throw new Error('trust store offline');
    });
    await expect(
      captureTrustedLoadSecurityCommitments('/doc', rejectedResolver),
    ).rejects.toThrow(/failed/);
    expect(rejectedResolver).toHaveBeenCalledTimes(1);
  });
});
