import { describe, expect, jest, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  INITIAL_LOAD_CHALLENGE_LENGTH,
  cloneInitialLoadChallenge,
  createInitialLoadChallenge,
  deserializeInitialLoadChallengeFromWire,
  initialLoadChallengeEquals,
  initialLoadRequestSignaturePayload,
  serializeInitialLoadChallengeForWire,
  validateInitialLoadChallenge,
} from './initial-load-challenge.js';

describe('V4 initial-load challenge', () => {
  test('creates one fixed-width random challenge', () => {
    const getRandomValues = jest.spyOn(crypto, 'getRandomValues');
    const challenge = createInitialLoadChallenge();
    expect(challenge).toHaveLength(INITIAL_LOAD_CHALLENGE_LENGTH);
    expect(getRandomValues).toHaveBeenCalledTimes(1);
    getRandomValues.mockRestore();
  });

  test('clones and compares all challenge bytes', () => {
    const challenge = new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH).fill(1);
    const cloned = cloneInitialLoadChallenge(challenge);
    expect(cloned).not.toBe(challenge);
    expect(initialLoadChallengeEquals(challenge, cloned)).toBe(true);
    cloned[31] ^= 1;
    expect(initialLoadChallengeEquals(challenge, cloned)).toBe(false);
    expect(initialLoadChallengeEquals(challenge, undefined)).toBe(false);
  });

  test('accepts and snapshots genuine cross-realm challenge bytes', () => {
    const challenge = runInNewContext(
      'new Uint8Array(32).fill(9)',
    ) as Uint8Array;
    expect(challenge instanceof Uint8Array).toBe(false);
    Object.defineProperties(challenge, {
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

    expect(() => validateInitialLoadChallenge(challenge)).not.toThrow();
    const cloned = cloneInitialLoadChallenge(challenge);
    expect(cloned).toEqual(new Uint8Array(32).fill(9));
    expect(cloned instanceof Uint8Array).toBe(true);
    expect(initialLoadChallengeEquals(challenge, cloned)).toBe(true);
    expect(serializeInitialLoadChallengeForWire(challenge)).toBe(
      serializeInitialLoadChallengeForWire(cloned),
    );
    expect(initialLoadRequestSignaturePayload('/doc', challenge)).toEqual(
      initialLoadRequestSignaturePayload('/doc', cloned),
    );
  });

  test('rejects SharedArrayBuffer backing and Uint8Array lookalikes', () => {
    const lookalike = Object.create(Uint8Array.prototype) as Uint8Array;
    Object.defineProperties(lookalike, {
      byteLength: { value: 32 },
      buffer: { value: new ArrayBuffer(32) },
      [Symbol.toStringTag]: { value: 'Uint8Array' },
    });
    const invalidValues = [lookalike];
    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = runInNewContext(
        'new Uint8Array(new SharedArrayBuffer(32)).fill(4)',
      ) as Uint8Array;
      Object.defineProperty(shared, 'buffer', {
        value: new ArrayBuffer(32),
      });
      invalidValues.push(shared);
    }

    for (const invalid of invalidValues) {
      expect(() => validateInitialLoadChallenge(invalid)).toThrow(/unshared/);
      expect(() => cloneInitialLoadChallenge(invalid)).toThrow(/unshared/);
      expect(() => serializeInitialLoadChallengeForWire(invalid)).toThrow(
        /unshared/,
      );
      expect(() =>
        initialLoadRequestSignaturePayload('/doc', invalid),
      ).toThrow(/unshared/);
      expect(
        initialLoadChallengeEquals(new Uint8Array(32).fill(4), invalid),
      ).toBe(false);
    }
  });

  test('round-trips only canonical fixed-width base64', () => {
    const challenge = new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH).fill(7);
    const wire = serializeInitialLoadChallengeForWire(challenge);
    expect(deserializeInitialLoadChallengeFromWire(wire)).toEqual(challenge);
    expect(() => deserializeInitialLoadChallengeFromWire('AQ==')).toThrow(
      /32-byte/,
    );
    expect(() =>
      deserializeInitialLoadChallengeFromWire(wire.replace(/=$/, '')),
    ).toThrow(/canonical base64|32-byte/);
  });

  test('signature payload binds document, nonce, boundaries, and rejects lone surrogates', () => {
    const challenge = new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH).fill(1);
    expect(initialLoadRequestSignaturePayload('/a', challenge)).not.toEqual(
      initialLoadRequestSignaturePayload('/b', challenge),
    );
    const changed = new Uint8Array(challenge);
    changed[0] ^= 1;
    expect(initialLoadRequestSignaturePayload('/a', challenge)).not.toEqual(
      initialLoadRequestSignaturePayload('/a', changed),
    );
    expect(() =>
      initialLoadRequestSignaturePayload('\ud800', challenge),
    ).toThrow(/well-formed UTF-16/);
  });
});
