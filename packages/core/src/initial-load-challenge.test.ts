import { describe, expect, jest, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  INITIAL_LOAD_CHALLENGE_LENGTH,
  MAX_INITIAL_LOAD_RESPONDER_BYTES,
  cloneInitialLoadChallenge,
  createInitialLoadChallenge,
  deserializeInitialLoadChallengeFromWire,
  initialLoadChallengeEquals,
  initialLoadRequestSignaturePayload,
  serializeInitialLoadChallengeForWire,
  validateInitialLoadChallenge,
  validateInitialLoadResponder,
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
    expect(initialLoadRequestSignaturePayload('/doc', challenge, 'peer')).toEqual(
      initialLoadRequestSignaturePayload('/doc', cloned, 'peer'),
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
        initialLoadRequestSignaturePayload('/doc', invalid, 'peer'),
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
    expect(() =>
      deserializeInitialLoadChallengeFromWire('A'.repeat(1024 * 1024)),
    ).toThrow(/fixed-width base64/);
    expect(() =>
      deserializeInitialLoadChallengeFromWire(`${'A'.repeat(43)}!`),
    ).toThrow(/fixed-width base64/);
  });

  test('signature payload binds document, nonce, boundaries, and rejects lone surrogates', () => {
    const challenge = new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH).fill(1);
    expect(initialLoadRequestSignaturePayload('/a', challenge, 'peer')).not.toEqual(
      initialLoadRequestSignaturePayload('/b', challenge, 'peer'),
    );
    const changed = new Uint8Array(challenge);
    changed[0] ^= 1;
    expect(initialLoadRequestSignaturePayload('/a', challenge, 'peer')).not.toEqual(
      initialLoadRequestSignaturePayload('/a', changed, 'peer'),
    );
    expect(() =>
      initialLoadRequestSignaturePayload('\ud800', challenge, 'peer'),
    ).toThrow(/well-formed UTF-16/);
  });

  test('signature payload binds the addressed responder with a length prefix', () => {
    const challenge = new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH).fill(1);
    const relay = initialLoadRequestSignaturePayload('/a', challenge, 'relay');
    expect(relay).not.toEqual(
      initialLoadRequestSignaturePayload('/a', challenge, 'writer'),
    );
    expect(relay).not.toEqual(
      initialLoadRequestSignaturePayload('/a', challenge, 'relay2'),
    );
    expect(relay.subarray(-9)).toEqual(
      new Uint8Array([0, 0, 0, 5, ...new TextEncoder().encode('relay')]),
    );
    const longest = 'p'.repeat(MAX_INITIAL_LOAD_RESPONDER_BYTES);
    expect(() =>
      initialLoadRequestSignaturePayload('/a', challenge, longest),
    ).not.toThrow();
    expect(() => validateInitialLoadResponder(longest)).not.toThrow();
  });

  test.each([
    ['a missing responder', undefined, /non-empty string/],
    ['an empty responder', '', /non-empty string/],
    ['a non-string responder', 7, /non-empty string/],
    ['a boxed responder', new String('peer'), /non-empty string/],
    [
      'an oversized responder',
      'p'.repeat(MAX_INITIAL_LOAD_RESPONDER_BYTES + 1),
      /exceeds 128 UTF-8 bytes/,
    ],
    ['a wide oversized responder', 'あ'.repeat(43), /exceeds 128 UTF-8 bytes/],
    ['a lone surrogate responder', '\udc00', /well-formed UTF-16/],
  ])('rejects %s', (_label, responder, error) => {
    const challenge = new Uint8Array(INITIAL_LOAD_CHALLENGE_LENGTH).fill(1);
    expect(() => validateInitialLoadResponder(responder)).toThrow(error);
    expect(() =>
      initialLoadRequestSignaturePayload('/a', challenge, responder as string),
    ).toThrow(error);
  });
});
