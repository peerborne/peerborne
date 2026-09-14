import { describe, expect, test } from '@jest/globals';
import {
  identifyInitialLoadSigner,
  verifyInitialLoadAuthentication,
} from './initial-load-auth.js';
import { MAX_INITIAL_LOAD_SIGNER_AUTHORITIES } from './initial-load-trust.js';

const payload = new Uint8Array([1]);
const signature = new Uint8Array([2]);

describe('verifyInitialLoadAuthentication', () => {
  test('strict first load requires a pinned bootstrap writer', async () => {
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: [],
        trustedBootstrapWriterKeys: [],
        verify: async () => true,
      }),
    ).resolves.toBe(false);
  });

  test('uses existing writers in preference to bootstrap keys', async () => {
    const seen: string[] = [];
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['existing'],
        trustedBootstrapWriterKeys: ['bootstrap'],
        verify: async (_raw, key) => {
          seen.push(key);
          return key === 'existing';
        },
      }),
    ).resolves.toBe(true);
    expect(seen).toEqual(['existing']);
  });

  test('accepts any valid pinned writer even when another verifier throws', async () => {
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: [],
        trustedBootstrapWriterKeys: ['malformed', 'valid'],
        verify: (_raw, key) => {
          if (key === 'malformed') throw new Error('bad key');
          return Promise.resolve(true);
        },
      }),
    ).resolves.toBe(true);
  });

  test.each([
    [true, false],
    [false, true],
  ])(
    'signing disabled with strict=%s returns %s',
    async (strict, expected) => {
      await expect(
        verifyInitialLoadAuthentication({
          strict,
          signingEnabled: false,
          payload,
          existingWriterKeys: [],
          trustedBootstrapWriterKeys: [],
          verify: async () => true,
        }),
      ).resolves.toBe(expected);
    },
  );

  test('legacy first load retains key-possession fallback', async () => {
    await expect(
      verifyInitialLoadAuthentication({
        strict: false,
        signingEnabled: true,
        payload,
        existingWriterKeys: [],
        trustedBootstrapWriterKeys: [],
        verify: async () => false,
      }),
    ).resolves.toBe(true);
  });

  test('rejects a missing signature when trust keys exist', async () => {
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        existingWriterKeys: [],
        trustedBootstrapWriterKeys: ['writer'],
        verify: async () => true,
      }),
    ).resolves.toBe(false);
  });

  test('does not fall back to bootstrap keys once an existing ACL is trusted', async () => {
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['existing'],
        trustedBootstrapWriterKeys: ['bootstrap'],
        verify: async (_raw, key) => key === 'bootstrap',
      }),
    ).resolves.toBe(false);
  });

  test('non-strict mode still verifies when an explicit trust set exists', async () => {
    await expect(
      verifyInitialLoadAuthentication({
        strict: false,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['writer'],
        trustedBootstrapWriterKeys: [],
        verify: async () => false,
      }),
    ).resolves.toBe(false);
  });

  test('identifies the exact trusted authority that signed the envelope', async () => {
    await expect(
      identifyInitialLoadSigner({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['writer-a', 'writer-b'],
        trustedBootstrapWriterKeys: [],
        verify: async (_raw, key) => key === 'writer-b',
      }),
    ).resolves.toEqual({ publicKey: 'writer-b', keyIndex: 1 });
  });

  test('pins signer attribution to the trust-key snapshot used for verification', async () => {
    const writerKeys = ['writer-a', 'writer-b'];
    await expect(
      identifyInitialLoadSigner({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: writerKeys,
        trustedBootstrapWriterKeys: [],
        verify: async (_raw, key) => {
          if (key === 'writer-b') {
            writerKeys.splice(0, writerKeys.length, 'attacker-a', 'attacker-b');
          }
          return key === 'writer-b';
        },
      }),
    ).resolves.toEqual({ publicKey: 'writer-b', keyIndex: 1 });
    expect(writerKeys).toEqual(['attacker-a', 'attacker-b']);
  });

  test('rejects an over-limit trust-key snapshot before verification', async () => {
    let verifierCalls = 0;
    await expect(
      identifyInitialLoadSigner({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: new Array(
          MAX_INITIAL_LOAD_SIGNER_AUTHORITIES + 1,
        ).fill('writer'),
        trustedBootstrapWriterKeys: [],
        verify: async () => {
          verifierCalls++;
          return true;
        },
      }),
    ).rejects.toThrow(/exceeds/);
    expect(verifierCalls).toBe(0);
  });

  test('rejects ambiguous signatures instead of assigning a vote arbitrarily', async () => {
    await expect(
      identifyInitialLoadSigner({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['writer-a', 'writer-b'],
        trustedBootstrapWriterKeys: [],
        verify: async () => true,
      }),
    ).resolves.toBeNull();
  });
});
