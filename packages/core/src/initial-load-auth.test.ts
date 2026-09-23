import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES,
  identifyInitialLoadSigner,
  verifyInitialLoadAuthentication,
} from './initial-load-auth.js';
import type { InitialLoadAuthenticationOptions } from './initial-load-auth.js';
import { MAX_INITIAL_LOAD_BOOTSTRAP_WRITER_KEYS } from './initial-load-trust.js';

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

  test('rejects empty signed bytes before verification', async () => {
    let verifierCalls = 0;
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload: new Uint8Array(),
        signature,
        existingWriterKeys: ['writer'],
        trustedBootstrapWriterKeys: [],
        verify: async () => {
          verifierCalls++;
          return true;
        },
      }),
    ).resolves.toBe(false);
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature: new Uint8Array(),
        existingWriterKeys: ['writer'],
        trustedBootstrapWriterKeys: [],
        verify: async () => {
          verifierCalls++;
          return true;
        },
      }),
    ).resolves.toBe(false);
    expect(verifierCalls).toBe(0);
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

  test('accepts more existing writers than the bootstrap cap', async () => {
    const writers = Array.from(
      { length: MAX_INITIAL_LOAD_BOOTSTRAP_WRITER_KEYS + 1 },
      (_, index) => `writer-${index}`,
    );
    const lastWriter = writers[writers.length - 1];
    const options = {
      strict: true,
      signingEnabled: true,
      payload,
      signature,
      existingWriterKeys: writers,
      trustedBootstrapWriterKeys: [],
      verify: async (_raw: Uint8Array, key: string) => key === lastWriter,
    };
    await expect(verifyInitialLoadAuthentication(options)).resolves.toBe(true);
    await expect(identifyInitialLoadSigner(options)).resolves.toEqual({
      publicKey: lastWriter,
      keyIndex: writers.length - 1,
    });
  });

  test('rejects an over-limit bootstrap key snapshot before verification', async () => {
    let verifierCalls = 0;
    await expect(
      identifyInitialLoadSigner({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: [],
        trustedBootstrapWriterKeys: new Array(
          MAX_INITIAL_LOAD_BOOTSTRAP_WRITER_KEYS + 1,
        ).fill('writer'),
        verify: async () => {
          verifierCalls++;
          return true;
        },
      }),
    ).rejects.toThrow(/exceeds/);
    expect(verifierCalls).toBe(0);
  });

  test('captures the verifier and gives each key isolated signed bytes', async () => {
    const mutablePayload = new Uint8Array([1, 2, 3]);
    const mutableSignature = new Uint8Array([4, 5, 6]);
    const seen: Array<{
      key: string;
      payload: number[];
      signature: number[];
    }> = [];
    let options: InitialLoadAuthenticationOptions<string>;
    const originalVerify = async (
      receivedPayload: Uint8Array,
      key: string,
      receivedSignature: Uint8Array,
    ): Promise<boolean> => {
      seen.push({
        key,
        payload: Array.from(receivedPayload),
        signature: Array.from(receivedSignature),
      });
      receivedPayload.fill(0xaa);
      receivedSignature.fill(0xbb);
      if (key === 'writer-a') {
        mutablePayload.fill(0xcc);
        mutableSignature.fill(0xdd);
        options.verify = async () => false;
      }
      return key === 'writer-b';
    };
    options = {
      strict: true,
      signingEnabled: true,
      payload: mutablePayload,
      signature: mutableSignature,
      existingWriterKeys: ['writer-a', 'writer-b'],
      trustedBootstrapWriterKeys: [],
      verify: originalVerify,
    };

    await expect(identifyInitialLoadSigner(options)).resolves.toEqual({
      publicKey: 'writer-b',
      keyIndex: 1,
    });
    expect(seen).toEqual([
      { key: 'writer-a', payload: [1, 2, 3], signature: [4, 5, 6] },
      { key: 'writer-b', payload: [1, 2, 3], signature: [4, 5, 6] },
    ]);
  });

  test('accepts genuine cross-realm payload and signature bytes', async () => {
    const crossRealmPayload = runInNewContext(
      'new Uint8Array([1, 2, 3])',
    ) as Uint8Array;
    const crossRealmSignature = runInNewContext(
      'new Uint8Array([4, 5, 6])',
    ) as Uint8Array;
    expect(crossRealmPayload instanceof Uint8Array).toBe(false);
    expect(crossRealmSignature instanceof Uint8Array).toBe(false);

    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload: crossRealmPayload,
        signature: crossRealmSignature,
        existingWriterKeys: ['writer'],
        trustedBootstrapWriterKeys: [],
        verify: async (receivedPayload, _key, receivedSignature) => {
          expect(receivedPayload).not.toBe(crossRealmPayload);
          expect(receivedSignature).not.toBe(crossRealmSignature);
          expect(receivedPayload).toEqual(new Uint8Array([1, 2, 3]));
          expect(receivedSignature).toEqual(new Uint8Array([4, 5, 6]));
          return true;
        },
      }),
    ).resolves.toBe(true);
  });

  test.each(['payload', 'signature'] as const)(
    'rejects SharedArrayBuffer-backed %s bytes before verification',
    async (field) => {
      if (typeof SharedArrayBuffer === 'undefined') return;
      let verifierCalls = 0;
      const shared = new Uint8Array(new SharedArrayBuffer(3));
      const options = {
        strict: true,
        signingEnabled: true,
        payload: field === 'payload' ? shared : payload,
        signature: field === 'signature' ? shared : signature,
        existingWriterKeys: ['writer'],
        trustedBootstrapWriterKeys: [],
        verify: async () => {
          verifierCalls++;
          return true;
        },
      };

      await expect(verifyInitialLoadAuthentication(options)).resolves.toBe(
        false,
      );
      expect(verifierCalls).toBe(0);
    },
  );

  test('rejects an oversized signature before verification', async () => {
    let verifierCalls = 0;
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature: new Uint8Array(
          MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES + 1,
        ),
        existingWriterKeys: ['writer'],
        trustedBootstrapWriterKeys: [],
        verify: async () => {
          verifierCalls++;
          return true;
        },
      }),
    ).resolves.toBe(false);
    expect(verifierCalls).toBe(0);
  });

  test('a key listed twice is not treated as ambiguous', async () => {
    await expect(
      identifyInitialLoadSigner({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['writer-a', 'writer-b', 'writer-a'],
        trustedBootstrapWriterKeys: [],
        verify: async (_raw, key) => key === 'writer-a',
      }),
    ).resolves.toEqual({ publicKey: 'writer-a', keyIndex: 0 });
  });

  test('stops verifying after the first trusted key matches', async () => {
    const seen: string[] = [];
    await expect(
      verifyInitialLoadAuthentication({
        strict: true,
        signingEnabled: true,
        payload,
        signature,
        existingWriterKeys: ['writer-a', 'writer-b', 'writer-c'],
        trustedBootstrapWriterKeys: [],
        verify: async (_raw, key) => {
          seen.push(key);
          return key !== 'writer-c';
        },
      }),
    ).resolves.toBe(true);
    expect(seen).toEqual(['writer-a']);
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
