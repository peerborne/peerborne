import { describe, expect, jest, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  InitialLoadAuthenticationBudget,
  MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS,
  MAX_INITIAL_LOAD_AUTHENTICATION_PAYLOAD_BYTES,
  MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES,
  MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES,
  identifyInitialLoadSigner,
  verifyInitialLoadAuthentication,
  type InitialLoadAuthenticationOptions,
} from './initial-load-auth.js';
import {
  createInitialLoadSignerLookup,
  MAX_INITIAL_LOAD_SIGNER_AUTHORITY_ID_BYTES,
} from './initial-load-trust.js';

const payload = new Uint8Array([1, 2, 3]);
const signature = new Uint8Array([4, 5, 6]);
const authorities = [
  { authorityId: 'authority-a', publicKey: 'writer-a' },
  { authorityId: 'authority-b', publicKey: 'writer-b' },
];
function options(
  changes: Partial<InitialLoadAuthenticationOptions<string>> = {},
): InitialLoadAuthenticationOptions<string> {
  return {
    payload,
    signature,
    signerAuthority: 'authority-b',
    trustedSigners: createInitialLoadSignerLookup(authorities),
    budget: new InitialLoadAuthenticationBudget(),
    verify: async (_payload, key) => key === 'writer-b',
    ...changes,
  };
}

describe('indexed initial-load authentication', () => {
  test.each([-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'invalid budget amounts cannot change its counters (%p)',
    (amount) => {
      const budget = new InitialLoadAuthenticationBudget();
      expect(budget.reserve(amount)).toBe(false);
      expect(budget.reserve(MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES)).toBe(
        true,
      );
      expect(budget.reserve(1)).toBe(false);
    },
  );

  test('verifies only the claimed locally trusted authority', async () => {
    const verify = jest.fn(
      async (_payload: Uint8Array, key: string) => key === 'writer-b',
    );
    await expect(
      identifyInitialLoadSigner(options({ verify })),
    ).resolves.toEqual({
      publicKey: 'writer-b',
      keyIndex: 1,
    });
    expect(verify).toHaveBeenCalledTimes(1);
    expect(verify.mock.calls[0][1]).toBe('writer-b');
  });

  test('one invalid signature costs one verification with thousands of writers', async () => {
    const entries = Array.from({ length: 4096 }, (_, i) => ({
      authorityId: `authority-${i}`,
      publicKey: `writer-${i}`,
    }));
    const verify = jest.fn(async () => false);
    await expect(
      identifyInitialLoadSigner(
        options({
          signerAuthority: 'authority-4095',
          trustedSigners: createInitialLoadSignerLookup(entries),
          verify,
        }),
      ),
    ).resolves.toBeNull();
    expect(verify).toHaveBeenCalledTimes(1);
    expect(verify.mock.calls[0][1]).toBe('writer-4095');
  });

  test('accepts a valid writer beyond the former 256-writer cap', async () => {
    const entries = Array.from({ length: 1024 }, (_, i) => ({
      authorityId: `authority-${i}`,
      publicKey: `writer-${i}`,
    }));
    const verify = jest.fn(
      async (_raw: Uint8Array, key: string) => key === 'writer-1023',
    );
    await expect(
      verifyInitialLoadAuthentication(
        options({
          signerAuthority: 'authority-1023',
          trustedSigners: createInitialLoadSignerLookup(entries),
          verify,
        }),
      ),
    ).resolves.toBe(true);
    expect(verify).toHaveBeenCalledTimes(1);
  });

  test.each([
    undefined,
    '',
    null,
    1,
    {},
    'untrusted',
    '__proto__',
    '\ud800',
    'x'.repeat(MAX_INITIAL_LOAD_SIGNER_AUTHORITY_ID_BYTES + 1),
    'é'.repeat(MAX_INITIAL_LOAD_SIGNER_AUTHORITY_ID_BYTES),
  ])(
    'rejects an absent, malformed or unknown authority before crypto (%p)',
    async (signerAuthority) => {
      const verify = jest.fn(async () => true);
      await expect(
        identifyInitialLoadSigner(
          options({
            signerAuthority: signerAuthority as string,
            verify,
          }),
        ),
      ).resolves.toBeNull();
      expect(verify).not.toHaveBeenCalled();
    },
  );

  test('never falls through to another key when the claimed signer fails', async () => {
    const verify = jest.fn(
      async (_raw: Uint8Array, key: string) => key === 'writer-a',
    );
    await expect(
      verifyInitialLoadAuthentication(options({ verify })),
    ).resolves.toBe(false);
    expect(verify).toHaveBeenCalledTimes(1);
  });

  test('a throwing verifier is one rejected attempt, not a key scan', async () => {
    const verify = jest.fn(async () => {
      throw new Error('invalid signature');
    });
    await expect(
      identifyInitialLoadSigner(options({ verify })),
    ).resolves.toBeNull();
    expect(verify).toHaveBeenCalledTimes(1);
  });

  test('lookup owns its authority entries and does not retain a mutable list', async () => {
    const entries = authorities.map((entry) => ({ ...entry }));
    const trustedSigners = createInitialLoadSignerLookup(entries);
    entries[1].authorityId = 'attacker';
    entries[1].publicKey = 'attacker';
    entries.length = 0;
    await expect(
      identifyInitialLoadSigner(options({ trustedSigners })),
    ).resolves.toEqual({
      publicKey: 'writer-b',
      keyIndex: 1,
    });
    expect(trustedSigners('attacker')).toBeUndefined();
  });

  test('rejects duplicate authority IDs rather than replacing the trusted key', () => {
    expect(() =>
      createInitialLoadSignerLookup([
        { authorityId: 'same', publicKey: 'trusted' },
        { authorityId: 'same', publicKey: 'attacker' },
      ]),
    ).toThrow(/Duplicate/);
  });

  test('verifier arguments are detached and the verifier is captured', async () => {
    const raw = new Uint8Array(payload);
    const sig = new Uint8Array(signature);
    const setting = options({ payload: raw, signature: sig });
    setting.verify = async (data, key, bytes) => {
      expect(data).not.toBe(raw);
      expect(bytes).not.toBe(sig);
      data.fill(9);
      bytes.fill(8);
      setting.verify = async () => false;
      setting.signerAuthority = 'authority-a';
      await Promise.resolve();
      return key === 'writer-b';
    };
    await expect(identifyInitialLoadSigner(setting)).resolves.toEqual({
      publicKey: 'writer-b',
      keyIndex: 1,
    });
    expect(raw).toEqual(payload);
    expect(sig).toEqual(signature);
  });

  test('accepts genuine cross-realm byte arrays', async () => {
    await expect(
      verifyInitialLoadAuthentication(
        options({
          payload: runInNewContext('new Uint8Array([1, 2, 3])'),
          signature: runInNewContext('new Uint8Array([4, 5, 6])'),
        }),
      ),
    ).resolves.toBe(true);
  });

  test.each(['payload', 'signature'] as const)(
    'rejects SharedArrayBuffer-backed %s',
    async (field) => {
      if (typeof SharedArrayBuffer === 'undefined') return;
      const verify = jest.fn(async () => true);
      await expect(
        verifyInitialLoadAuthentication(
          options({
            [field]: new Uint8Array(new SharedArrayBuffer(3)),
            verify,
          }),
        ),
      ).resolves.toBe(false);
      expect(verify).not.toHaveBeenCalled();
    },
  );

  test.each([
    ['payload', new Uint8Array()],
    ['signature', undefined],
    ['signature', new Uint8Array()],
    [
      'signature',
      new Uint8Array(MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES + 1),
    ],
    [
      'payload',
      new Uint8Array(MAX_INITIAL_LOAD_AUTHENTICATION_PAYLOAD_BYTES + 1),
    ],
  ])(
    'rejects malformed or oversized %s before verification',
    async (field, value) => {
      const verify = jest.fn(async () => true);
      await expect(
        identifyInitialLoadSigner(
          options({ [field as string]: value, verify }),
        ),
      ).resolves.toBeNull();
      expect(verify).not.toHaveBeenCalled();
    },
  );

  test('a shared round budget reserves attempts before concurrent verification', async () => {
    const budget = new InitialLoadAuthenticationBudget();
    const verify = jest.fn(async () => {
      await Promise.resolve();
      return false;
    });
    const results = await Promise.all(
      Array.from(
        { length: MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS + 20 },
        () => identifyInitialLoadSigner(options({ budget, verify })),
      ),
    );
    expect(results.every((result) => result === null)).toBe(true);
    expect(verify).toHaveBeenCalledTimes(
      MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS,
    );
  });

  test('a fresh load has its own attempt budget', async () => {
    const budget = new InitialLoadAuthenticationBudget();
    for (let i = 0; i < MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS; i++)
      expect(budget.reserve(0)).toBe(true);
    const verify = jest.fn(async () => true);
    await expect(
      verifyInitialLoadAuthentication(options({ budget, verify })),
    ).resolves.toBe(false);
    await expect(
      verifyInitialLoadAuthentication(options({ verify })),
    ).resolves.toBe(true);
    expect(verify).toHaveBeenCalledTimes(1);
  });

  test('an exhausted byte budget rejects before invoking the verifier', async () => {
    const budget = new InitialLoadAuthenticationBudget();
    expect(
      budget.reserve(
        MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES - payload.byteLength + 1,
      ),
    ).toBe(true);
    const verify = jest.fn(async () => true);
    await expect(
      identifyInitialLoadSigner(options({ budget, verify })),
    ).resolves.toBeNull();
    expect(verify).not.toHaveBeenCalled();
  });

  test('cancellation prevents work and discards a late result', async () => {
    const controller = new AbortController();
    const verify = jest.fn(async () => {
      controller.abort();
      return true;
    });
    await expect(
      identifyInitialLoadSigner(options({ signal: controller.signal, verify })),
    ).resolves.toBeNull();
    await expect(
      identifyInitialLoadSigner(options({ signal: controller.signal, verify })),
    ).resolves.toBeNull();
    expect(verify).toHaveBeenCalledTimes(1);
  });

  test('changing the signed authority cannot reuse another writer signature', async () => {
    const a = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const b = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const trustedSigners = createInitialLoadSignerLookup([
      { authorityId: 'a', publicKey: a.publicKey },
      { authorityId: 'b', publicKey: b.publicKey },
    ]);
    const body = (signerAuthority: string) =>
      new TextEncoder().encode(
        JSON.stringify({
          documentId: '/doc',
          signerAuthority,
          challenge: 'fresh-challenge',
        }),
      );
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' },
        a.privateKey,
        body('a'),
      ),
    );
    const verify = async (
      payload: Uint8Array,
      key: CryptoKey,
      sig: Uint8Array,
    ) =>
      crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        key,
        sig,
        payload,
      );
    const shared = {
      signature,
      trustedSigners,
      verify,
      budget: new InitialLoadAuthenticationBudget(),
    };
    await expect(
      verifyInitialLoadAuthentication({
        ...shared,
        signerAuthority: 'a',
        payload: body('a'),
      }),
    ).resolves.toBe(true);
    await expect(
      verifyInitialLoadAuthentication({
        ...shared,
        signerAuthority: 'b',
        payload: body('b'),
      }),
    ).resolves.toBe(false);
    await expect(
      verifyInitialLoadAuthentication({
        ...shared,
        signerAuthority: 'a',
        payload: body('b'),
      }),
    ).resolves.toBe(false);
  });
});
