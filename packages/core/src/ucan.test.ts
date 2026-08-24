import { describe, expect, test } from '@jest/globals';
import {
  createUCAN,
  verifyUCANSignature,
  serializeUCAN,
  deserializeUCAN,
  validateUCANChain,
  UCAN,
} from './ucan.js';

/** Generate an ECDSA P-384 key pair for testing. */
async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
}

/** Export a public key to Base64 for use as UCAN issuer/audience. */
async function publicKeyToBase64(publicKey: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return btoa(String.fromCharCode(...raw));
}

/** Resolve a Base64 public key back to a CryptoKey. */
function makeKeyResolver(keyMap: Map<string, CryptoKey>) {
  return async (base64Key: string): Promise<CryptoKey> => {
    const key = keyMap.get(base64Key);
    if (!key) throw new Error(`Unknown key: ${base64Key}`);
    return key;
  };
}

describe('createUCAN', () => {
  test('creates a UCAN with all required fields', async () => {
    const keyPair = await generateKeyPair();
    const issuerBase64 = await publicKeyToBase64(keyPair.publicKey);
    const audienceKeyPair = await generateKeyPair();
    const audienceBase64 = await publicKeyToBase64(audienceKeyPair.publicKey);

    const ucan = await createUCAN(
      keyPair.privateKey,
      issuerBase64,
      audienceBase64,
      [{ resource: 'doc-123', ability: '/doc/write' }],
    );

    expect(ucan.version).toBe('0.1.0');
    expect(ucan.issuer).toBe(issuerBase64);
    expect(ucan.audience).toBe(audienceBase64);
    expect(ucan.capabilities).toEqual([{ resource: 'doc-123', ability: '/doc/write' }]);
    expect(ucan.expiration).toBeNull();
    expect(ucan.notBefore).toBeNull();
    expect(typeof ucan.nonce).toBe('string');
    expect(ucan.nonce.length).toBe(32); // 16 bytes as hex
    expect(ucan.proofs).toEqual([]);
    expect(typeof ucan.signature).toBe('string');
    expect(ucan.signature.length).toBeGreaterThan(0);
  });

  test('nonce is unique across calls', async () => {
    const keyPair = await generateKeyPair();
    const issuerBase64 = await publicKeyToBase64(keyPair.publicKey);
    const audienceBase64 = 'some-audience';

    const ucan1 = await createUCAN(
      keyPair.privateKey,
      issuerBase64,
      audienceBase64,
      [{ resource: 'doc-1', ability: '/doc/read' }],
    );
    const ucan2 = await createUCAN(
      keyPair.privateKey,
      issuerBase64,
      audienceBase64,
      [{ resource: 'doc-1', ability: '/doc/read' }],
    );

    expect(ucan1.nonce).not.toBe(ucan2.nonce);
  });

  test('respects expiration and notBefore options', async () => {
    const keyPair = await generateKeyPair();
    const issuerBase64 = await publicKeyToBase64(keyPair.publicKey);

    const expiration = Math.floor(Date.now() / 1000) + 3600;
    const notBefore = Math.floor(Date.now() / 1000) - 60;

    const ucan = await createUCAN(
      keyPair.privateKey,
      issuerBase64,
      'audience',
      [{ resource: 'doc-1', ability: '/doc/read' }],
      [],
      { expiration, notBefore },
    );

    expect(ucan.expiration).toBe(expiration);
    expect(ucan.notBefore).toBe(notBefore);
  });
});

describe('verifyUCANSignature', () => {
  test('returns true for a valid signature', async () => {
    const keyPair = await generateKeyPair();
    const issuerBase64 = await publicKeyToBase64(keyPair.publicKey);

    const ucan = await createUCAN(
      keyPair.privateKey,
      issuerBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/write' }],
    );

    const result = await verifyUCANSignature(ucan, keyPair.publicKey);
    expect(result).toBe(true);
  });

  test('returns false when verified with wrong public key', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();
    const issuerBase64 = await publicKeyToBase64(keyPair1.publicKey);

    const ucan = await createUCAN(
      keyPair1.privateKey,
      issuerBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/write' }],
    );

    const result = await verifyUCANSignature(ucan, keyPair2.publicKey);
    expect(result).toBe(false);
  });
});

describe('serializeUCAN / deserializeUCAN', () => {
  test('round-trip produces equivalent UCAN', async () => {
    const keyPair = await generateKeyPair();
    const issuerBase64 = await publicKeyToBase64(keyPair.publicKey);

    const original = await createUCAN(
      keyPair.privateKey,
      issuerBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/read' }],
    );

    const serialized = serializeUCAN(original);
    expect(typeof serialized).toBe('string');

    const deserialized = deserializeUCAN(serialized);

    expect(deserialized.version).toBe(original.version);
    expect(deserialized.issuer).toBe(original.issuer);
    expect(deserialized.audience).toBe(original.audience);
    expect(deserialized.capabilities).toEqual(original.capabilities);
    expect(deserialized.expiration).toBe(original.expiration);
    expect(deserialized.notBefore).toBe(original.notBefore);
    expect(deserialized.nonce).toBe(original.nonce);
    expect(deserialized.proofs).toEqual(original.proofs);
    expect(deserialized.signature).toBe(original.signature);
  });
});

describe('validateUCANChain', () => {
  test('valid root UCAN (no proofs, issued by root) is valid', async () => {
    const rootKeyPair = await generateKeyPair();
    const rootBase64 = await publicKeyToBase64(rootKeyPair.publicKey);

    const audienceKeyPair = await generateKeyPair();
    const audienceBase64 = await publicKeyToBase64(audienceKeyPair.publicKey);

    const ucan = await createUCAN(
      rootKeyPair.privateKey,
      rootBase64,
      audienceBase64,
      [{ resource: 'doc-1', ability: '/doc/write' }],
    );

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(rootBase64, rootKeyPair.publicKey);
    keyMap.set(audienceBase64, audienceKeyPair.publicKey);

    const result = await validateUCANChain(
      ucan,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result).toEqual({ valid: true });
  });

  test('UCAN with valid delegation chain is valid', async () => {
    const rootKeyPair = await generateKeyPair();
    const rootBase64 = await publicKeyToBase64(rootKeyPair.publicKey);

    const delegateKeyPair = await generateKeyPair();
    const delegateBase64 = await publicKeyToBase64(delegateKeyPair.publicKey);

    const endUserKeyPair = await generateKeyPair();
    const endUserBase64 = await publicKeyToBase64(endUserKeyPair.publicKey);

    // Root grants /doc/admin to delegate
    const rootUcan = await createUCAN(
      rootKeyPair.privateKey,
      rootBase64,
      delegateBase64,
      [{ resource: 'doc-1', ability: '/doc/admin' }],
    );

    // Delegate grants /doc/write to end user (attenuated from /doc/admin)
    const delegatedUcan = await createUCAN(
      delegateKeyPair.privateKey,
      delegateBase64,
      endUserBase64,
      [{ resource: 'doc-1', ability: '/doc/write' }],
      [serializeUCAN(rootUcan)],
    );

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(rootBase64, rootKeyPair.publicKey);
    keyMap.set(delegateBase64, delegateKeyPair.publicKey);
    keyMap.set(endUserBase64, endUserKeyPair.publicKey);

    const result = await validateUCANChain(
      delegatedUcan,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result).toEqual({ valid: true });
  });

  test('UCAN with invalid signature is invalid', async () => {
    const rootKeyPair = await generateKeyPair();
    const rootBase64 = await publicKeyToBase64(rootKeyPair.publicKey);

    const ucan = await createUCAN(
      rootKeyPair.privateKey,
      rootBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/read' }],
    );

    // Tamper with the signature
    const tampered: UCAN = {
      ...ucan,
      signature: ucan.signature.slice(0, -4) + 'AAAA',
    };

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(rootBase64, rootKeyPair.publicKey);

    const result = await validateUCANChain(
      tampered,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid UCAN signature');
  });

  test('UCAN with wrong issuer (not root, no proofs) is invalid', async () => {
    const rootKeyPair = await generateKeyPair();
    const nonRootKeyPair = await generateKeyPair();
    const nonRootBase64 = await publicKeyToBase64(nonRootKeyPair.publicKey);

    // Non-root issues a UCAN with no proofs
    const ucan = await createUCAN(
      nonRootKeyPair.privateKey,
      nonRootBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/read' }],
    );

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(nonRootBase64, nonRootKeyPair.publicKey);

    const result = await validateUCANChain(
      ucan,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Root UCAN must be issued by document creator');
  });

  test('UCAN with capability attenuation violation is invalid', async () => {
    const rootKeyPair = await generateKeyPair();
    const rootBase64 = await publicKeyToBase64(rootKeyPair.publicKey);

    const delegateKeyPair = await generateKeyPair();
    const delegateBase64 = await publicKeyToBase64(delegateKeyPair.publicKey);

    const endUserKeyPair = await generateKeyPair();
    const endUserBase64 = await publicKeyToBase64(endUserKeyPair.publicKey);

    // Root grants /doc/read to delegate
    const rootUcan = await createUCAN(
      rootKeyPair.privateKey,
      rootBase64,
      delegateBase64,
      [{ resource: 'doc-1', ability: '/doc/read' }],
    );

    // Delegate tries to grant /doc/write (escalation!) to end user
    const delegatedUcan = await createUCAN(
      delegateKeyPair.privateKey,
      delegateBase64,
      endUserBase64,
      [{ resource: 'doc-1', ability: '/doc/write' }],
      [serializeUCAN(rootUcan)],
    );

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(rootBase64, rootKeyPair.publicKey);
    keyMap.set(delegateBase64, delegateKeyPair.publicKey);
    keyMap.set(endUserBase64, endUserKeyPair.publicKey);

    const result = await validateUCANChain(
      delegatedUcan,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('not authorized by proof');
  });

  test('expired UCAN is invalid', async () => {
    const rootKeyPair = await generateKeyPair();
    const rootBase64 = await publicKeyToBase64(rootKeyPair.publicKey);

    // Expired 1 hour ago
    const ucan = await createUCAN(
      rootKeyPair.privateKey,
      rootBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/read' }],
      [],
      { expiration: Math.floor(Date.now() / 1000) - 3600 },
    );

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(rootBase64, rootKeyPair.publicKey);

    const result = await validateUCANChain(
      ucan,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe('UCAN has expired');
  });

  test('not-yet-valid UCAN is invalid', async () => {
    const rootKeyPair = await generateKeyPair();
    const rootBase64 = await publicKeyToBase64(rootKeyPair.publicKey);

    // Not valid until 1 hour from now
    const ucan = await createUCAN(
      rootKeyPair.privateKey,
      rootBase64,
      'audience-key',
      [{ resource: 'doc-1', ability: '/doc/read' }],
      [],
      { notBefore: Math.floor(Date.now() / 1000) + 3600 },
    );

    const keyMap = new Map<string, CryptoKey>();
    keyMap.set(rootBase64, rootKeyPair.publicKey);

    const result = await validateUCANChain(
      ucan,
      rootKeyPair.publicKey,
      makeKeyResolver(keyMap),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe('UCAN is not yet valid');
  });
});
