import { describe, expect, test } from '@jest/globals';
import { createUCAN, verifyUCANSignature, serializeUCAN, deserializeUCAN } from './ucan';

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
}
async function publicKeyToBase64(publicKey: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return btoa(String.fromCharCode(...raw));
}

describe('UCAN forgery resistance', () => {
  test('tampered capabilities fail verification', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-1', ability: '/doc/read' }]);
    const forged = { ...ucan, capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }] };
    expect(await verifyUCANSignature(forged, issuer.publicKey)).toBe(false);
  });

  test('tampered resource fails verification', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-1', ability: '/doc/read' }]);
    const forged = { ...ucan, capabilities: [{ resource: 'doc-2', ability: '/doc/admin' }] };
    expect(await verifyUCANSignature(forged, issuer.publicKey)).toBe(false);
  });

  test('tampered signature fails verification', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-1', ability: '/doc/read' }]);
    const sigBytes = Buffer.from(ucan.signature, 'base64');
    sigBytes[0] ^= 0xff;
    const forged = { ...ucan, signature: sigBytes.toString('base64') };
    expect(await verifyUCANSignature(forged, issuer.publicKey)).toBe(false);
  });

  test('tampered issuer fails verification', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const wrongIssuer = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const wrongB64 = await publicKeyToBase64(wrongIssuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-1', ability: '/doc/read' }]);
    const forged = { ...ucan, issuer: wrongB64 };
    expect(await verifyUCANSignature(forged, issuer.publicKey)).toBe(false);
  });

  test('wrong verification key fails', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const wrongKey = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-1', ability: '/doc/read' }]);
    expect(await verifyUCANSignature(ucan, wrongKey.publicKey)).toBe(false);
  });

  test('valid UCAN verifies', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [
      { resource: 'doc-1', ability: '/doc/write' },
      { resource: 'doc-1', ability: '/doc/read' },
    ]);
    expect(await verifyUCANSignature(ucan, issuer.publicKey)).toBe(true);
  });

  test('serialize/deserialize round-trip preserves fields', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-42', ability: '/doc/write' }]);
    const serialized = serializeUCAN(ucan);
    const deserialized = deserializeUCAN(serialized);
    expect(deserialized.version).toBe(ucan.version);
    expect(deserialized.issuer).toBe(ucan.issuer);
    expect(deserialized.audience).toBe(ucan.audience);
    expect(deserialized.capabilities).toEqual(ucan.capabilities);
    expect(deserialized.signature).toBe(ucan.signature);
  });

  test('deserialized UCAN still verifies', async () => {
    const issuer = await generateKeyPair();
    const audience = await generateKeyPair();
    const issuerB64 = await publicKeyToBase64(issuer.publicKey);
    const audienceB64 = await publicKeyToBase64(audience.publicKey);
    const ucan = await createUCAN(issuer.privateKey, issuerB64, audienceB64, [{ resource: 'doc-1', ability: '/doc/read' }]);
    const serialized = serializeUCAN(ucan);
    const deserialized = deserializeUCAN(serialized);
    expect(await verifyUCANSignature(deserialized, issuer.publicKey)).toBe(true);
  });
});
