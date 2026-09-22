import { expect, jest, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import { decodeCanonicalP384PublicKeyEncoding } from './serialized-public-key.js';

test('rejects oversized P-384 encodings before allocating decoded bytes', () => {
  const decode = jest.spyOn(Base64, 'toUint8Array');
  try {
    expect(() => decodeCanonicalP384PublicKeyEncoding('A'.repeat(1024 * 1024), 'Public key')).toThrow(/canonical base64.*97-byte/);
    expect(decode).not.toHaveBeenCalled();
  } finally {
    decode.mockRestore();
  }
});

test.each([undefined, null, 12])('rejects non-string P-384 identity %p', (value) => {
  expect(() => decodeCanonicalP384PublicKeyEncoding(value, 'Public key')).toThrow(/must be a string/);
});

test.each(['padding', 'length', 'prefix', 'x', 'y', 'off-curve'])(
  'rejects a P-384 encoding with invalid %s',
  (failure) => {
    const raw = new Uint8Array(failure === 'length' ? 98 : 97);
    raw[0] = failure === 'prefix' ? 3 : 4;
    if (failure === 'x') raw.fill(255, 1, 49);
    if (failure === 'y') raw.fill(255, 49);
    let encoded = Base64.fromUint8Array(raw);
    if (failure === 'padding') encoded = encoded.slice(0, -3) + 'B==';
    expect(() => decodeCanonicalP384PublicKeyEncoding(encoded, 'Public key')).toThrow(
      failure === 'padding' ? /canonical base64/ : /P-384 point/,
    );
  },
);

test('accepts a canonical generated P-384 public point', async () => {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  expect(decodeCanonicalP384PublicKeyEncoding(Base64.fromUint8Array(raw), 'Public key')).toEqual(raw);
});
