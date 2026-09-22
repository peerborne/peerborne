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
