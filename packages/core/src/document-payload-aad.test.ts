import { describe, expect, test } from '@jest/globals';
import {
  documentPayloadAAD,
  type DocumentPayloadKind,
} from './document-payload-aad.js';
import { SubtleCrypto } from './auth-subtlecrypto.js';

const KEY_ID = Uint8Array.from({ length: 16 }, (_, index) => index);
const KINDS: DocumentPayloadKind[] = [
  'block',
  'frame',
  'response',
  'invitation-bootstrap',
];

describe('documentPayloadAAD', () => {
  test('encodes a versioned domain, then the path, key ID and kind with lengths', () => {
    const encoder = new TextEncoder();
    const framed = (bytes: Uint8Array) => [0, 0, 0, bytes.length, ...bytes];
    expect(documentPayloadAAD('/a', new Uint8Array([9, 8]), 'frame')).toEqual(
      new Uint8Array([
        ...encoder.encode('peerborne/document-payload/v1\0'),
        ...framed(encoder.encode('/a')),
        ...framed(new Uint8Array([9, 8])),
        ...framed(encoder.encode('frame')),
      ]),
    );
  });

  test('separates every kind, path and key ID', () => {
    const encoded = new Set<string>();
    const inputs: [string, Uint8Array, DocumentPayloadKind][] = [];
    for (const kind of KINDS)
      for (const path of ['/doc', '/doc2', '/do', 'c/doc'])
        for (const keyId of [KEY_ID, KEY_ID.subarray(1), new Uint8Array(16)])
          inputs.push([path, keyId, kind]);
    for (const input of inputs)
      encoded.add(Buffer.from(documentPayloadAAD(...input)).toString('hex'));
    expect(encoded.size).toBe(inputs.length);
  });

  test('rejects unknown kinds and ill-formed paths', () => {
    expect(() =>
      documentPayloadAAD('/doc', KEY_ID, 'snapshot' as DocumentPayloadKind),
    ).toThrow(TypeError);
    expect(() => documentPayloadAAD('/doc\ud800', KEY_ID, 'block')).toThrow(
      TypeError,
    );
  });

  test('a ciphertext opens only as the payload it was sealed as', async () => {
    const auth = new SubtleCrypto();
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const plaintext = new Uint8Array([1, 2, 3]);
    const sealed = documentPayloadAAD('/doc', KEY_ID, 'frame');
    const { data, nonce } = await auth.encrypt(plaintext, key, sealed);

    await expect(auth.decrypt(data, key, nonce, sealed)).resolves.toEqual(
      plaintext,
    );
    const otherKeyId = new Uint8Array(KEY_ID);
    otherKeyId[0] ^= 1;
    for (const replayed of [
      ...KINDS.filter((kind) => kind !== 'frame').map((kind) =>
        documentPayloadAAD('/doc', KEY_ID, kind),
      ),
      documentPayloadAAD('/other', KEY_ID, 'frame'),
      documentPayloadAAD('/doc', otherKeyId, 'frame'),
    ]) {
      await expect(auth.decrypt(data, key, nonce, replayed)).rejects.toThrow();
    }
  });
});
