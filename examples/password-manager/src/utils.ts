import { Peerborne, PeerborneDocument } from '@peerborne/core';
import * as Y from 'yjs';

export function encodeKemPublicKey(raw: Uint8Array): string {
  return btoa(String.fromCharCode(...raw));
}

export class KemPublicKeyInputError extends Error {}

export function decodeKemPublicKey(encoded: string): Uint8Array {
  let decoded: string;
  try {
    decoded = atob(encoded.trim());
  } catch {
    throw new KemPublicKeyInputError(
      'The member KEM public key is not valid base64.',
    );
  }
  const raw = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new KemPublicKeyInputError(
      'The member KEM public key must be a 65-byte uncompressed P-256 ' +
        'public key starting with 0x04.',
    );
  }
  return raw;
}

export type YjsPeerborne = Peerborne<
  Y.Doc,
  Uint8Array,
  (doc: Y.Doc) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
export type YjsPeerborneDocument = PeerborneDocument<
  Y.Doc,
  Uint8Array,
  (doc: Y.Doc) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;

export async function exportKey(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk);
}

export async function importKey(
  keyData: string,
  keyUsage: KeyUsage[],
): Promise<CryptoKey> {
  const jwk = JSON.parse(keyData) as JsonWebKey;
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    },
    true,
    keyUsage,
  );
}
