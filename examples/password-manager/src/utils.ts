import { Peerborne, PeerborneDocument } from '@peerborne/core';
import { createContext } from 'react';
import * as Y from 'yjs';

/** This session's KEM key pair, used to seal and open BeeKEM Welcomes. */
export const KemKeyPairContext = createContext<CryptoKeyPair | undefined>(
  undefined,
);

export function encodeKemPublicKey(raw: Uint8Array): string {
  return btoa(String.fromCharCode(...raw));
}

export function decodeKemPublicKey(encoded: string): Uint8Array {
  return Uint8Array.from(atob(encoded.trim()), (char) => char.charCodeAt(0));
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
