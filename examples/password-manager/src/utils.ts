import { Peerborne, PeerborneDocument } from '@peerborne/core';
import * as Y from 'yjs';

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
