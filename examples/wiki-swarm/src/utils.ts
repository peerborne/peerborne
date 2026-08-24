import { Peerborne, PeerborneDocument } from '@peerborne/core';
import {
  PeerborneActions,
  PeerborneState,
} from '@peerborne/redux';
import { Doc, Change } from '@automerge/automerge';

export type AutomergeSwarm<T = any> = Peerborne<
  Doc<T>,
  Change[],
  (doc: T) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
export type AutomergeSwarmDocument<T = any> = PeerborneDocument<
  Doc<T>,
  Change[],
  (doc: T) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
export type AutomergeSwarmState<T = any> = PeerborneState<
  Doc<T>,
  Change[],
  (doc: T) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
export type AutomergeSwarmActions<T = any> = PeerborneActions<
  Doc<T>,
  Change[],
  (doc: T) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
