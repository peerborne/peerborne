import {
  PeerborneActions,
  PeerborneState,
} from '@peerborne/redux';
import { Doc, Change } from '@automerge/automerge';

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
