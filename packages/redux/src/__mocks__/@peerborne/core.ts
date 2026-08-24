// Mock for @peerborne/core - provides stub exports
// so jest doesn't need to resolve the full libp2p dependency chain.

export class Peerborne {
  constructor(..._args: any[]) {}
}

export class PeerborneDocument {
  document: any = {};
  constructor(..._args: any[]) {}
}

export interface CRDTProvider {}
export interface AuthProvider {}
export interface ACLProvider {}
export interface KeychainProvider {}
export interface ChangesSerializer {}
export interface SyncMessageSerializer {}
export interface LoadMessageSerializer {}
export interface PeerborneConfig {}

export function defaultConfig(..._args: any[]) {
  return {};
}
export function defaultBootstrapConfig(..._args: any[]) {
  return {};
}
