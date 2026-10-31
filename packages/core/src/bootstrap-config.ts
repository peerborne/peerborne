/** True when libp2p's bootstrap discovery service should be constructed. */
export interface BootstrapPeerList {
  readonly list: readonly string[];
}

export function hasBootstrapPeers(config: BootstrapPeerList): boolean {
  //@ verify
  //@ ensures \result <==> config.list.length > 0
  return config.list.length > 0;
}
