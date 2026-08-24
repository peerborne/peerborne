/** True when libp2p's bootstrap discovery service should be constructed. */
export function hasBootstrapPeers(config: { list: readonly string[] }): boolean {
  return config.list.length > 0;
}
