import { isPrivateIp } from '@libp2p/utils';
import type { Multiaddr } from '@multiformats/multiaddr';

const NAME_COMPONENTS = new Set(['dns', 'dns4', 'dns6', 'dnsaddr']);
const LOCAL_NAME_SUFFIXES = ['localhost', 'local', 'internal', 'home.arpa'];

function isLocalName(value: string): boolean {
  const name = value.toLowerCase().replace(/\.$/u, '');
  const literal = isPrivateIp(name);
  if (literal !== undefined) return literal;
  const labels = name.split('.');
  const last = labels.at(-1) ?? '';
  return (
    labels.length < 2 ||
    /^(?:\d+|0x[0-9a-f]*)$/u.test(last) ||
    LOCAL_NAME_SUFFIXES.some(
      (suffix) => name === suffix || name.endsWith(`.${suffix}`),
    )
  );
}

/**
 * Whether dialing `address` would reach a host outside the public internet:
 * a loopback, private, shared (CGNAT), link-local (including the
 * `169.254.169.254` cloud metadata service), unique-local, unspecified,
 * documentation, multicast or other IANA special-purpose IP address, a
 * Unix socket, an IPv6 zone, or a DNS name that cannot be a public name
 * (`localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, a
 * single label, or a numeric last label).
 *
 * Only the first network component is checked, which for a circuit address
 * is the relay. An address with no network component, such as
 * `/p2p/<relay>/p2p-circuit/p2p/<peer>`, opens no new socket and is not local.
 * DNS names are judged by their spelling: a public name that resolves to a
 * private address is not detected.
 */
export function isLocalNetworkAddress(address: Multiaddr): boolean {
  for (const { name, value } of address.getComponents()) {
    if (name === 'unix' || name === 'ip6zone') return true;
    if (value === undefined) continue;
    if (name === 'ip4' || name === 'ip6') return isPrivateIp(value) !== false;
    if (NAME_COMPONENTS.has(name)) return isLocalName(value);
  }
  return false;
}

/**
 * Connection gater check that refuses every address
 * {@link isLocalNetworkAddress} reports, so a remote peer cannot make this
 * node connect to loopback, LAN or cloud metadata services by advertising
 * such an address.
 */
export async function denyLocalNetworkDial(
  address: Multiaddr,
): Promise<boolean> {
  return isLocalNetworkAddress(address);
}
