const defaultRelayConnectSource = 'wss://relay.peerborne.io';
const relayMultiaddrPattern =
  /^\/(dns4|ip4)\/([^/\s]+)\/tcp\/(\d{1,5})\/(ws|wss)\/p2p\/([^/\s]+)$/u;
const relayConnectSourcePlaceholder = '__PEERBORNE_RELAY_CONNECT_SOURCE__';
const upgradeInsecureRequestsPlaceholder =
  '__PEERBORNE_UPGRADE_INSECURE_REQUESTS__';

function isDnsHostname(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  return value.split('.').every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(label),
  );
}

function isIpv4Address(value: string): boolean {
  const octets = value.split('.');
  return (
    octets.length === 4 &&
    octets.every(
      (octet) =>
        /^(?:0|[1-9]\d{0,2})$/u.test(octet) && Number(octet) <= 255,
    )
  );
}

export function relayConnectSourceFromMultiaddr(
  value: string | undefined,
  required: boolean,
  isValidPeerId: (value: string) => boolean,
): string {
  const relay = value?.trim() ?? '';
  if (relay.length === 0 && !required) return defaultRelayConnectSource;
  const match = relay.length <= 1024 ? relayMultiaddrPattern.exec(relay) : null;
  const port = match ? Number(match[3]) : 0;
  const validHost =
    match?.[1] === 'dns4'
      ? isDnsHostname(match[2])
      : match?.[1] === 'ip4' && isIpv4Address(match[2]);
  if (
    !match ||
    !validHost ||
    port < 1 ||
    port > 65_535 ||
    !isValidPeerId(match[5]) ||
    (required && (match[1] !== 'dns4' || port !== 443 || match[4] !== 'wss'))
  ) {
    throw new Error(
      required
        ? 'Deployment requires a complete DNS, TCP 443, WSS, peer-ID-qualified VITE_PEERBORNE_RELAY_MULTIADDR'
        : 'Relay configuration requires a valid DNS4 or IPv4 WebSocket multiaddr with a peer ID',
    );
  }
  const scheme = match[4];
  const defaultPort = scheme === 'wss' ? 443 : 80;
  const authority = `${match[2].toLowerCase()}${port === defaultPort ? '' : `:${port}`}`;
  return `${scheme}://${authority}`;
}

export function renderPagesHeaders(
  template: string,
  relayConnectSource: string,
): string {
  if (!template.includes(relayConnectSourcePlaceholder)) {
    throw new Error(
      'Peerborne Note public/_headers has no relay connect-source placeholder',
    );
  }
  if (!template.includes(upgradeInsecureRequestsPlaceholder)) {
    throw new Error(
      'Peerborne Note public/_headers has no upgrade-insecure-requests placeholder',
    );
  }
  return template
    .replaceAll(relayConnectSourcePlaceholder, relayConnectSource)
    .replaceAll(
      upgradeInsecureRequestsPlaceholder,
      relayConnectSource.startsWith('wss://')
        ? 'upgrade-insecure-requests'
        : '',
    );
}
