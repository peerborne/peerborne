const INVITATION_FRAGMENT_PREFIX = '#invite=';

export const MAX_INVITATION_TOKEN_CHARACTERS = 128 * 1024;

export interface FragmentLocation {
  readonly hash: string;
  readonly pathname: string;
  readonly search: string;
}

export interface FragmentHistory {
  readonly state: unknown;
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}

export type ConsumedInvitationFragment =
  | { readonly kind: 'none' }
  | { readonly kind: 'invite'; readonly bytes: Uint8Array }
  | { readonly kind: 'invalid' };

export function consumeInvitationFragment(
  location: FragmentLocation,
  history: FragmentHistory,
): ConsumedInvitationFragment {
  const hash = location.hash;
  if (hash.length > 0) {
    history.replaceState(
      history.state,
      '',
      `${location.pathname}${location.search}`,
    );
  }
  if (hash.length === 0) return { kind: 'none' };
  if (!hash.startsWith(INVITATION_FRAGMENT_PREFIX)) {
    return { kind: 'invalid' };
  }
  const token = hash.slice(INVITATION_FRAGMENT_PREFIX.length);
  if (token.length === 0 || token.length > MAX_INVITATION_TOKEN_CHARACTERS) {
    return { kind: 'invalid' };
  }
  try {
    return { kind: 'invite', bytes: decodeInvitationToken(token) };
  } catch {
    return { kind: 'invalid' };
  }
}

export function encodeInvitationToken(bytes: Uint8Array): string {
  const chunks: string[] = [];
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    chunks.push(String.fromCharCode(...chunk));
  }
  return btoa(chunks.join(''))
    .replace(/\+/gu, '-')
    .replace(/\//gu, '_')
    .replace(/=+$/u, '');
}

export function decodeInvitationToken(token: string): Uint8Array {
  if (token.length === 0 || token.length > MAX_INVITATION_TOKEN_CHARACTERS) {
    throw new Error('Invitation token has an invalid size');
  }
  if (!/^[A-Za-z0-9_-]+$/u.test(token) || token.length % 4 === 1) {
    throw new Error('Invitation token is not canonical Base64url');
  }
  const padded = token.replace(/-/gu, '+').replace(/_/gu, '/').padEnd(
    token.length + ((4 - (token.length % 4)) % 4),
    '=',
  );
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('Invitation token is not valid Base64url');
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeInvitationToken(bytes) !== token) {
    throw new Error('Invitation token is not canonical Base64url');
  }
  return bytes;
}

export function invitationUrl(bytes: Uint8Array, currentHref: string): string {
  const url = new URL(currentHref);
  url.hash = `invite=${encodeInvitationToken(bytes)}`;
  return url.toString();
}

export function rendezvousForCircuitReservation(
  observedAddresses: readonly string[],
  relayMultiaddr: string,
  peerId: string,
): string | undefined {
  const relayPeerComponent = relayMultiaddr.slice(
    relayMultiaddr.lastIndexOf('/p2p/'),
  );
  const reservationSuffix = `${relayPeerComponent}/p2p-circuit/p2p/${peerId}`;
  const reservationObserved = observedAddresses.some((address) =>
    address.endsWith(reservationSuffix),
  );
  return reservationObserved
    ? `${relayMultiaddr}/p2p-circuit/p2p/${peerId}`
    : undefined;
}

export function assertTrustedRendezvous(
  rendezvous: readonly string[],
  relayMultiaddr: string,
): void {
  if (
    relayMultiaddr.length === 0 ||
    relayMultiaddr.endsWith('/') ||
    /[\u0000-\u0020\u007f]/u.test(relayMultiaddr)
  ) {
    throw new Error('The configured relay multiaddr is invalid');
  }
  if (rendezvous.length !== 1) {
    throw new Error('Peerborne Note invitations require one rendezvous address');
  }
  const prefix = `${relayMultiaddr}/p2p-circuit/p2p/`;
  for (const address of rendezvous) {
    if (!address.startsWith(prefix)) {
      throw new Error('Invitation rendezvous is outside the configured relay');
    }
    const founderPeerId = address.slice(prefix.length);
    if (
      founderPeerId.length === 0 ||
      founderPeerId.length > 256 ||
      founderPeerId.includes('/') ||
      /[\u0000-\u0020\u007f]/u.test(founderPeerId)
    ) {
      throw new Error('Invitation rendezvous has an invalid founder peer ID');
    }
  }
}

export function assertRelayMultiaddrForOrigin(
  relayMultiaddr: string | undefined,
  isSecureContext: boolean,
): asserts relayMultiaddr is string {
  if (!relayMultiaddr) {
    throw new Error('Peerborne Note has no relay configured');
  }
  if (
    !relayMultiaddr.startsWith('/') ||
    relayMultiaddr.endsWith('/') ||
    !relayMultiaddr.includes('/p2p/') ||
    /[\u0000-\u0020\u007f]/u.test(relayMultiaddr)
  ) {
    throw new Error('Peerborne Note has an invalid relay configuration');
  }
  if (isSecureContext && !relayMultiaddr.includes('/wss/')) {
    throw new Error('Secure Peerborne Note pages require a WSS relay');
  }
}
