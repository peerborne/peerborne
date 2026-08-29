import {
  assertRelayMultiaddrForOrigin,
  assertTrustedRendezvous,
  consumeInvitationFragment,
  decodeInvitationToken,
  encodeInvitationToken,
  invitationUrl,
  MAX_INVITATION_TOKEN_CHARACTERS,
  rendezvousForCircuitReservation,
} from './invitation-link.js';

describe('invitation fragments', () => {
  test('scrubs the fragment immediately and retains only decoded bytes', () => {
    const replaceState = jest.fn();
    expect(consumeInvitationFragment(
      {
        hash: '#invite=AQID',
        pathname: '/note',
        search: '?from=test',
      },
      { state: { preserved: true }, replaceState },
    )).toEqual({ kind: 'invite', bytes: Uint8Array.from([1, 2, 3]) });
    expect(replaceState).toHaveBeenCalledWith(
      { preserved: true },
      '',
      '/note?from=test',
    );
  });

  test('scrubs and rejects a non-canonical invitation token', () => {
    const replaceState = jest.fn();
    expect(consumeInvitationFragment(
      { hash: '#invite=AQID=', pathname: '/', search: '' },
      { state: null, replaceState },
    )).toEqual({ kind: 'invalid' });
    expect(replaceState).toHaveBeenCalledTimes(1);
  });

  test('scrubs and rejects unknown, empty, and oversized fragments', () => {
    for (const hash of [
      '#section',
      '#invite=',
      `#invite=${'A'.repeat(MAX_INVITATION_TOKEN_CHARACTERS + 1)}`,
    ]) {
      const replaceState = jest.fn();
      expect(consumeInvitationFragment(
        { hash, pathname: '/', search: '' },
        { state: null, replaceState },
      )).toEqual({ kind: 'invalid' });
      expect(replaceState).toHaveBeenCalledTimes(1);
    }
  });

  test('leaves a URL without a fragment untouched', () => {
    const replaceState = jest.fn();
    expect(consumeInvitationFragment(
      { hash: '', pathname: '/', search: '' },
      { state: null, replaceState },
    )).toEqual({ kind: 'none' });
    expect(replaceState).not.toHaveBeenCalled();
  });
});

describe('invitation Base64url', () => {
  test('round-trips canonical unpadded bytes', () => {
    const bytes = Uint8Array.from([0, 1, 2, 253, 254, 255]);
    const token = encodeInvitationToken(bytes);
    expect(token).toBe('AAEC_f7_');
    expect(decodeInvitationToken(token)).toEqual(bytes);
  });

  test('round-trips bytes across encoding chunks', () => {
    const bytes = Uint8Array.from(
      { length: 0x8001 },
      (_, index) => index % 256,
    );
    expect(decodeInvitationToken(encodeInvitationToken(bytes))).toEqual(bytes);
  });

  test.each([
    '',
    'AQID=',
    'AQ ID',
    'A',
    'AQID&next=value',
  ])('rejects non-canonical token %j', (token) => {
    expect(() => decodeInvitationToken(token)).toThrow();
  });

  test('places the token in a URL fragment', () => {
    expect(invitationUrl(
      Uint8Array.from([1, 2, 3]),
      'https://try.peerborne.io/?source=test',
    )).toBe('https://try.peerborne.io/?source=test#invite=AQID');
  });
});

describe('relay boundaries', () => {
  const relay =
    '/dns4/relay.peerborne.io/tcp/443/wss/p2p/12D3KooWRelay';
  const founder =
    `${relay}/p2p-circuit/p2p/12D3KooWFounder`;

  test('accepts only founder addresses beneath the exact configured relay', () => {
    expect(() => assertTrustedRendezvous([founder], relay)).not.toThrow();
  });

  test.each([
    founder,
    '/ip4/203.0.113.7/tcp/443/wss/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWFounder',
  ])('recognizes an exact or resolved relay reservation', (observed) => {
    expect(rendezvousForCircuitReservation(
      [observed],
      relay,
      '12D3KooWFounder',
    )).toBe(founder);
  });

  test('ignores reservations for another relay or local peer', () => {
    expect(rendezvousForCircuitReservation(
      [
        '/ip4/203.0.113.7/tcp/443/wss/p2p/12D3KooWOther/p2p-circuit/p2p/12D3KooWFounder',
        '/ip4/203.0.113.7/tcp/443/wss/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWOther',
        '/ip4/203.0.113.7/tcp/443/wss/p2p/12D3KooWFounder',
      ],
      relay,
      '12D3KooWFounder',
    )).toBeUndefined();
  });

  test.each([
    { addresses: [] },
    { addresses: [founder, founder] },
    { addresses: ['/dns4/other.example/tcp/443/wss/p2p/12D3KooWOther/p2p-circuit/p2p/12D3KooWFounder'] },
    { addresses: [`${relay}/p2p-circuit/p2p/`] },
    { addresses: [`${relay}/p2p-circuit/p2p/12D3KooWFounder/p2p/another`] },
    { addresses: [`${relay}/p2p-circuit/p2p/founder\nsmuggled`] },
  ])('rejects untrusted or malformed rendezvous %#', ({ addresses }) => {
    expect(() => assertTrustedRendezvous(addresses, relay)).toThrow();
  });

  test('requires WSS when the page is served over HTTPS', () => {
    expect(() => assertRelayMultiaddrForOrigin(relay, true)).not.toThrow();
    expect(() => assertRelayMultiaddrForOrigin(
      '/dns4/relay/tcp/9001/ws/p2p/12D3KooWRelay',
      true,
    )).toThrow(/WSS/u);
    expect(() => assertRelayMultiaddrForOrigin(
      '/dns4/relay/tcp/9001/ws/p2p/12D3KooWRelay',
      false,
    )).not.toThrow();
  });
});
