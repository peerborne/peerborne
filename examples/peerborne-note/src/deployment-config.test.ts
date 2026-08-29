import {
  relayConnectSourceFromMultiaddr,
  renderPagesHeaders,
} from './deployment-config.js';

describe('deployment configuration', () => {
  const validPeerId =
    '12D3KooWRqEojevLXwbPxiAvDaK4HbCUXip6rSzrhWurUBdgwFGT';
  const isValidPeerId = (value: string) => value === validPeerId;

  it('uses the public relay for an ordinary local build', () => {
    expect(
      relayConnectSourceFromMultiaddr(undefined, false, isValidPeerId),
    ).toBe('wss://relay.peerborne.io');
  });

  it('requires and extracts a deployment relay origin', () => {
    expect(() =>
      relayConnectSourceFromMultiaddr(undefined, true, isValidPeerId),
    ).toThrow(/Deployment requires/);
    expect(
      relayConnectSourceFromMultiaddr(
        `/dns4/Relay.Example.com/tcp/443/wss/p2p/${validPeerId}`,
        true,
        isValidPeerId,
      ),
    ).toBe('wss://relay.example.com');
  });

  it.each([
    [
      `/ip4/127.0.0.1/tcp/9001/ws/p2p/${validPeerId}`,
      'ws://127.0.0.1:9001',
    ],
    [`/dns4/relay/tcp/9001/ws/p2p/${validPeerId}`, 'ws://relay:9001'],
    [
      `/dns4/relay.example.com/tcp/9443/wss/p2p/${validPeerId}`,
      'wss://relay.example.com:9443',
    ],
  ])('allows a local-development relay: %s', (relay, expected) => {
    expect(
      relayConnectSourceFromMultiaddr(relay, false, isValidPeerId),
    ).toBe(expected);
  });

  it('rejects an invalid local-development relay', () => {
    expect(() =>
      relayConnectSourceFromMultiaddr(
        `/ip4/999.0.0.1/tcp/9001/ws/p2p/${validPeerId}`,
        false,
        isValidPeerId,
      ),
    ).toThrow(/Relay configuration requires/);
  });

  it.each(['relay.\u212Aexample.com', 'relay.\u017Fexample.com'])(
    'rejects a non-ASCII hostname: %s',
    (host) => {
      expect(() =>
        relayConnectSourceFromMultiaddr(
          `/dns4/${host}/tcp/9001/ws/p2p/${validPeerId}`,
          false,
          isValidPeerId,
        ),
      ).toThrow(/Relay configuration requires/);
    },
  );

  it.each([
    `/dns4/-relay.example.com/tcp/443/wss/p2p/${validPeerId}`,
    `/dns4/relay.example.com;/tcp/443/wss/p2p/${validPeerId}`,
    `/dns4/relay.example.com/tcp/80/wss/p2p/${validPeerId}`,
    `/dns4/relay.example.com/tcp/443/ws/p2p/${validPeerId}`,
    '/dns4/relay.example.com/tcp/443/wss/p2p/x',
  ])('rejects an unsafe or incomplete relay multiaddr: %s', (relay) => {
    expect(() =>
      relayConnectSourceFromMultiaddr(relay, true, isValidPeerId),
    ).toThrow(/Deployment requires/);
  });

  it('pins the rendered CSP to the configured relay host', () => {
    const rendered = renderPagesHeaders(
      "connect-src 'self' __PEERBORNE_RELAY_CONNECT_SOURCE__; __PEERBORNE_UPGRADE_INSECURE_REQUESTS__",
      'wss://relay.example.com',
    );
    expect(rendered).toBe(
      "connect-src 'self' wss://relay.example.com; upgrade-insecure-requests",
    );
  });

  it('omits insecure-request upgrades for a local WS relay', () => {
    const rendered = renderPagesHeaders(
      "connect-src 'self' __PEERBORNE_RELAY_CONNECT_SOURCE__; __PEERBORNE_UPGRADE_INSECURE_REQUESTS__",
      'ws://127.0.0.1:9001',
    );
    expect(rendered).toBe("connect-src 'self' ws://127.0.0.1:9001; ");
  });

  it('fails closed when the headers template loses its relay placeholder', () => {
    expect(() =>
      renderPagesHeaders("connect-src 'self'", 'relay.example.com'),
    ).toThrow(/no relay connect-source placeholder/);
  });
});
