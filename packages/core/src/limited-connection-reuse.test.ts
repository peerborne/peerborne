import { describe, expect, jest, test } from '@jest/globals';
import type { Libp2p } from '@libp2p/interface';
import { reuseLimitedConnections } from './limited-connection-reuse.js';
import type { LimitedConnectionReuseOptions } from './limited-connection-reuse.js';

jest.mock(
  '@libp2p/interface',
  () => ({ isPeerId: (value: { kind?: string }) => value?.kind === 'peer' }),
  { virtual: true },
);
jest.mock(
  '@multiformats/multiaddr',
  () => ({
    isMultiaddr: (value: { kind?: string }) => value?.kind === 'multiaddr',
  }),
  { virtual: true },
);

jest.mock(
  '@libp2p/utils',
  () => ({
    isPrivateIp: (ip: string) => /^(?:127|10|192\.168|169\.254)\./u.test(ip),
  }),
  { virtual: true },
);

const VALUED = new Set(['ip4', 'tcp', 'p2p']);
const RELAY = '/ip4/93.184.215.14/tcp/4001/ws/p2p/relay';
const CIRCUIT = `${RELAY}/p2p-circuit/p2p/peer-a`;
const WEBRTC = `${RELAY}/p2p-circuit/webrtc/p2p/peer-a`;
const DIRECT = '/ip4/93.184.215.15/tcp/4001/ws/p2p/peer-a';
const LOCAL_RELAY = '/ip4/127.0.0.1/tcp/4001/ws/p2p/relay';
const LOCAL = [
  '/ip4/127.0.0.1/tcp/4001/ws/p2p/peer-a',
  '/ip4/192.168.1.20/tcp/4001/ws/p2p/peer-a',
  '/ip4/169.254.169.254/tcp/80/ws/p2p/peer-a',
  `${LOCAL_RELAY}/p2p-circuit/webrtc/p2p/peer-a`,
];

interface FakeAddress {
  kind: 'multiaddr';
  text: string;
  getComponents(): { name: string; value?: string }[];
  encapsulate(suffix: string): FakeAddress;
}

function address(text: string): FakeAddress {
  const parts = text.split('/').filter(Boolean);
  const components: { name: string; value?: string }[] = [];
  for (let index = 0; index < parts.length; index++) {
    const name = parts[index]!;
    components.push(
      VALUED.has(name) ? { name, value: parts[++index] } : { name },
    );
  }
  return {
    kind: 'multiaddr',
    text,
    getComponents: () => components,
    encapsulate: (suffix) => address(`${text}${suffix}`),
  };
}

const peer = (id: string) => ({ kind: 'peer', toString: () => id });

function connection(
  remote: string,
  { limited = true, opened = 1, status = 'open' } = {},
) {
  const stream = { connection: remote, opened };
  return {
    remotePeer: peer(remote),
    status,
    limits: limited ? { bytes: 1n } : undefined,
    timeline: { open: opened },
    stream,
    newStream: jest.fn(async () => stream),
  };
}

type FakeConnection = ReturnType<typeof connection>;

function node(
  connections: FakeConnection[],
  addresses: string[] = [CIRCUIT],
  options?: LimitedConnectionReuseOptions,
) {
  const dialed = { dialed: true };
  const dialProtocol = jest.fn(async () => dialed as unknown);
  const upgradeDial = jest.fn(async () => connections[0] as unknown);
  const isDialable = jest.fn(async () => true);
  const libp2p = {
    dial: upgradeDial,
    dialProtocol,
    isDialable,
    getConnections: (target?: { toString(): string }) =>
      connections.filter(
        ({ remotePeer }) =>
          target === undefined || remotePeer.toString() === target.toString(),
      ),
    peerStore: {
      get: jest.fn(async () => ({
        addresses: addresses.map((text) => ({ multiaddr: address(text) })),
      })),
    },
  };
  reuseLimitedConnections(libp2p as unknown as Libp2p, options);
  const open = async (
    target: unknown,
    options: Record<string, unknown> = {},
  ) => {
    const stream = await (libp2p as unknown as Libp2p).dialProtocol(
      target as never,
      ['/ipfs/bitswap/1.2.0'],
      options,
    );
    await new Promise((resolve) => setImmediate(resolve));
    return stream;
  };
  return { open, dialProtocol, upgradeDial, isDialable, dialed };
}

const limitedOnly = { runOnLimitedConnection: true };

describe('limited connection reuse', () => {
  test('opens the stream on the oldest open relayed connection of a relay-only peer', async () => {
    const newer = connection('peer-a', { opened: 2 });
    const older = connection('peer-a', { opened: 1 });
    const { open, dialProtocol, upgradeDial } = node([newer, older]);

    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(older.stream);

    expect(older.newStream).toHaveBeenCalledWith(
      ['/ipfs/bitswap/1.2.0'],
      limitedOnly,
    );
    expect(newer.newStream).not.toHaveBeenCalled();
    expect(dialProtocol).not.toHaveBeenCalled();
    expect(upgradeDial).not.toHaveBeenCalled();
  });

  test('reuses the relayed connection for a relay-only multiaddr', async () => {
    const other = connection('peer-b');
    const relayed = connection('peer-a');
    const { open, dialProtocol, upgradeDial } = node([other, relayed]);

    await expect(open(address(CIRCUIT), limitedOnly)).resolves.toBe(
      relayed.stream,
    );

    expect(other.newStream).not.toHaveBeenCalled();
    expect(dialProtocol).not.toHaveBeenCalled();
    expect(upgradeDial).not.toHaveBeenCalled();
  });

  test.each([
    ['limited connections are not accepted', {}],
    ['the dial is forced', { runOnLimitedConnection: true, force: true }],
  ])('leaves the dial to libp2p when %s', async (_, options) => {
    const relayed = connection('peer-a');
    const { open, dialProtocol, dialed } = node([relayed]);

    await expect(open(peer('peer-a'), options)).resolves.toBe(dialed);

    expect(relayed.newStream).not.toHaveBeenCalled();
    expect(dialProtocol).toHaveBeenCalledTimes(1);
  });

  test.each([
    [
      'an unlimited connection is open',
      [connection('peer-a', { limited: false }), connection('peer-a')],
    ],
    ['no connection is open', [connection('peer-a', { status: 'closing' })]],
    ['the target has no peer ID', [connection('peer-a')]],
  ])('leaves the dial to libp2p when %s', async (reason, connections) => {
    const { open, dialProtocol, dialed } = node(connections);
    const target =
      reason === 'the target has no peer ID'
        ? address(`${RELAY}/p2p-circuit`)
        : peer('peer-a');

    await expect(open(target, limitedOnly)).resolves.toBe(dialed);

    for (const { newStream } of connections) {
      expect(newStream).not.toHaveBeenCalled();
    }
    expect(dialProtocol).toHaveBeenCalledTimes(1);
  });

  test.each([
    ['a WebRTC address', WEBRTC],
    ['a direct address', DIRECT],
  ])(
    'opens the stream at once and upgrades a peer with %s in the background',
    async (_, upgrade) => {
      const relayed = connection('peer-a');
      const target = peer('peer-a');
      const { open, dialProtocol, upgradeDial, isDialable } = node(
        [relayed],
        [CIRCUIT, upgrade],
      );

      await expect(open(target, limitedOnly)).resolves.toBe(relayed.stream);

      expect(isDialable).toHaveBeenCalledWith([
        expect.objectContaining({ text: upgrade }),
      ]);
      expect(upgradeDial).toHaveBeenCalledWith([
        expect.objectContaining({ text: upgrade }),
      ]);
      expect(dialProtocol).not.toHaveBeenCalled();
    },
  );

  test('names the peer in an upgrade address from the peer store', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial } = node(
      [relayed],
      [CIRCUIT, '/ip4/93.184.215.15/tcp/4001/ws'],
    );

    await open(peer('peer-a'), limitedOnly);

    expect(upgradeDial).toHaveBeenCalledWith([
      expect.objectContaining({ text: DIRECT }),
    ]);
  });

  test('does not upgrade to loopback, private, link-local or locally relayed addresses', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial, isDialable } = node(
      [relayed],
      [CIRCUIT, ...LOCAL],
    );

    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(
      relayed.stream,
    );

    expect(isDialable).not.toHaveBeenCalled();
    expect(upgradeDial).not.toHaveBeenCalled();
  });

  test('upgrade-dials only the public addresses of a peer', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial, isDialable } = node(
      [relayed],
      [...LOCAL, DIRECT, WEBRTC],
    );

    await open(peer('peer-a'), limitedOnly);

    const expected = [
      expect.objectContaining({ text: DIRECT }),
      expect.objectContaining({ text: WEBRTC }),
    ];
    expect(isDialable).toHaveBeenCalledWith(expected);
    expect(upgradeDial).toHaveBeenCalledWith(expected);
  });

  test('upgrades over local-network addresses when they are allowed', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial } = node([relayed], [CIRCUIT, ...LOCAL], {
      allowLocalNetworkUpgrades: true,
    });

    await open(peer('peer-a'), limitedOnly);

    expect(upgradeDial).toHaveBeenCalledWith(
      LOCAL.map((text) => expect.objectContaining({ text })),
    );
  });

  test('upgrades a relayed connection once when the upgrade dial leaves only limited connections', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial } = node([relayed], [CIRCUIT, WEBRTC]);

    await open(peer('peer-a'), limitedOnly);
    await open(peer('peer-a'), limitedOnly);
    await open(peer('peer-a'), limitedOnly);

    expect(upgradeDial).toHaveBeenCalledTimes(1);
    expect(relayed.newStream).toHaveBeenCalledTimes(3);
  });

  test('starts one upgrade for concurrent streams', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial } = node([relayed], [CIRCUIT, WEBRTC]);

    await Promise.all(
      Array.from({ length: 4 }, () => open(peer('peer-a'), limitedOnly)),
    );

    expect(upgradeDial).toHaveBeenCalledTimes(1);
  });

  test('keeps the stream on the relayed connection when the upgrade dial fails', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial } = node([relayed], [WEBRTC]);
    upgradeDial.mockRejectedValueOnce(new Error('WebRTC dial timed out'));

    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(
      relayed.stream,
    );
    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(
      relayed.stream,
    );
    expect(upgradeDial).toHaveBeenCalledTimes(1);
  });

  test('does not try upgrade addresses this node cannot dial', async () => {
    const relayed = connection('peer-a');
    const { open, upgradeDial, isDialable } = node(
      [relayed],
      [CIRCUIT, DIRECT],
    );
    isDialable.mockResolvedValue(false);

    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(
      relayed.stream,
    );
    expect(upgradeDial).not.toHaveBeenCalled();
  });

  test('upgrades once an upgrade address becomes known', async () => {
    const relayed = connection('peer-a');
    const addresses = [CIRCUIT];
    const { open, upgradeDial } = node([relayed], addresses);

    await open(peer('peer-a'), limitedOnly);
    expect(upgradeDial).not.toHaveBeenCalled();
    addresses.push(WEBRTC);
    await open(peer('peer-a'), limitedOnly);

    expect(upgradeDial).toHaveBeenCalledTimes(1);
  });

  test('uses the unlimited connection once an upgrade succeeds', async () => {
    const relayed = connection('peer-a');
    const connections = [relayed];
    const { open, upgradeDial, dialProtocol, dialed } = node(connections, [
      CIRCUIT,
      WEBRTC,
    ]);
    upgradeDial.mockImplementationOnce(async () => {
      const direct = connection('peer-a', { limited: false, opened: 2 });
      connections.push(direct);
      return direct;
    });

    await open(peer('peer-a'), limitedOnly);

    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(dialed);
    expect(dialProtocol).toHaveBeenCalledTimes(1);
  });

  test('upgrades a new relayed connection again', async () => {
    const first = connection('peer-a', { opened: 1 });
    const connections = [first];
    const { open, upgradeDial } = node(connections, [WEBRTC]);
    await open(peer('peer-a'), limitedOnly);
    first.status = 'closed';
    connections.push(connection('peer-a', { opened: 2 }));

    await open(peer('peer-a'), limitedOnly);

    expect(upgradeDial).toHaveBeenCalledTimes(2);
  });

  test('still dials directly for a stream that needs an unlimited connection', async () => {
    const relayed = connection('peer-a');
    const { open, dialProtocol, upgradeDial, dialed } = node(
      [relayed],
      [WEBRTC],
    );
    await open(peer('peer-a'), limitedOnly);
    const target = peer('peer-a');
    const unlimited = { signal: new AbortController().signal };

    await expect(open(target, unlimited)).resolves.toBe(dialed);
    await expect(open(address(WEBRTC), unlimited)).resolves.toBe(dialed);

    expect(dialProtocol).toHaveBeenNthCalledWith(
      1,
      target,
      ['/ipfs/bitswap/1.2.0'],
      unlimited,
    );
    expect(dialProtocol).toHaveBeenCalledTimes(2);
    expect(upgradeDial).toHaveBeenCalledTimes(1);
    expect(relayed.newStream).toHaveBeenCalledTimes(1);
  });

  test('dials again when the relayed connection closes while opening the stream', async () => {
    const relayed = connection('peer-a');
    relayed.newStream.mockImplementationOnce(async () => {
      relayed.status = 'closed';
      throw new Error('connection closed');
    });
    const { open, dialProtocol, dialed } = node([relayed]);

    await expect(open(peer('peer-a'), limitedOnly)).resolves.toBe(dialed);
    expect(dialProtocol).toHaveBeenCalledTimes(1);
  });

  test('keeps a stream error from a relayed connection that stays open', async () => {
    const relayed = connection('peer-a');
    const failure = new Error('protocol selection failed');
    relayed.newStream.mockRejectedValueOnce(failure);
    const { open, dialProtocol } = node([relayed]);

    await expect(open(peer('peer-a'), limitedOnly)).rejects.toBe(failure);
    expect(dialProtocol).not.toHaveBeenCalled();
  });

  test('keeps the stream error after the caller aborts', async () => {
    const relayed = connection('peer-a');
    const failure = new Error('aborted');
    relayed.newStream.mockImplementationOnce(async () => {
      relayed.status = 'closed';
      throw failure;
    });
    const { open, dialProtocol } = node([relayed]);
    const controller = new AbortController();
    controller.abort();

    await expect(
      open(peer('peer-a'), { ...limitedOnly, signal: controller.signal }),
    ).rejects.toBe(failure);
    expect(dialProtocol).not.toHaveBeenCalled();
  });
});
