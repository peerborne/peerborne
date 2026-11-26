import { describe, expect, jest, test } from '@jest/globals';
import type { Libp2p } from '@libp2p/interface';
import { reuseLimitedConnections } from './limited-connection-reuse.js';

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

const VALUED = new Set(['ip4', 'tcp', 'p2p']);
const RELAY = '/ip4/127.0.0.1/tcp/4001/ws/p2p/relay';

function address(text: string) {
  const parts = text.split('/').filter(Boolean);
  const components: { name: string; value?: string }[] = [];
  for (let index = 0; index < parts.length; index++) {
    const name = parts[index]!;
    components.push(
      VALUED.has(name) ? { name, value: parts[++index] } : { name },
    );
  }
  return { kind: 'multiaddr', getComponents: () => components };
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

function node(
  connections: ReturnType<typeof connection>[],
  addresses: string[] = [`${RELAY}/p2p-circuit/p2p/peer-a`],
) {
  const dialed = { dialed: true };
  const dialProtocol = jest.fn(async () => dialed as unknown);
  const libp2p = {
    dialProtocol,
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
  reuseLimitedConnections(libp2p as unknown as Libp2p);
  const dial = (target: unknown, options: Record<string, unknown> = {}) =>
    (libp2p as unknown as Libp2p).dialProtocol(
      target as never,
      ['/ipfs/bitswap/1.2.0'],
      options,
    );
  return { dial, dialProtocol, dialed };
}

const limitedOnly = { runOnLimitedConnection: true };

describe('limited connection reuse', () => {
  test('opens the stream on the oldest open relayed connection of a relay-only peer', async () => {
    const newer = connection('peer-a', { opened: 2 });
    const older = connection('peer-a', { opened: 1 });
    const { dial, dialProtocol } = node([newer, older]);

    await expect(dial(peer('peer-a'), limitedOnly)).resolves.toBe(older.stream);

    expect(older.newStream).toHaveBeenCalledWith(
      ['/ipfs/bitswap/1.2.0'],
      limitedOnly,
    );
    expect(newer.newStream).not.toHaveBeenCalled();
    expect(dialProtocol).not.toHaveBeenCalled();
  });

  test('reuses the relayed connection for a relay-only multiaddr', async () => {
    const other = connection('peer-b');
    const relayed = connection('peer-a');
    const { dial, dialProtocol } = node([other, relayed]);

    await expect(
      dial(address(`${RELAY}/p2p-circuit/p2p/peer-a`), limitedOnly),
    ).resolves.toBe(relayed.stream);

    expect(other.newStream).not.toHaveBeenCalled();
    expect(dialProtocol).not.toHaveBeenCalled();
  });

  test.each([
    ['limited connections are not accepted', {}],
    ['the dial is forced', { runOnLimitedConnection: true, force: true }],
  ])('leaves the dial to libp2p when %s', async (_, options) => {
    const relayed = connection('peer-a');
    const { dial, dialProtocol, dialed } = node([relayed]);

    await expect(dial(peer('peer-a'), options)).resolves.toBe(dialed);

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
    const { dial, dialProtocol, dialed } = node(connections);
    const target =
      reason === 'the target has no peer ID'
        ? address(`${RELAY}/p2p-circuit`)
        : peer('peer-a');

    await expect(dial(target, limitedOnly)).resolves.toBe(dialed);

    for (const { newStream } of connections) {
      expect(newStream).not.toHaveBeenCalled();
    }
    expect(dialProtocol).toHaveBeenCalledTimes(1);
  });

  test.each([
    ['a WebRTC address', `${RELAY}/p2p-circuit/webrtc/p2p/peer-a`],
    ['a direct address', '/ip4/192.0.2.1/tcp/4001/ws/p2p/peer-a'],
  ])('lets libp2p try to upgrade a peer with %s', async (_, upgrade) => {
    const relayed = connection('peer-a');
    const { dial, dialProtocol, dialed } = node(
      [relayed],
      [`${RELAY}/p2p-circuit/p2p/peer-a`, upgrade],
    );

    await expect(dial(peer('peer-a'), limitedOnly)).resolves.toBe(dialed);

    expect(dialProtocol).toHaveBeenCalledTimes(1);
    expect(relayed.newStream).not.toHaveBeenCalled();
  });

  test('falls back to the relayed connection and stops upgrading it when the upgrade dial fails', async () => {
    const relayed = connection('peer-a');
    const { dial, dialProtocol } = node(
      [relayed],
      [`${RELAY}/p2p-circuit/webrtc/p2p/peer-a`],
    );
    dialProtocol.mockRejectedValueOnce(new Error('WebRTC dial timed out'));

    await expect(dial(peer('peer-a'), limitedOnly)).resolves.toBe(
      relayed.stream,
    );
    await expect(dial(peer('peer-a'), limitedOnly)).resolves.toBe(
      relayed.stream,
    );

    expect(dialProtocol).toHaveBeenCalledTimes(1);
    expect(relayed.newStream).toHaveBeenCalledTimes(2);
  });

  test('tries the upgrade again over a new relayed connection', async () => {
    const first = connection('peer-a', { opened: 1 });
    const connections = [first];
    const { dial, dialProtocol, dialed } = node(connections, [
      `${RELAY}/p2p-circuit/webrtc/p2p/peer-a`,
    ]);
    dialProtocol.mockRejectedValueOnce(new Error('WebRTC dial timed out'));
    await dial(peer('peer-a'), limitedOnly);
    first.status = 'closed';
    connections.push(connection('peer-a', { opened: 2 }));

    await expect(dial(peer('peer-a'), limitedOnly)).resolves.toBe(dialed);
    expect(dialProtocol).toHaveBeenCalledTimes(2);
  });

  test('keeps the upgrade error after the caller aborts', async () => {
    const relayed = connection('peer-a');
    const { dial, dialProtocol } = node(
      [relayed],
      [`${RELAY}/p2p-circuit/webrtc/p2p/peer-a`],
    );
    const failure = new Error('aborted');
    dialProtocol.mockRejectedValueOnce(failure);
    const controller = new AbortController();
    controller.abort();

    await expect(
      dial(peer('peer-a'), { ...limitedOnly, signal: controller.signal }),
    ).rejects.toBe(failure);
    expect(relayed.newStream).not.toHaveBeenCalled();
  });

  test('dials again when the relayed connection closes while opening the stream', async () => {
    const relayed = connection('peer-a');
    relayed.newStream.mockImplementationOnce(async () => {
      relayed.status = 'closed';
      throw new Error('connection closed');
    });
    const { dial, dialProtocol, dialed } = node([relayed]);

    await expect(dial(peer('peer-a'), limitedOnly)).resolves.toBe(dialed);
    expect(dialProtocol).toHaveBeenCalledTimes(1);
  });

  test('keeps a stream error from a relayed connection that stays open', async () => {
    const relayed = connection('peer-a');
    const failure = new Error('protocol selection failed');
    relayed.newStream.mockRejectedValueOnce(failure);
    const { dial, dialProtocol } = node([relayed]);

    await expect(dial(peer('peer-a'), limitedOnly)).rejects.toBe(failure);
    expect(dialProtocol).not.toHaveBeenCalled();
  });
});
