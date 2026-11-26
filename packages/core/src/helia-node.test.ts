import { beforeEach, describe, expect, jest, test } from '@jest/globals';
import { createHelia, createHeliaLight } from 'helia';
import { withBitswap } from '@helia/bitswap';
import { withLibp2pLight } from '@helia/libp2p';
import { isLibp2p } from 'libp2p';
import type { PeerborneConfig } from './peerborne-config.js';
import { createAndStartHeliaNode } from './helia-node.js';
import { acquirePeerIdentity } from './peer-identity.js';
import { reuseLimitedConnections } from './limited-connection-reuse.js';

jest.mock(
  'helia',
  () => ({
    createHelia: jest.fn(),
    createHeliaLight: jest.fn(),
  }),
  { virtual: true },
);
jest.mock(
  '@helia/bitswap',
  () => ({ withBitswap: jest.fn() }),
  { virtual: true },
);
jest.mock(
  '@helia/libp2p',
  () => ({ withLibp2pLight: jest.fn() }),
  { virtual: true },
);
jest.mock('./peer-identity.js', () => ({ acquirePeerIdentity: jest.fn() }));
jest.mock('./limited-connection-reuse.js', () => ({
  reuseLimitedConnections: jest.fn(),
}));
jest.mock('@ipld/dag-cbor', () => ({}), { virtual: true });
jest.mock('@ipld/dag-json', () => ({}), { virtual: true });
jest.mock('multiformats/codecs/json', () => ({}), { virtual: true });
jest.mock('multiformats/hashes/sha2', () => ({ sha512: {} }), {
  virtual: true,
});
jest.mock('libp2p', () => ({ isLibp2p: jest.fn() }), { virtual: true });

const mockCreateHelia = jest.mocked(createHelia);
const mockCreateHeliaLight = jest.mocked(createHeliaLight);
const mockWithBitswap = jest.mocked(withBitswap);
const mockWithLibp2pLight = jest.mocked(withLibp2pLight);
const mockIsLibp2p = jest.mocked(isLibp2p);
const mockAcquirePeerIdentity = jest.mocked(acquirePeerIdentity);
const mockReuseLimitedConnections = jest.mocked(reuseLimitedConnections);
const generatedKey = { type: 'Ed25519' } as never;
const release = jest.fn();

interface FakeHeliaNode {
  start: jest.Mock<() => Promise<void>>;
  stop: jest.Mock<() => Promise<void>>;
  addMixin: jest.Mock;
  routing: { cancelReprovide: (key: unknown) => Promise<void> };
  libp2p: { services: { pubsub?: object } };
}

function fakeRouting(failure?: Error) {
  return {
    cancelReprovide: jest.fn(async (_key: unknown) => {
      if (failure) throw failure;
    }),
  };
}

function arrangeNode(node: FakeHeliaNode) {
  mockCreateHeliaLight.mockReturnValue(node as never);
  mockWithLibp2pLight.mockReturnValue(node as never);
  mockWithBitswap.mockReturnValue(node as never);
}

function createConfig() {
  const datastore = {
    open: jest.fn(async () => undefined),
    close: jest.fn(async () => undefined),
  };
  const blockstore = {
    open: jest.fn(async () => undefined),
    close: jest.fn(async () => undefined),
  };
  const helia = {
    datastore,
    blockstore,
    libp2p: {},
  } as unknown as NonNullable<PeerborneConfig['helia']>;

  return { helia, datastore, blockstore };
}

describe('Helia node startup cleanup', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockIsLibp2p.mockReturnValue(false);
    mockAcquirePeerIdentity.mockResolvedValue({
      privateKey: generatedKey,
      release,
    });
  });

  test('stops the node and closes stores when startup fails', async () => {
    const failure = new Error('synthetic start failure');
    const node: FakeHeliaNode = {
      start: jest.fn(async () => {
        throw failure;
      }),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia, datastore, blockstore } = createConfig();
    arrangeNode(node);

    await expect(createAndStartHeliaNode(helia)).rejects.toBe(failure);

    const lightOptions = mockCreateHeliaLight.mock.calls[0]?.[0];
    expect(lightOptions?.codecs).toHaveLength(3);
    expect(lightOptions?.hashers).toHaveLength(1);
    expect(node.stop).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalled();
    expect(blockstore.close).toHaveBeenCalledTimes(1);
    expect(datastore.close).toHaveBeenCalledTimes(1);
  });

  test('stops the node and closes stores when pubsub is absent', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: {} },
    };
    const { helia, datastore, blockstore } = createConfig();
    arrangeNode(node);

    await expect(createAndStartHeliaNode(helia)).rejects.toThrow(
      'Helia node must be initialized with a pubsub service (e.g., gossipsub)',
    );

    expect(node.stop).toHaveBeenCalledTimes(1);
    expect(blockstore.close).toHaveBeenCalledTimes(1);
    expect(datastore.close).toHaveBeenCalledTimes(1);
  });

  test('forwards Bitswap options when using Helia defaults', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const bitswap = {};
    mockCreateHelia.mockReturnValue(node as never);

    const result = await createAndStartHeliaNode({
      bitswap,
    } as NonNullable<PeerborneConfig['helia']>);

    expect(mockCreateHelia).toHaveBeenCalledWith({
      libp2p: { privateKey: generatedKey },
      bitswap: { runOnLimitedConnections: true },
    });
    expect(result.heliaNode).toBe(node);
    expect(result.openedStores).toEqual([]);
  });

  test('keeps an explicit Bitswap limited-connection setting', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    mockCreateHelia.mockReturnValue(node as never);

    await createAndStartHeliaNode({
      bitswap: { runOnLimitedConnections: false },
    } as NonNullable<PeerborneConfig['helia']>);

    expect(mockCreateHelia).toHaveBeenCalledWith({
      libp2p: { privateKey: generatedKey },
      bitswap: { runOnLimitedConnections: false },
    });
  });

  test('reuses relayed connections on the started libp2p node', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia } = createConfig();
    arrangeNode(node);

    await createAndStartHeliaNode(helia);

    expect(mockReuseLimitedConnections).toHaveBeenCalledWith(
      node.libp2p,
      undefined,
    );
    expect(node.start.mock.invocationCallOrder[0]).toBeLessThan(
      mockReuseLimitedConnections.mock.invocationCallOrder[0]!,
    );
  });

  test('passes the local-network upgrade opt-in to relayed connection reuse', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia } = createConfig();
    arrangeNode(node);

    await createAndStartHeliaNode(helia, { allowLocalNetworkUpgrades: true });

    expect(mockReuseLimitedConnections).toHaveBeenCalledWith(node.libp2p, {
      allowLocalNetworkUpgrades: true,
    });
  });

  test('loads the persisted key while holding the datastore identity', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia, datastore } = createConfig();
    mockAcquirePeerIdentity.mockResolvedValue({ release });
    arrangeNode(node);

    await createAndStartHeliaNode(helia);

    expect(mockAcquirePeerIdentity).toHaveBeenCalledWith(datastore);
    expect(mockWithLibp2pLight.mock.calls[0]?.[1]?.privateKey).toBeUndefined();
    expect(node.addMixin).toHaveBeenCalledWith({
      name: 'peerborne-peer-identity',
      stop: release,
    });
    expect(release).not.toHaveBeenCalled();
  });

  test('starts libp2p with a fresh key when another instance holds the identity', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia } = createConfig();
    arrangeNode(node);

    await createAndStartHeliaNode(helia);

    expect(mockWithLibp2pLight.mock.calls[0]?.[1]).toEqual({
      privateKey: generatedKey,
    });
    expect(helia.libp2p).toEqual({});
  });

  test('keeps a configured libp2p private key', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
      addMixin: jest.fn(),
      routing: fakeRouting(),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia } = createConfig();
    const privateKey = { type: 'Ed25519' } as never;
    helia.libp2p = { privateKey };
    arrangeNode(node);

    await createAndStartHeliaNode(helia);

    expect(mockAcquirePeerIdentity).not.toHaveBeenCalled();
    expect(mockWithLibp2pLight.mock.calls[0]?.[1]?.privateKey).toBe(privateKey);
    expect(node.addMixin).not.toHaveBeenCalled();
  });

  test.each([
    ['NoContentRoutersError', true],
    ['AbortError', false],
  ])(
    'deletion tolerates a %s from cancelling a reprovide: %s',
    async (name, tolerated) => {
      const failure = Object.assign(new Error('synthetic routing failure'), {
        name,
      });
      const routing = fakeRouting(failure);
      const cancel = routing.cancelReprovide;
      const node: FakeHeliaNode = {
        start: jest.fn(async () => undefined),
        stop: jest.fn(async () => undefined),
        addMixin: jest.fn(),
        routing,
        libp2p: { services: { pubsub: {} } },
      };
      const { helia } = createConfig();
      arrangeNode(node);

      await createAndStartHeliaNode(helia);

      const cancelling = node.routing.cancelReprovide('cid');
      if (tolerated) await expect(cancelling).resolves.toBeUndefined();
      else await expect(cancelling).rejects.toBe(failure);
      expect(cancel).toHaveBeenCalledWith('cid', undefined);
    },
  );

  test('rejects an already-created libp2p node explicitly', async () => {
    mockIsLibp2p.mockReturnValue(true);

    await expect(createAndStartHeliaNode({
      libp2p: {},
    } as NonNullable<PeerborneConfig['helia']>)).rejects.toThrow(
      'Helia 7 requires libp2p creation options; preconfigured libp2p nodes are not supported',
    );

    expect(mockCreateHeliaLight).not.toHaveBeenCalled();
  });
});
