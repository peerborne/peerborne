import { beforeEach, describe, expect, jest, test } from '@jest/globals';
import { createHelia, createHeliaLight } from 'helia';
import { withBitswap } from '@helia/bitswap';
import { withLibp2pLight } from '@helia/libp2p';
import { isLibp2p } from 'libp2p';
import type { PeerborneConfig } from './peerborne-config.js';
import { createAndStartHeliaNode } from './helia-node.js';

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

interface FakeHeliaNode {
  start: jest.Mock<() => Promise<void>>;
  stop: jest.Mock<() => Promise<void>>;
  libp2p: { services: { pubsub?: object } };
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
  });

  test('stops the node and closes stores when startup fails', async () => {
    const failure = new Error('synthetic start failure');
    const node: FakeHeliaNode = {
      start: jest.fn(async () => {
        throw failure;
      }),
      stop: jest.fn(async () => undefined),
      libp2p: { services: { pubsub: {} } },
    };
    const { helia, datastore, blockstore } = createConfig();
    arrangeNode(node);

    await expect(createAndStartHeliaNode(helia)).rejects.toBe(failure);

    const lightOptions = mockCreateHeliaLight.mock.calls[0]?.[0];
    expect(lightOptions?.codecs).toHaveLength(3);
    expect(lightOptions?.hashers).toHaveLength(1);
    expect(node.stop).toHaveBeenCalledTimes(1);
    expect(blockstore.close).toHaveBeenCalledTimes(1);
    expect(datastore.close).toHaveBeenCalledTimes(1);
  });

  test('stops the node and closes stores when pubsub is absent', async () => {
    const node: FakeHeliaNode = {
      start: jest.fn(async () => undefined),
      stop: jest.fn(async () => undefined),
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
      libp2p: { services: { pubsub: {} } },
    };
    const bitswap = {};
    mockCreateHelia.mockReturnValue(node as never);

    const result = await createAndStartHeliaNode({
      bitswap,
    } as NonNullable<PeerborneConfig['helia']>);

    expect(mockCreateHelia).toHaveBeenCalledWith({ bitswap });
    expect(result.heliaNode).toBe(node);
    expect(result.openedLegacyStores).toEqual([]);
  });

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
