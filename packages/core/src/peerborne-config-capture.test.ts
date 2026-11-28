import { afterEach, describe, expect, jest, test } from '@jest/globals';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('libp2p', () => ({}), { virtual: true });
jest.mock('@libp2p/peer-id', () => ({ peerIdFromString: jest.fn() }), {
  virtual: true,
});
jest.mock(
  '@multiformats/multiaddr',
  () => ({ multiaddr: jest.fn((value: string) => value) }),
  { virtual: true },
);
jest.mock('./peerborne-config.js', () => ({
  defaultBootstrapConfig: jest.fn(),
  defaultConfig: jest.fn(),
}));
jest.mock('./peerborne-document.js', () => ({
  PeerborneDocument: class {},
}));
jest.mock('./helia-node.js', () => ({
  createAndStartHeliaNode: jest.fn(),
}));

import { Peerborne } from './peerborne.js';
import { createAndStartHeliaNode } from './helia-node.js';
import type { PeerborneConfig } from './peerborne-config.js';

function started() {
  const peerborne = new Peerborne(
    { id: 'private' },
    { id: 'public' },
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
  );
  (peerborne as any)._registerSharedProtocolHandlers = async () => {};
  jest.mocked(createAndStartHeliaNode).mockResolvedValue({
    heliaNode: {
      libp2p: { addEventListener: jest.fn(), peerId: 'peer' },
      stop: jest.fn(async () => {}),
    },
    openedStores: [],
  } as never);
  return peerborne;
}

function config(fields: Partial<PeerborneConfig> = {}): PeerborneConfig {
  return { helia: {}, pubsubDocumentPrefix: '/peerborne', ...fields };
}

describe('configuration captured by initialize()', () => {
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
  afterEach(() => {
    warn.mockClear();
    jest.mocked(createAndStartHeliaNode).mockReset();
  });

  test('mutating the caller object after initialize() changes no security setting', async () => {
    const peerborne = started();
    const supplied = config({
      enableTopicValidators: true,
      loadQuorumK: 3,
      compaction: { enabled: true },
      antiEntropy: { enabled: true },
    });
    await peerborne.initialize(supplied);

    supplied.enableSigning = false;
    supplied.enableTopicValidators = false;
    supplied.loadQuorumEnabled = false;
    supplied.loadQuorumK = 1;
    supplied.loadQuorumAllowSinglePeer = true;
    supplied.allowLocalNetworkDials = true;
    supplied.compaction!.enabled = false;
    supplied.antiEntropy!.enabled = false;

    expect(peerborne.config).toEqual(
      expect.objectContaining({
        enableTopicValidators: true,
        loadQuorumK: 3,
        compaction: { enabled: true },
        antiEntropy: { enabled: true },
      }),
    );
    expect(peerborne.config?.enableSigning).toBeUndefined();
    expect(peerborne.config?.loadQuorumEnabled).toBeUndefined();
    expect(peerborne.config?.loadQuorumAllowSinglePeer).toBeUndefined();
    expect(peerborne.config?.allowLocalNetworkDials).toBeUndefined();
  });

  test('the captured configuration cannot be changed in place', async () => {
    const peerborne = started();
    await peerborne.initialize(config({ compaction: { enabled: true } }));
    const captured = peerborne.config!;

    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.compaction)).toBe(true);
    expect(Reflect.set(captured, 'enableSigning', false)).toBe(false);
    expect(Reflect.set(captured, 'enableTopicValidators', true)).toBe(false);
    expect(Reflect.set(captured, 'loadQuorumEnabled', false)).toBe(false);
    expect(Reflect.set(captured.compaction!, 'enabled', false)).toBe(false);
    expect(captured.enableSigning).toBeUndefined();
    expect(captured.compaction).toEqual({ enabled: true });
  });

  test('passes the caller helia options and the local-network upgrade opt-in to the node', async () => {
    const helia = {};
    await started().initialize(config({ helia }));
    expect(createAndStartHeliaNode).toHaveBeenLastCalledWith(helia, {
      allowLocalNetworkUpgrades: false,
    });

    await started().initialize(config({ allowLocalNetworkDials: true }));
    expect(createAndStartHeliaNode).toHaveBeenLastCalledWith(
      {},
      { allowLocalNetworkUpgrades: true },
    );
  });

  test('warns once per initialization when signing or the load quorum is disabled', async () => {
    await started().initialize(config());
    expect(warn).not.toHaveBeenCalled();

    await started().initialize(
      config({ enableSigning: false, loadQuorumEnabled: false }),
    );
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls.map(([message]) => message)).toEqual([
      expect.stringMatching(/enableSigning is false/),
      expect.stringMatching(/loadQuorumEnabled is false/),
    ]);
  });

  test('validates the captured copy', async () => {
    const supplied = config();
    let reads = 0;
    Object.defineProperty(supplied, 'loadQuorumK', {
      enumerable: true,
      get: () => (reads++ === 0 ? 3 : 1.5),
    });
    const peerborne = started();
    await peerborne.initialize(supplied);
    expect(peerborne.config?.loadQuorumK).toBe(3);
  });
});
