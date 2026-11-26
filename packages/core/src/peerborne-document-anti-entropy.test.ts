import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import type { AntiEntropyEvent } from './anti-entropy.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { PeerborneDocument } from './peerborne-document.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: {
      Accept: 'accept',
      Ignore: 'ignore',
      Reject: 'reject',
    },
  }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

type Listener = (event: { detail: unknown }) => void;
const topic = '/topic';

function documentFixture(config: Record<string, unknown> = {}) {
  const listeners = new Map<string, Listener>();
  const pubsub = {
    addEventListener: jest.fn((name: string, listener: Listener) => {
      listeners.set(name, listener);
    }),
    removeEventListener: jest.fn((name: string, listener: Listener) => {
      if (listeners.get(name) === listener) listeners.delete(name);
    }),
    subscribe: jest.fn(),
    unsubscribe: jest.fn(),
    topicValidators: new Map(),
  };
  const publishSyncRequest = jest.fn(async () => 'sent' as const);
  const pending = { value: false };
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/anti-entropy',
    _invitationBootstrapReady: true,
    load: jest.fn(async () => true),
    _hashes: new Set<string>(),
    _computeTopic: () => topic,
    _isSigningEnabled: () => true,
    _mutationQueue: new InvitationMembershipQueue(),
    _antiEntropyHandlers: new Map(),
    _publishSyncRequest: publishSyncRequest,
    _crdtProvider: { hasPendingChanges: () => pending.value },
    swarm: {
      config,
      registerDocument: jest.fn(),
      unregisterDocument: jest.fn(),
      heliaNode: {
        libp2p: {
          peerId: { toString: () => '12D3KooWThisNode' },
          getConnections: () => [],
          services: { pubsub },
        },
      },
    },
  }) as PeerborneDocument<unknown, unknown, unknown, unknown, unknown, unknown>;
  const subscriptionChange = (
    peer: string,
    subscriptions: Array<{ topic: string; subscribe: boolean }>,
  ) =>
    listeners.get('subscription-change')?.({
      detail: { peerId: { toString: () => peer }, subscriptions },
    });
  return {
    document,
    pubsub,
    listeners,
    pending,
    publishSyncRequest,
    subscriptionChange,
  };
}

beforeEach(() => {
  jest.useFakeTimers({ now: 1_700_000_000_000 });
  jest.spyOn(Math, 'random').mockReturnValue(0.5);
});

afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

async function advance(ms: number): Promise<void> {
  await jest.advanceTimersByTimeAsync(ms);
}

test('an opened document requests on open and when a peer subscribes to its topic', async () => {
  const fixture = documentFixture();
  const events: AntiEntropyEvent[] = [];
  fixture.document.subscribeToAntiEntropy('test', (event) =>
    events.push(event),
  );
  await fixture.document.open();
  expect(fixture.listeners.has('subscription-change')).toBe(true);
  expect(fixture.document.antiEntropyStatus).toMatchObject({
    enabled: true,
    running: true,
    requests: 0,
  });
  await advance(1_500);
  expect(fixture.publishSyncRequest).toHaveBeenCalledTimes(1);
  expect(fixture.publishSyncRequest).toHaveBeenCalledWith(false);
  expect(events).toEqual([
    expect.objectContaining({ type: 'request', triggers: ['open'] }),
  ]);

  fixture.subscriptionChange('12D3KooWOtherTopic', [
    { topic: '/other', subscribe: true },
  ]);
  fixture.subscriptionChange('12D3KooWLeaving', [{ topic, subscribe: false }]);
  await advance(45_000);
  expect(fixture.publishSyncRequest).toHaveBeenCalledTimes(2);
  expect(events.at(-1)).toMatchObject({ triggers: ['periodic'] });

  fixture.subscriptionChange('12D3KooWRejoined', [
    { topic: '/other', subscribe: true },
    { topic, subscribe: true },
  ]);
  await advance(5_000);
  expect(fixture.publishSyncRequest).toHaveBeenCalledTimes(3);
  expect(events.at(-1)).toMatchObject({ triggers: ['peer-subscribed'] });
  fixture.document.unsubscribeFromAntiEntropy('test');
  await fixture.document.close();
});

test('closing removes the subscription listener and stops requests', async () => {
  const fixture = documentFixture();
  await fixture.document.open();
  const listener = fixture.listeners.get('subscription-change');
  await fixture.document.close();
  expect(fixture.pubsub.removeEventListener).toHaveBeenCalledWith(
    'subscription-change',
    listener,
  );
  expect(fixture.document.antiEntropyStatus.enabled).toBe(false);
  await advance(120_000);
  expect(fixture.publishSyncRequest).not.toHaveBeenCalled();
});

test('pending CRDT state after applied remote state opens a gap, and loads need the commitment resolver', async () => {
  const fixture = documentFixture({ antiEntropy: { loadAfterMs: 5_000 } });
  await fixture.document.open();
  const antiEntropy = (
    fixture.document as unknown as {
      _antiEntropy: { remoteStateApplied(): void };
    }
  )._antiEntropy;
  await advance(1_500);
  fixture.pending.value = true;
  antiEntropy.remoteStateApplied();
  expect(fixture.document.antiEntropyStatus.gap).toBe(true);
  await advance(6_500);
  expect(fixture.publishSyncRequest).toHaveBeenCalledTimes(2);
  await advance(30_000);
  expect(fixture.document.load).not.toHaveBeenCalled();
  fixture.pending.value = false;
  antiEntropy.remoteStateApplied();
  expect(fixture.document.antiEntropyStatus.gap).toBe(false);
  await fixture.document.close();
});

test('catch-up stays off when disabled, unsigned or without a libp2p identity', async () => {
  const disabled = documentFixture({ antiEntropy: { enabled: false } });
  const unsigned = documentFixture();
  Object.assign(unsigned.document, { _isSigningEnabled: () => false });
  const anonymous = documentFixture();
  Object.assign(anonymous.document.swarm.heliaNode.libp2p, {
    peerId: undefined,
  });
  for (const fixture of [disabled, unsigned, anonymous]) {
    await fixture.document.open();
    expect(fixture.listeners.has('subscription-change')).toBe(false);
    expect(fixture.document.antiEntropyStatus).toEqual({
      enabled: false,
      running: false,
      phase: 'idle',
      gap: false,
      requests: 0,
      loads: 0,
      suppressed: 0,
    });
  }
  await advance(120_000);
  for (const fixture of [disabled, unsigned, anonymous]) {
    expect(fixture.publishSyncRequest).not.toHaveBeenCalled();
    await fixture.document.close();
  }
});

test('a throwing observer does not stop catch-up', async () => {
  const fixture = documentFixture();
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  try {
    fixture.document.subscribeToAntiEntropy('broken', () => {
      throw new Error('observer');
    });
    await fixture.document.open();
    await advance(62_000);
    expect(fixture.publishSyncRequest).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledWith('Anti-entropy handler failed');
  } finally {
    warn.mockRestore();
    await fixture.document.close();
  }
});
