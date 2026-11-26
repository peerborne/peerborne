import { describe, expect, test } from '@jest/globals';
import {
  AntiEntropy,
  AntiEntropyBudget,
  defaultAntiEntropyConfig,
  resolveAntiEntropyConfig,
  type AntiEntropyClock,
  type AntiEntropyConfig,
  type AntiEntropyEvent,
  type AntiEntropyHost,
  type AntiEntropyRequestOutcome,
} from './anti-entropy.js';

const START = 1_000_000;

async function flush(): Promise<void> {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

function fakeClock(random: () => number = () => 0.5) {
  let now = START;
  let next = 0;
  const timers = new Map<number, { at: number; callback: () => void }>();
  const clock: AntiEntropyClock = {
    now: () => now,
    setTimeout(callback, ms) {
      const handle = ++next;
      timers.set(handle, { at: now + ms, callback });
      return handle;
    },
    clearTimeout(handle) {
      timers.delete(handle as number);
    },
    random: () => random(),
  };
  return {
    clock,
    get now() {
      return now - START;
    },
    get timers() {
      return timers.size;
    },
    setRandom(value: () => number) {
      random = value;
    },
    /** Advance to `START + at`, running due timers in order. */
    async to(at: number): Promise<void> {
      const end = START + at;
      for (;;) {
        await flush();
        let due: [number, { at: number; callback: () => void }] | undefined;
        for (const entry of timers)
          if (due === undefined || entry[1].at < due[1].at) due = entry;
        if (due === undefined || due[1].at > end) break;
        timers.delete(due[0]);
        now = Math.max(now, due[1].at);
        due[1].callback();
      }
      now = end;
      await flush();
    },
  };
}

function fakeHost() {
  const state = {
    known: new Set<string>(),
    connected: new Set<string>(),
    pending: false,
    loadable: true,
    outcome: 'sent' as AntiEntropyRequestOutcome,
    load: async (
      _peer: string | undefined,
      _signal: AbortSignal,
    ): Promise<boolean> => true,
    requestTimes: [] as number[],
    loads: [] as Array<{ peer?: string; at: number }>,
    signals: [] as AbortSignal[],
  };
  let clockNow = () => 0;
  const host: AntiEntropyHost = {
    request: async () => {
      state.requestTimes.push(clockNow());
      return state.outcome;
    },
    hasPendingChanges: () => state.pending,
    isKnown: (cid) => state.known.has(cid),
    canLoad: () => state.loadable,
    isConnected: (peer) => state.connected.has(peer),
    load: (peer, signal) => {
      state.loads.push({
        ...(peer === undefined ? {} : { peer }),
        at: clockNow(),
      });
      state.signals.push(signal);
      return state.load(peer, signal);
    },
  };
  return {
    host,
    state,
    bind(now: () => number) {
      clockNow = now;
    },
  };
}

function setup(
  config: Partial<AntiEntropyConfig> = {},
  options: { budget?: AntiEntropyBudget; random?: () => number } = {},
) {
  const time = fakeClock(options.random);
  const fake = fakeHost();
  fake.bind(() => time.now);
  const events: AntiEntropyEvent[] = [];
  const antiEntropy = new AntiEntropy(
    resolveAntiEntropyConfig(config),
    fake.host,
    options.budget ?? new AntiEntropyBudget(),
    (event) => events.push(event),
    time.clock,
  );
  return { time, ...fake, events, antiEntropy };
}

describe('anti-entropy configuration', () => {
  test('defaults to an enabled 30-60 s cycle and rejects malformed options', () => {
    expect(resolveAntiEntropyConfig()).toEqual(defaultAntiEntropyConfig);
    expect(resolveAntiEntropyConfig({ enabled: false }).enabled).toBe(false);
    expect(
      resolveAntiEntropyConfig({
        intervalMs: 3_000,
        minRequestIntervalMs: 2_000,
      }),
    ).toMatchObject({ intervalMs: 3_000, minRequestIntervalMs: 2_000 });
    for (const [value, error] of [
      [null, TypeError],
      [[], TypeError],
      [{ enabled: 'yes' }, TypeError],
      [{ interval: 1_000 }, TypeError],
      [{ intervalMs: 999 }, RangeError],
      [{ intervalMs: 1.5e3 + 0.5 }, RangeError],
      [{ intervalMs: '45000' }, RangeError],
      [{ loadAfterMs: Number.MAX_SAFE_INTEGER }, RangeError],
      [{ minRequestIntervalMs: 1_999 }, RangeError],
      [{ intervalMs: 4_000, minRequestIntervalMs: 5_000 }, RangeError],
    ] as const)
      expect(() =>
        resolveAntiEntropyConfig(value as Partial<AntiEntropyConfig>),
      ).toThrow(error);
  });
});

describe('anti-entropy triggering', () => {
  test('coalesces the open request with signals that arrive while it settles', async () => {
    const { time, state, events, antiEntropy } = setup();
    antiEntropy.start();
    antiEntropy.peerSubscribed('a');
    antiEntropy.peerSubscribed('b');
    antiEntropy.peerSubscribed('a');
    await time.to(999);
    expect(state.requestTimes).toEqual([]);
    await time.to(1_000);
    expect(state.requestTimes).toEqual([1_000]);
    expect(events).toEqual([
      expect.objectContaining({
        type: 'request',
        triggers: ['open', 'peer-subscribed'],
        outcome: 'sent',
      }),
    ]);
    expect(antiEntropy.status()).toMatchObject({
      enabled: true,
      running: true,
      requests: 1,
      suppressed: 2,
      gap: false,
      lastRequestAt: START + 1_000,
      nextRunAt: START + 46_000,
    });
  });

  test('requests when the CRDT waits for dependencies, spacing requests while the gap persists', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    await time.to(1_000);
    state.pending = true;
    antiEntropy.remoteStateApplied();
    antiEntropy.remoteStateApplied();
    await time.to(200_000);
    expect(state.requestTimes).toEqual([
      1_000, 6_000, 16_000, 36_000, 76_000, 121_000, 166_000,
    ]);
    expect(events.filter((event) => event.type === 'gap')).toEqual([
      expect.objectContaining({ trigger: 'pending-changes' }),
    ]);
    state.pending = false;
    antiEntropy.remoteStateApplied();
    expect(events.at(-1)).toMatchObject({ type: 'repaired', afterMs: 199_000 });
    expect(antiEntropy.status().gap).toBe(false);
    await time.to(210_999);
    expect(state.requestTimes).toHaveLength(7);
    await time.to(211_000);
    expect(state.requestTimes.at(-1)).toBe(211_000);
  });

  test('a missing change opens a gap until it is recorded', async () => {
    const { time, state, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    await time.to(1_000);
    antiEntropy.missingChange('bafy-known');
    state.known.add('bafy-known');
    antiEntropy.missingChange('bafy-known');
    antiEntropy.missingChange('bafy-missing');
    await time.to(6_000);
    expect(state.requestTimes).toEqual([1_000, 6_000]);
    expect(antiEntropy.status().gap).toBe(true);
    state.known.add('bafy-missing');
    antiEntropy.remoteStateApplied();
    expect(antiEntropy.status().gap).toBe(false);
  });

  test('one member or peer triggers at most one request per kind of signal within its cooldown', async () => {
    const { time, state, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    await time.to(1_000);
    for (let i = 0; i < 20; i++) antiEntropy.peerSubscribed('flapping');
    await time.to(10_000);
    expect(state.requestTimes).toEqual([1_000, 6_000]);
    expect(antiEntropy.status().suppressed).toBe(19);
    expect(antiEntropy.admitAdvertisement('flapping', 'head')).toBe(true);
    antiEntropy.advertisement('flapping', 'peer-flapping', 'head', true);
    expect(antiEntropy.admitAdvertisement('flapping', 'head')).toBe(false);
    expect(antiEntropy.admitAdvertisement('flapping', 'newer')).toBe(false);
    await time.to(31_000);
    antiEntropy.peerSubscribed('flapping');
    expect(antiEntropy.admitAdvertisement('flapping', 'newer')).toBe(false);
    await time.to(41_000);
    expect(antiEntropy.admitAdvertisement('flapping', 'newer')).toBe(true);
  });

  test('admits at most four advertisement checks at once, refilled at one per two seconds', async () => {
    const { time, state, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    const admitted = Array.from({ length: 10 }, (_, i) =>
      antiEntropy.admitAdvertisement(`peer-${i}`, `head-${i}`),
    );
    expect(admitted.filter(Boolean)).toHaveLength(4);
    expect(antiEntropy.admitAdvertisement('peer-10', 'head-10')).toBe(false);
    await time.to(2_000);
    expect(antiEntropy.admitAdvertisement('peer-11', 'head-11')).toBe(true);
    expect(antiEntropy.admitAdvertisement('peer-12', 'head-12')).toBe(false);
    state.known.add('known');
    expect(antiEntropy.admitAdvertisement('peer-13', 'known')).toBe(false);
  });

  test('periodic requests are jittered across two thirds to four thirds of the interval', async () => {
    const draws = [0, 0.999, 0.25, 0, 0.75];
    let index = 0;
    const { time, state, antiEntropy } = setup(
      {},
      { random: () => draws[index++ % draws.length]! },
    );
    antiEntropy.start();
    await time.to(1_000_000);
    const gaps = state.requestTimes
      .slice(1)
      .map((at, i) => at - state.requestTimes[i]!);
    expect(gaps.length).toBeGreaterThan(15);
    for (const gap of gaps) {
      expect(gap).toBeGreaterThanOrEqual(30_000);
      expect(gap).toBeLessThanOrEqual(60_000);
    }
    expect(new Set(gaps).size).toBeGreaterThan(1);
  });

  test("another member's equivalent request postpones one periodic request per interval", async () => {
    const { time, state, antiEntropy } = setup();
    antiEntropy.start();
    await time.to(1_000);
    await time.to(40_000);
    antiEntropy.equivalentRequest();
    antiEntropy.equivalentRequest();
    await time.to(84_999);
    expect(state.requestTimes).toEqual([1_000]);
    await time.to(85_000);
    expect(state.requestTimes).toEqual([1_000, 85_000]);
    expect(antiEntropy.status().suppressed).toBe(1);
    state.pending = true;
    antiEntropy.remoteStateApplied();
    antiEntropy.equivalentRequest();
    expect(antiEntropy.status().suppressed).toBe(1);
  });

  test('a manual request restarts the periodic delay and counts toward spacing', async () => {
    const { time, state, antiEntropy } = setup();
    antiEntropy.start();
    await time.to(1_000);
    await time.to(20_000);
    antiEntropy.manualRequest();
    antiEntropy.peerSubscribed('a');
    await time.to(24_999);
    expect(state.requestTimes).toEqual([1_000]);
    await time.to(25_000);
    expect(state.requestTimes).toEqual([1_000, 25_000]);
    await time.to(69_999);
    expect(state.requestTimes).toHaveLength(2);
    await time.to(70_000);
    expect(state.requestTimes).toHaveLength(3);
  });

  test('requests that are not ready or fail keep the schedule without counting', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.outcome = 'not-ready';
    antiEntropy.start();
    await time.to(1_000);
    const failing = setup();
    failing.host.request = async () => {
      throw new Error('boom');
    };
    failing.antiEntropy.start();
    await failing.time.to(1_000);
    expect(antiEntropy.status().requests).toBe(0);
    expect(events.at(-1)).toMatchObject({ outcome: 'not-ready' });
    expect(failing.events.at(-1)).toMatchObject({ outcome: 'failed' });
    expect(failing.antiEntropy.status()).toMatchObject({
      requests: 0,
      nextRunAt: START + 46_000,
    });
    await time.to(46_000);
    expect(state.requestTimes).toEqual([1_000, 46_000]);
  });

  test('closing cancels timers, ignores later signals and runs close callbacks once', async () => {
    const { time, state, antiEntropy } = setup();
    let closed = 0;
    antiEntropy.onClose(() => closed++);
    antiEntropy.start();
    antiEntropy.close();
    antiEntropy.close();
    antiEntropy.peerSubscribed('a');
    antiEntropy.missingChange('cid');
    antiEntropy.advertisement('a', 'peer-a', 'head', true);
    antiEntropy.remoteStateApplied();
    await time.to(1_000_000);
    expect(state.requestTimes).toEqual([]);
    expect(time.timers).toBe(0);
    expect(closed).toBe(1);
    antiEntropy.onClose(() => closed++);
    expect(closed).toBe(2);
    expect(antiEntropy.status()).toMatchObject({ running: false, gap: false });
  });

  test('observer failures do not interrupt scheduling', async () => {
    const time = fakeClock();
    const fake = fakeHost();
    fake.bind(() => time.now);
    const antiEntropy = new AntiEntropy(
      resolveAntiEntropyConfig(),
      fake.host,
      new AntiEntropyBudget(),
      () => {
        throw new Error('observer');
      },
      time.clock,
    );
    antiEntropy.start();
    await time.to(47_000);
    expect(fake.state.requestTimes).toEqual([1_000, 46_000]);
  });
});

describe('anti-entropy load escalation', () => {
  test('loads a head two members advertise from its newest connected writer', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.connected = new Set(['reader', 'w1', 'w2']);
    state.load = async () => {
      state.known.add('h1');
      state.known.add('h2');
      return true;
    };
    antiEntropy.start();
    await time.to(1_000);
    await time.to(2_000);
    antiEntropy.advertisement('m-reader', 'reader', 'h1', false);
    antiEntropy.advertisement('m-w1', 'w1', 'h1', true);
    antiEntropy.advertisement('m-w2', 'w2', 'h2', true);
    antiEntropy.advertisement('m-w3', 'w3', 'h1', true);
    await time.to(20_999);
    expect(state.requestTimes).toEqual([1_000, 6_000, 16_000]);
    expect(state.loads).toEqual([]);
    await time.to(21_000);
    expect(state.loads).toEqual([{ peer: 'w1', at: 21_000 }]);
    expect(events.slice(-2)).toEqual([
      expect.objectContaining({ type: 'repaired', afterMs: 19_000 }),
      expect.objectContaining({ type: 'load', peer: 'w1', outcome: 'loaded' }),
    ]);
    expect(antiEntropy.status()).toMatchObject({
      loads: 1,
      gap: false,
      lastLoad: { at: START + 21_000, peer: 'w1', outcome: 'loaded' },
    });
  });

  test('a gap advertised only by readers is repaired over gossip, never by load', async () => {
    const { time, state, antiEntropy } = setup();
    state.connected = new Set(['reader']);
    antiEntropy.start();
    await time.to(1_000);
    antiEntropy.advertisement('m-reader', 'reader', 'h', false);
    await time.to(600_000);
    expect(state.loads).toEqual([]);
    expect(state.requestTimes.length).toBeGreaterThan(10);
  });

  test('without the load path, a local gap keeps asking at the periodic rate', async () => {
    const { time, state, antiEntropy } = setup();
    state.loadable = false;
    state.pending = true;
    antiEntropy.start();
    await time.to(1_000_000);
    expect(state.loads).toEqual([]);
    const gaps = state.requestTimes
      .slice(1)
      .map((at, i) => at - state.requestTimes[i]!);
    expect(Math.max(...gaps)).toBe(45_000);
  });

  test('local evidence starts at most three loads per gap, with doubling spacing', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.pending = true;
    let attempt = 0;
    state.load = async () => {
      if (attempt++ % 2) throw new Error('quorum');
      return false;
    };
    antiEntropy.start();
    await time.to(5_000_000);
    expect(state.loads).toEqual([
      { at: 16_000 },
      { at: 136_000 },
      { at: 376_000 },
    ]);
    expect(
      events
        .filter((event) => event.type === 'load')
        .map((event) => event.type === 'load' && event.outcome),
    ).toEqual(['not-served', 'failed', 'not-served']);
    expect(antiEntropy.status().gap).toBe(true);
  });

  test('a repaired gap resets request and load backoff', async () => {
    const { time, state, antiEntropy } = setup();
    state.pending = true;
    state.load = async () => {
      state.pending = false;
      return true;
    };
    antiEntropy.start();
    await time.to(16_000);
    expect(state.loads).toEqual([{ at: 16_000 }]);
    expect(antiEntropy.status().gap).toBe(false);
    state.pending = true;
    antiEntropy.remoteStateApplied();
    await time.to(17_000);
    expect(state.requestTimes.at(-1)).toBe(17_000);
    await time.to(75_999);
    expect(state.loads).toEqual([{ at: 16_000 }]);
    await time.to(76_000);
    expect(state.loads).toEqual([{ at: 16_000 }, { at: 76_000 }]);
  });
});

describe('anti-entropy shared budget', () => {
  test('documents sharing a budget spread their requests', async () => {
    const budget = new AntiEntropyBudget(1, 2);
    const time = fakeClock();
    const documents = Array.from({ length: 3 }, () => {
      const fake = fakeHost();
      fake.bind(() => time.now);
      const antiEntropy = new AntiEntropy(
        resolveAntiEntropyConfig(),
        fake.host,
        budget,
        () => {},
        time.clock,
      );
      antiEntropy.start();
      return fake.state;
    });
    await time.to(1_000);
    expect(documents.map((state) => state.requestTimes)).toEqual([
      [1_000],
      [1_000],
      [],
    ]);
    await time.to(3_000);
    expect(documents[2]!.requestTimes).toEqual([3_000]);
  });

  test('loads are serialized across documents and spaced per peer', async () => {
    const budget = new AntiEntropyBudget(4, 16, 1, 10_000);
    const release = budget.acquireLoad('p', 0)!;
    expect(budget.acquireLoad('q', 0)).toBeUndefined();
    release();
    release();
    expect(budget.acquireLoad('p', 5_000)).toBeUndefined();
    const second = budget.acquireLoad('q', 5_000)!;
    second();
    expect(budget.acquireLoad('p', 10_000)).toBeDefined();
  });

  test('a document waiting for the shared load slot retries without loading twice', async () => {
    const budget = new AntiEntropyBudget();
    const time = fakeClock();
    let finish!: (loaded: boolean) => void;
    const states = Array.from({ length: 2 }, (_, index) => {
      const fake = fakeHost();
      fake.bind(() => time.now);
      fake.state.pending = true;
      fake.state.load = () =>
        index === 0
          ? new Promise<boolean>((resolve) => {
              finish = resolve;
            })
          : Promise.resolve(true);
      new AntiEntropy(
        resolveAntiEntropyConfig(),
        fake.host,
        budget,
        () => {},
        time.clock,
      ).start();
      return fake.state;
    });
    await time.to(30_000);
    expect(states[0]!.loads).toHaveLength(1);
    expect(states[1]!.loads).toHaveLength(0);
    finish(false);
    await time.to(35_000);
    expect(states[1]!.loads).toHaveLength(1);
    expect(states[0]!.loads).toHaveLength(1);
  });
});

describe('anti-entropy evidence and abuse bounds', () => {
  test('subscriptions from peers not seen as members share one cooldown per document', async () => {
    const { time, state, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    await time.to(1_000);
    for (let i = 0; i < 50; i++) antiEntropy.peerSubscribed(`throwaway-${i}`);
    await time.to(30_000);
    expect(state.requestTimes).toEqual([1_000, 6_000]);
    antiEntropy.memberPeer('member-a');
    antiEntropy.memberPeer('member-b');
    antiEntropy.peerSubscribed('member-a');
    antiEntropy.peerSubscribed('member-b');
    antiEntropy.peerSubscribed('throwaway-50');
    await time.to(40_000);
    expect(state.requestTimes).toEqual([1_000, 6_000, 31_000]);
    antiEntropy.peerSubscribed('member-a');
    antiEntropy.peerSubscribed('throwaway-51');
    await time.to(45_000);
    expect(state.requestTimes).toHaveLength(4);
    expect(antiEntropy.status().suppressed).toBe(51);
    antiEntropy.peerSubscribed('throwaway-52');
    antiEntropy.peerSubscribed('dialed-relay', true);
    await time.to(55_000);
    expect(state.requestTimes).toHaveLength(5);
    expect(antiEntropy.status().suppressed).toBe(52);
  });

  test('one member counts once however many PeerIds it advertises from', async () => {
    const { time, state, antiEntropy } = setup();
    state.connected = new Set(Array.from({ length: 20 }, (_, i) => `p${i}`));
    antiEntropy.start();
    await time.to(1_000);
    for (let i = 0; i < 20; i++) {
      await time.to(1_000 + i * 31_000);
      if (antiEntropy.admitAdvertisement('member', 'head'))
        antiEntropy.advertisement('member', `p${i}`, 'head', true);
    }
    await time.to(2_000_000);
    expect(state.loads).toEqual([]);
  });

  test('a head only one member advertises is asked for, then abandoned with a growing penalty, never loaded', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.connected = new Set(['w']);
    antiEntropy.start();
    await time.to(1_000);
    expect(antiEntropy.admitAdvertisement('m', 'fake-1')).toBe(true);
    antiEntropy.advertisement('m', 'w', 'fake-1', true);
    await time.to(200_000);
    expect(state.loads).toEqual([]);
    const abandoned = events.find((event) => event.type === 'abandoned')!;
    expect(abandoned).toBeDefined();
    expect(events.some((event) => event.type === 'repaired')).toBe(false);
    expect(abandoned.at - START).toBeGreaterThanOrEqual(136_000);
    const firstStrike = abandoned.at - START;
    await time.to(firstStrike + 299_000);
    expect(antiEntropy.admitAdvertisement('m', 'fake-2')).toBe(false);
    await time.to(firstStrike + 300_000);
    expect(antiEntropy.admitAdvertisement('m', 'fake-2')).toBe(true);
    antiEntropy.advertisement('m', 'w', 'fake-2', true);
    await time.to(firstStrike + 600_000);
    const second = events.filter((event) => event.type === 'abandoned')[1]!;
    const secondStrike = second.at - START;
    await time.to(secondStrike + 599_000);
    expect(antiEntropy.admitAdvertisement('m', 'fake-3')).toBe(false);
    await time.to(secondStrike + 600_000);
    expect(antiEntropy.admitAdvertisement('m', 'fake-3')).toBe(true);
    expect(state.loads).toEqual([]);
  });

  test('a corroborated load that leaves the head unknown penalizes its advertisers and keeps the backoff', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.connected = new Set(['w1', 'w2']);
    antiEntropy.start();
    await time.to(1_000);
    antiEntropy.advertisement('m1', 'w1', 'fake', true);
    antiEntropy.advertisement('m2', 'w2', 'fake', true);
    await time.to(21_000);
    expect(state.loads).toEqual([{ peer: 'w2', at: 21_000 }]);
    expect(events.slice(-2).map((event) => event.type)).toEqual([
      'abandoned',
      'load',
    ]);
    expect(antiEntropy.status().gap).toBe(false);
    expect(antiEntropy.admitAdvertisement('m1', 'fake')).toBe(false);
    expect(antiEntropy.admitAdvertisement('m2', 'other')).toBe(false);
    antiEntropy.advertisement('m3', 'w1', 'next', true);
    antiEntropy.advertisement('m4', 'w2', 'next', true);
    await time.to(140_999);
    expect(state.loads).toHaveLength(1);
    await time.to(141_000);
    expect(state.loads).toHaveLength(2);
  });

  test('an unfetched change a load does not reveal is not escalated again for an hour', async () => {
    const { time, state, events, antiEntropy } = setup();
    antiEntropy.start();
    await time.to(1_000);
    antiEntropy.missingChange('ghost');
    await time.to(21_000);
    expect(state.loads).toEqual([{ at: 21_000 }]);
    expect(events.filter((event) => event.type === 'abandoned')).toHaveLength(
      1,
    );
    const suppressed = antiEntropy.status().suppressed;
    antiEntropy.missingChange('ghost');
    expect(antiEntropy.status()).toMatchObject({
      gap: false,
      suppressed: suppressed + 1,
    });
    await time.to(21_000 + 60 * 60 * 1000);
    antiEntropy.missingChange('ghost');
    expect(antiEntropy.status().gap).toBe(true);
  });

  test("advertisements expire, a member's latest replaces its earlier one, and a retraction is not a repair", async () => {
    const { time, state, events, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    await time.to(1_000);
    antiEntropy.advertisement('m', 'p', 'h1', false);
    await time.to(32_000);
    expect(antiEntropy.admitAdvertisement('m', 'h2')).toBe(true);
    antiEntropy.advertisement('m', 'p', 'h2', false);
    state.known.add('h1');
    antiEntropy.remoteStateApplied();
    expect(antiEntropy.status().gap).toBe(true);
    expect(antiEntropy.admitRetraction('other')).toBe(false);
    expect(antiEntropy.admitRetraction('m')).toBe(true);
    antiEntropy.retractAdvertisement('m');
    expect(antiEntropy.status().gap).toBe(false);
    expect(events.at(-1)).toMatchObject({ type: 'abandoned' });
    expect(events.some((event) => event.type === 'repaired')).toBe(false);
  });

  test('many open documents stretch the periodic interval and keep tokens for gap-driven requests', async () => {
    const budget = new AntiEntropyBudget();
    const time = fakeClock();
    const documents = Array.from({ length: 300 }, () => {
      const fake = fakeHost();
      fake.bind(() => time.now);
      fake.state.loadable = false;
      const antiEntropy = new AntiEntropy(
        resolveAntiEntropyConfig(),
        fake.host,
        budget,
        () => {},
        time.clock,
      );
      antiEntropy.start();
      return { ...fake, antiEntropy };
    });
    expect(budget.openDocuments).toBe(300);
    expect(budget.periodicScale(45_000)).toBeCloseTo(300 / 90);
    await time.to(600_000);
    const counts = documents.map(({ state }) => state.requestTimes.length);
    const total = counts.reduce((sum, count) => sum + count, 0);
    expect(total).toBeLessThanOrEqual(600 * 4 + 16);
    expect(Math.max(...counts)).toBeLessThanOrEqual(6);
    const target = documents[0]!;
    target.antiEntropy.missingChange('needed');
    const before = target.state.requestTimes.length;
    await time.to(603_000);
    expect(target.state.requestTimes.length).toBe(before + 1);
    for (const { antiEntropy } of documents) antiEntropy.close();
    expect(budget.openDocuments).toBe(0);
  });

  test('closing during a load aborts it and reports nothing afterwards', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.pending = true;
    state.load = (_peer, signal) =>
      new Promise<boolean>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), {
          once: true,
        });
      });
    antiEntropy.start();
    await time.to(16_000);
    expect(state.loads).toHaveLength(1);
    expect(antiEntropy.status().phase).toBe('loading');
    const signal = state.signals[0]!;
    expect(signal.aborted).toBe(false);
    const eventCount = events.length;
    antiEntropy.close();
    expect(signal.aborted).toBe(true);
    await time.to(200_000);
    expect(events).toHaveLength(eventCount);
    expect(antiEntropy.status()).toMatchObject({ running: false, loads: 0 });
  });
});
