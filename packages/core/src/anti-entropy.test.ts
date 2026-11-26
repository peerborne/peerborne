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
    load: async (_peer: string | undefined): Promise<boolean> => true,
    requestTimes: [] as number[],
    loads: [] as Array<{ peer?: string; at: number }>,
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
    load: (peer) => {
      state.loads.push({
        ...(peer === undefined ? {} : { peer }),
        at: clockNow(),
      });
      return state.load(peer);
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
      suppressed: 1,
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

  test('one peer triggers at most one request per kind of signal within its cooldown', async () => {
    const { time, state, antiEntropy } = setup();
    state.loadable = false;
    antiEntropy.start();
    await time.to(1_000);
    for (let i = 0; i < 20; i++) antiEntropy.peerSubscribed('flapping');
    await time.to(10_000);
    expect(state.requestTimes).toEqual([1_000, 6_000]);
    expect(antiEntropy.status().suppressed).toBe(19);
    expect(antiEntropy.admitAdvertisement('flapping', 'head')).toBe(true);
    antiEntropy.advertisement('flapping', 'head', true);
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
    antiEntropy.advertisement('a', 'head', true);
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
  test('loads from the newest connected writer that advertised newer state', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.connected = new Set(['reader', 'w1', 'w2']);
    antiEntropy.start();
    await time.to(1_000);
    await time.to(2_000);
    antiEntropy.advertisement('reader', 'h-reader', false);
    antiEntropy.advertisement('w1', 'h1', true);
    antiEntropy.advertisement('w2', 'h2', true);
    antiEntropy.advertisement('w3', 'h3', true);
    await time.to(20_999);
    expect(state.requestTimes).toEqual([1_000, 6_000, 16_000]);
    expect(state.loads).toEqual([]);
    await time.to(21_000);
    expect(state.loads).toEqual([{ peer: 'w2', at: 21_000 }]);
    expect(events.at(-1)).toMatchObject({
      type: 'load',
      peer: 'w2',
      outcome: 'loaded',
    });
    expect(antiEntropy.status()).toMatchObject({
      loads: 1,
      gap: true,
      lastLoad: { at: START + 21_000, peer: 'w2', outcome: 'loaded' },
    });
    state.known = new Set(['h-reader', 'h1', 'h3']);
    antiEntropy.remoteStateApplied();
    expect(events.at(-1)).toMatchObject({ type: 'repaired' });
  });

  test('a gap advertised only by readers is repaired over gossip, never by load', async () => {
    const { time, state, antiEntropy } = setup();
    state.connected = new Set(['reader']);
    antiEntropy.start();
    await time.to(1_000);
    antiEntropy.advertisement('reader', 'h', false);
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

  test('loads that leave the gap open back off to sixteen times the load interval', async () => {
    const { time, state, events, antiEntropy } = setup();
    state.pending = true;
    let attempt = 0;
    state.load = async () => {
      if (attempt++ % 2) throw new Error('quorum');
      return false;
    };
    antiEntropy.start();
    await time.to(5_000_000);
    const spacing = state.loads
      .slice(1)
      .map((load, i) => load.at - state.loads[i]!.at);
    expect(state.loads[0]).toEqual({ at: 16_000 });
    expect(spacing.slice(0, 5)).toEqual([
      120_000, 240_000, 480_000, 960_000, 960_000,
    ]);
    expect(
      events
        .filter((event) => event.type === 'load')
        .slice(0, 2)
        .map((event) => event.type === 'load' && event.outcome),
    ).toEqual(['not-served', 'failed']);
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
    expect(documents[2]!.requestTimes).toEqual([2_500]);
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
