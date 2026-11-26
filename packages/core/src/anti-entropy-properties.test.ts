import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  AntiEntropy,
  AntiEntropyBudget,
  resolveAntiEntropyConfig,
  type AntiEntropyClock,
} from './anti-entropy.js';

const peers = ['a', 'b', 'c', 'd'];

const signal = fc.record({
  afterMs: fc.integer({ min: 0, max: 20_000 }),
  kind: fc.constantFrom(
    'subscribed',
    'pending',
    'settled',
    'missing',
    'advertised',
    'equivalent',
    'learned',
    'member',
  ),
  peer: fc.integer({ min: 0, max: peers.length - 1 }),
  member: fc.integer({ min: 0, max: 2 }),
  head: fc.integer({ min: 0, max: 5 }),
  writer: fc.boolean(),
});

test('generated signal histories keep request, load and timer bounds', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(signal, { maxLength: 60 }),
      fc.array(fc.double({ min: 0, max: 0.999, noNaN: true }), {
        minLength: 1,
        maxLength: 8,
      }),
      fc.constantFrom('sent', 'rate-limited', 'not-ready', 'throw'),
      fc.constantFrom('loaded', 'not-served', 'throw'),
      fc.boolean(),
      async (signals, draws, requestOutcome, loadOutcome, loadable) => {
        const config = resolveAntiEntropyConfig();
        let now = 0;
        let draw = 0;
        const timers = new Map<number, { at: number; run: () => void }>();
        let handles = 0;
        const clock: AntiEntropyClock = {
          now: () => now,
          setTimeout(run, ms) {
            timers.set(++handles, { at: now + ms, run });
            return handles;
          },
          clearTimeout: (handle) => void timers.delete(handle as number),
          random: () => draws[draw++ % draws.length]!,
        };
        const known = new Set<string>();
        const connected = new Set(['a', 'b']);
        const writerPeers = new Set<string>();
        let pending = false;
        const requests: number[] = [];
        const loads: Array<{ at: number; peer?: string; writer?: boolean }> =
          [];
        let maxTimers = 0;
        const antiEntropy = new AntiEntropy(
          config,
          {
            request: async () => {
              requests.push(now);
              if (requestOutcome === 'throw') throw new Error('request');
              return requestOutcome;
            },
            hasPendingChanges: () => pending,
            isKnown: (cid) => known.has(cid),
            canLoad: () => loadable,
            isConnected: (peer) => connected.has(peer),
            load: async (peer) => {
              loads.push({
                at: now,
                ...(peer === undefined
                  ? {}
                  : { peer, writer: writerPeers.has(peer) }),
              });
              if (loadOutcome === 'throw') throw new Error('load');
              return loadOutcome === 'loaded';
            },
          },
          new AntiEntropyBudget(),
          () => {},
          clock,
        );
        const runUntil = async (end: number) => {
          for (;;) {
            for (let i = 0; i < 10; i++) await Promise.resolve();
            maxTimers = Math.max(maxTimers, timers.size);
            let due: [number, { at: number; run: () => void }] | undefined;
            for (const entry of timers)
              if (due === undefined || entry[1].at < due[1].at) due = entry;
            if (due === undefined || due[1].at > end) break;
            timers.delete(due[0]);
            now = Math.max(now, due[1].at);
            due[1].run();
          }
          now = end;
        };
        antiEntropy.start();
        for (const step of signals) {
          await runUntil(now + step.afterMs);
          const peer = peers[step.peer]!;
          const head = `head-${step.head}`;
          switch (step.kind) {
            case 'subscribed':
              antiEntropy.peerSubscribed(peer);
              break;
            case 'pending':
              pending = true;
              antiEntropy.remoteStateApplied();
              break;
            case 'settled':
              pending = false;
              antiEntropy.remoteStateApplied();
              break;
            case 'missing':
              antiEntropy.missingChange(head);
              break;
            case 'advertised':
              if (antiEntropy.admitAdvertisement(`m${step.member}`, head)) {
                antiEntropy.advertisement(
                  `m${step.member}`,
                  peer,
                  head,
                  step.writer,
                );
                if (step.writer) writerPeers.add(peer);
              }
              break;
            case 'equivalent':
              antiEntropy.equivalentRequest();
              break;
            case 'learned':
              known.add(head);
              antiEntropy.remoteStateApplied();
              break;
            case 'member':
              antiEntropy.memberPeer(peer);
              break;
          }
        }
        await runUntil(
          now + 2 * config.intervalMs + 20 * config.loadIntervalMs,
        );
        antiEntropy.close();

        expect(maxTimers).toBeLessThanOrEqual(1);
        for (let i = 1; i < requests.length; i++)
          expect(requests[i]! - requests[i - 1]!).toBeGreaterThanOrEqual(
            config.minRequestIntervalMs,
          );
        const lastSignalAt =
          now - 2 * config.intervalMs - 20 * config.loadIntervalMs;
        const quiet = requests.filter((at) => at > lastSignalAt);
        for (let i = 1; i < quiet.length; i++)
          expect(quiet[i]! - quiet[i - 1]!).toBeLessThanOrEqual(
            Math.ceil((config.intervalMs * 4) / 3),
          );
        if (!loadable) expect(loads).toEqual([]);
        for (let i = 1; i < loads.length; i++)
          expect(loads[i]!.at - loads[i - 1]!.at).toBeGreaterThanOrEqual(
            config.loadIntervalMs,
          );
        for (const { peer, at, writer } of loads) {
          expect(
            requests.some((request) => request <= at - config.loadAfterMs),
          ).toBe(true);
          if (peer !== undefined) {
            expect(writer).toBe(true);
            expect(connected.has(peer)).toBe(true);
          }
        }
        expect(antiEntropy.status().running).toBe(false);
      },
    ),
    { seed: 2026_11_25, numRuns: 60 },
  );
});
