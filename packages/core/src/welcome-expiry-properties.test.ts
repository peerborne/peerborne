import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { PeerborneDocument } from './peerborne-document.js';
import {
  PendingWelcomeBuffer,
  PENDING_WELCOME_MAX_BODY_BYTES,
  PENDING_WELCOMES_MAX_ENTRIES,
  PENDING_WELCOMES_MAX_RETAINED_BYTES,
  PENDING_WELCOMES_TTL_MS,
} from './pending-welcome-buffer.js';
import {
  advancePendingWelcomeClock,
  isPendingWelcomeExpired,
  planPendingWelcomeExpiry,
  type PendingWelcomeMetadata,
} from './policy/welcome-admission.js';
import * as admissionPolicy from './policy/welcome-admission.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Reject: 'reject' } }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

interface DrainHost {
  readonly _pendingWelcomes: PendingWelcomeBuffer;
  readonly _now: () => number;
  readonly documentPath: string;
  readonly _syncMessageSerializer: {
    deserializeSyncMessage(body: Uint8Array): unknown;
  };
  readonly _evaluateAndApplyBeeKEMWelcome: () => Promise<string>;
  readonly _bootstrapLoadApplicationState: string;
}

const drain = (
  PeerborneDocument.prototype as unknown as {
    _drainPendingWelcomesUnlocked(
      this: DrainHost,
      failClosed?: boolean,
      signal?: AbortSignal,
    ): Promise<void>;
  }
)._drainPendingWelcomesUnlocked;

test('expiry pruning lets the replay drain copy only live Welcome bodies', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 0, max: 1000000 }),
      fc.integer({ min: 1, max: PENDING_WELCOMES_MAX_ENTRIES }),
      fc.integer({ min: 1, max: 4096 }),
      fc.boolean(),
      async (base, count, size, keepLive) => {
        const buffer = new PendingWelcomeBuffer();
        for (let index = 0; index < count; index++)
          buffer.store(
            `expired-${index}`,
            new Uint8Array(size).fill(index),
            base + index,
            true,
          );
        const now = base + count + PENDING_WELCOMES_TTL_MS;
        if (keepLive)
          buffer.store('live', new Uint8Array(size).fill(255), now, true);
        let deserializations = 0,
          evaluations = 0;
        const host: DrainHost = {
          _pendingWelcomes: buffer,
          _now: () => now,
          documentPath: '/synthetic/welcome-expiry',
          _syncMessageSerializer: {
            deserializeSyncMessage: () => {
              deserializations++;
              return {};
            },
          },
          _evaluateAndApplyBeeKEMWelcome: async () => {
            evaluations++;
            return 'retry';
          },
          _bootstrapLoadApplicationState: 'active',
        };
        const replayCopy = jest.spyOn(buffer, 'get');
        const warning = jest
          .spyOn(console, 'warn')
          .mockImplementation(() => {});
        try {
          await drain.call(host);
          expect(replayCopy.mock.calls.map(([key]) => key)).toEqual(
            keepLive ? ['live'] : [],
          );
        } finally {
          replayCopy.mockRestore();
          warning.mockRestore();
        }
        expect(deserializations).toBe(keepLive ? 1 : 0);
        expect(evaluations).toBe(keepLive ? 1 : 0);
        expect(buffer.keysSnapshot()).toEqual(keepLive ? ['live'] : []);
        expect(buffer.retainedBytes).toBe(keepLive ? size : 0);
      },
    ),
    {
      seed: 2011321,
      numRuns: 20,
      examples: [
        [0, 1, 1, false],
        [0, 16, 4096, true],
      ],
    },
  );
});

const action = fc.record({
  kind: fc.constantFrom('store' as const, 'delete' as const, 'expire' as const),
  key: fc.integer({ min: 0, max: 23 }),
  time: fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
  authenticated: fc.boolean(),
  bytes: fc.integer({ min: 1, max: 16 }),
});

test('native expiry and admission histories preserve a monotone clock and exact owned state', () => {
  fc.assert(
    fc.property(fc.array(action, { maxLength: 80 }), (program) => {
      expect(PENDING_WELCOME_MAX_BODY_BYTES).toBe(10485760);
      expect(PENDING_WELCOMES_MAX_RETAINED_BYTES).toBe(20971520);
      expect(PENDING_WELCOMES_MAX_ENTRIES).toBe(16);
      expect(PENDING_WELCOMES_TTL_MS).toBe(300000);
      const buffer = new PendingWelcomeBuffer();
      let clock = 0n;
      let rows: Array<{
        key: string;
        at: bigint;
        authenticated: boolean;
        bytes: number;
        value: number;
      }> = [];
      const prelude = Array.from({ length: 16 }, (_, key) => ({
        kind: 'store' as const,
        key,
        time: key,
        authenticated: true,
        bytes: 1,
      }));
      for (const step of [...prelude, ...program]) {
        const key = String(step.key),
          sampled = BigInt(step.time);
        if (step.kind === 'expire') {
          if (sampled > clock) clock = sampled;
          const expired = rows
            .filter((row) => clock - row.at > BigInt(PENDING_WELCOMES_TTL_MS))
            .map((row) => row.key);
          expect(buffer.pruneExpired(step.time)).toEqual(expired);
          rows = rows.filter((row) => !expired.includes(row.key));
        } else if (step.kind === 'delete') {
          expect(buffer.delete(key)).toBe(rows.some((row) => row.key === key));
          rows = rows.filter((row) => row.key !== key);
        } else {
          const previous = rows.some((row) => row.key === key);
          const admitted =
            step.authenticated ||
            (!previous &&
              (rows.length < 16 || rows.some((row) => !row.authenticated)));
          const evicted: string[] = [];
          if (admitted) {
            if (sampled > clock) clock = sampled;
            rows = rows.filter((row) => row.key !== key);
            if (rows.length === 16) {
              const victim = rows.find((row) => !row.authenticated) ?? rows[0];
              evicted.push(victim.key);
              rows = rows.filter((row) => row !== victim);
            }
            rows.push({
              key,
              at: clock,
              authenticated: step.authenticated,
              bytes: step.bytes,
              value: step.key,
            });
          }
          const body = new Uint8Array(step.bytes).fill(step.key);
          expect(
            buffer.store(key, body, step.time, step.authenticated),
          ).toEqual({
            stored: admitted,
            replaced: admitted && previous,
            evictedKeys: evicted,
          });
          body.fill(255);
        }
        expect(buffer.keysSnapshot()).toEqual(rows.map((row) => row.key));
        expect(buffer.retainedBytes).toBe(
          rows.reduce((sum, row) => sum + row.bytes, 0),
        );
        for (const row of rows) {
          const value = buffer.get(row.key)!;
          expect(value.bufferedAtMs).toBe(Number(row.at));
          expect(value.authenticated).toBe(row.authenticated);
          expect(value.body.length).toBe(row.bytes);
          expect(value.body[0]).toBe(row.value);
        }
      }
    }),
    {
      seed: 2011320,
      numRuns: 100,
      examples: [
        [
          [
            {
              kind: 'store',
              key: 16,
              time: Number.MAX_SAFE_INTEGER,
              authenticated: false,
              bytes: 1,
            },
            { kind: 'delete', key: 0, time: 0, authenticated: false, bytes: 1 },
            { kind: 'store', key: 17, time: 20, authenticated: true, bytes: 1 },
          ],
        ],
        [
          [
            {
              kind: 'expire',
              key: 0,
              time: 20,
              authenticated: false,
              bytes: 1,
            },
            { kind: 'store', key: 0, time: 0, authenticated: true, bytes: 1 },
            {
              kind: 'expire',
              key: 0,
              time: PENDING_WELCOMES_TTL_MS + 20,
              authenticated: false,
              bytes: 1,
            },
          ],
        ],
      ],
    },
  );
});

test('invalid expiry clocks leave retained state and the next receipt time unchanged', () => {
  fc.assert(
    fc.property(
      fc.constantFrom<unknown>(
        NaN,
        Infinity,
        -Infinity,
        -1,
        1.5,
        Number.MAX_SAFE_INTEGER + 1,
        '1',
        null,
        undefined,
        {},
        new Number(1),
      ),
      (invalid) => {
        const buffer = new PendingWelcomeBuffer();
        buffer.store('old', new Uint8Array([1]), 10, true);
        expect(() => buffer.pruneExpired(invalid as number)).toThrow(TypeError);
        expect(buffer.keysSnapshot()).toEqual(['old']);
        expect(buffer.retainedBytes).toBe(1);
        buffer.store('fresh', new Uint8Array([2]), 11, true);
        expect(buffer.get('fresh')!.bufferedAtMs).toBe(11);
      },
    ),
    { seed: 2011322, numRuns: 30 },
  );
});

test('failed expiry preparation preserves payloads, accounting and the observed clock', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 1000000 }),
      fc.constantFrom('plan' as const, 'projection' as const),
      (base, stage) => {
        const buffer = new PendingWelcomeBuffer();
        buffer.store('old-a', new Uint8Array([1]), base, true);
        buffer.store('old-b', new Uint8Array([2]), base + 1, false);
        const prepare =
          stage === 'plan'
            ? jest.spyOn(admissionPolicy, 'planPendingWelcomeExpiry')
            : jest.spyOn(admissionPolicy, 'retainPendingWelcomeValues');
        prepare.mockImplementation(() => {
          throw new RangeError('Synthetic expiry preparation failure');
        });
        try {
          expect(() =>
            buffer.pruneExpired(base + PENDING_WELCOMES_TTL_MS + 2),
          ).toThrow('Synthetic expiry preparation failure');
          expect(prepare.mock.calls.length).toBe(1);
        } finally {
          prepare.mockRestore();
        }
        expect(buffer.keysSnapshot()).toEqual(['old-a', 'old-b']);
        expect(buffer.retainedBytes).toBe(2);
        expect(buffer.get('old-a')!.body[0]).toBe(1);
        expect(buffer.get('old-b')!.body[0]).toBe(2);
        expect(buffer.get('old-a')!.bufferedAtMs).toBe(base);
        expect(buffer.get('old-b')!.bufferedAtMs).toBe(base + 1);
        buffer.store('fresh', new Uint8Array([3]), base + 2, true);
        expect(buffer.get('fresh')!.bufferedAtMs).toBe(base + 2);
      },
    ),
    {
      seed: 2011323,
      numRuns: 20,
      examples: [
        [0, 'plan'],
        [1, 'projection'],
      ],
    },
  );
});

const timedMetadata = fc.uniqueArray(
  fc.record({
    id: fc.integer({ min: 0, max: 31 }),
    bytes: fc.integer({ min: 1, max: 10485760 }),
    authenticated: fc.boolean(),
    time: fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
  }),
  { selector: (row) => row.id, maxLength: 16 },
);

test('native expiry arithmetic and array ownership match a BigInt time oracle', () => {
  fc.assert(
    fc.property(
      timedMetadata,
      fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
      fc.oneof(
        fc.constantFrom(0, 1, PENDING_WELCOMES_TTL_MS, Number.MAX_SAFE_INTEGER),
        fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
      ),
      fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
      (generated, now, ttl, previous) => {
        const metadata = generated.map((row) => ({
          key: ['', '__proto__', '\ud800', '\u0000'][row.id] ?? String(row.id),
          bytes: row.bytes,
          authenticated: row.authenticated,
        }));
        const times = generated.map((row) => row.time);
        const before = metadata.map((row) => ({ ...row })),
          timesBefore = [...times];
        const kept = metadata.filter(
          (_, index) => BigInt(now) - BigInt(times[index]) <= BigInt(ttl),
        );
        const expiredKeys = metadata
          .filter(
            (_, index) => BigInt(now) - BigInt(times[index]) > BigInt(ttl),
          )
          .map((row) => row.key);
        const plan = planPendingWelcomeExpiry(metadata, times, now, ttl);
        expect(plan).toEqual({
          kept,
          expiredKeys,
          retainedBytes: Number(
            kept.reduce((sum, row) => sum + BigInt(row.bytes), 0n),
          ),
        });
        for (let index = 0; index < times.length; index++)
          expect(isPendingWelcomeExpired(times[index], now, ttl)).toBe(
            BigInt(now) - BigInt(times[index]) > BigInt(ttl),
          );
        const observed = advancePendingWelcomeClock(previous, now);
        expect(observed).toBe(
          Number(
            BigInt(previous) >= BigInt(now) ? BigInt(previous) : BigInt(now),
          ),
        );
        expect(advancePendingWelcomeClock(observed, previous)).toBe(observed);
        expect(plan.kept).not.toBe(metadata);
        (plan.kept as PendingWelcomeMetadata[]).push({
          key: 'injected',
          bytes: 1,
          authenticated: false,
        });
        expect(metadata).toEqual(before);
        expect(times).toEqual(timesBefore);
      },
    ),
    {
      seed: 2011324,
      numRuns: 200,
      examples: [
        [
          [
            {
              id: 0,
              bytes: 1,
              authenticated: true,
              time: Number.MAX_SAFE_INTEGER - 300000,
            },
          ],
          Number.MAX_SAFE_INTEGER,
          300000,
          0,
        ],
        [
          [
            {
              id: 0,
              bytes: 1,
              authenticated: true,
              time: Number.MAX_SAFE_INTEGER - 300001,
            },
          ],
          Number.MAX_SAFE_INTEGER,
          300000,
          0,
        ],
      ],
    },
  );
});

test('an already-cancelled replay does not prune, copy, or observe the clock', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 1, max: 16 }), async (count) => {
      const buffer = new PendingWelcomeBuffer();
      for (let index = 0; index < count; index++)
        buffer.store(String(index), new Uint8Array([index]), 0, true);
      let observations = 0;
      const host: DrainHost = {
        _pendingWelcomes: buffer,
        _now: () => {
          observations++;
          return PENDING_WELCOMES_TTL_MS + 1;
        },
        documentPath: '/synthetic/cancelled-welcome-expiry',
        _syncMessageSerializer: {
          deserializeSyncMessage: () => {
            throw new Error('Cancelled replay deserialized');
          },
        },
        _evaluateAndApplyBeeKEMWelcome: async () => {
          throw new Error('Cancelled replay evaluated');
        },
        _bootstrapLoadApplicationState: 'active',
      };
      const controller = new AbortController();
      const reason = new Error('Synthetic cancellation');
      controller.abort(reason);
      const copy = jest.spyOn(buffer, 'get');
      const prune = jest.spyOn(buffer, 'pruneExpired');
      try {
        await expect(drain.call(host, false, controller.signal)).rejects.toBe(
          reason,
        );
        expect(copy.mock.calls.length).toBe(0);
        expect(prune.mock.calls.length).toBe(0);
      } finally {
        copy.mockRestore();
        prune.mockRestore();
      }
      expect(observations).toBe(0);
      expect(buffer.size).toBe(count);
      expect(buffer.retainedBytes).toBe(count);
    }),
    { seed: 2011325, numRuns: 20 },
  );
});
