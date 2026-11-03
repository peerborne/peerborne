import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  advanceSyncRequestClock,
  pruneSyncRequestReplays,
  classifySyncRequestReplay,
  rememberSyncRequest,
  syncResponseAllowed,
} from './policy/sync-request.js';

const key = (value: number) =>
  ['__proto__', 'constructor', '\ud800', '\ufeff', ''][value] ??
  `request-${value}`;

test('calibrates native replay-map ownership and monotone time across generated response histories', () => {
  fc.assert(
    fc.property(
      fc.array(
        fc.record({
          id: fc.integer({ min: 0, max: 150 }),
          observed: fc.oneof(
            fc.nat(200000),
            fc.constant(Number.MAX_SAFE_INTEGER),
          ),
          issued: fc.oneof(
            fc.nat(200000),
            fc.constant(Number.MAX_SAFE_INTEGER),
          ),
          authenticated: fc.boolean(),
          changeKnown: fc.boolean(),
          snapshotKnown: fc.boolean(),
          hasSnapshot: fc.boolean(),
          hasChange: fc.boolean(),
        }),
        { maxLength: 180 },
      ),
      (attempts) => {
        let ledger = new Map<string, number>(),
          clock = 0,
          lastResponse = 0;
        let oracle: Array<readonly [string, number]> = [];
        const initial = {
          id: 0,
          observed: 5000,
          issued: 5000,
          authenticated: true,
          changeKnown: false,
          snapshotKnown: false,
          hasSnapshot: false,
          hasChange: true,
        };
        for (const attempt of [initial, ...attempts]) {
          const before = ledger,
            snapshot = [...before];
          const observed = Math.max(clock, attempt.observed);
          expect(advanceSyncRequestClock(clock, attempt.observed)).toBe(
            observed,
          );
          clock = observed;
          ledger = pruneSyncRequestReplays([...ledger.keys()], ledger, clock);
          expect([...before]).toEqual(snapshot);
          oracle = oracle.filter(([, issued]) => clock - issued <= 60000);
          expect([...ledger]).toEqual(oracle);
          before.clear();
          before.set('mutated-input', 0);
          expect([...ledger]).toEqual(oracle);
          const id = key(attempt.id),
            known = oracle.some(([token]) => token === id);
          const fresh =
            clock - attempt.issued <= 60000 && attempt.issued - clock <= 30000;
          const expected = !fresh
            ? 'stale'
            : known
              ? 'replay'
              : oracle.length >= 128
                ? 'capacity'
                : 'fresh';
          expect(
            classifySyncRequestReplay(
              attempt.issued,
              clock,
              known,
              ledger.size,
              128,
            ),
          ).toBe(expected);
          const response =
            clock - lastResponse >= 2000 &&
            attempt.hasChange &&
            (!attempt.changeKnown ||
              (attempt.hasSnapshot && !attempt.snapshotKnown));
          expect(
            syncResponseAllowed(
              clock,
              lastResponse,
              attempt.hasChange,
              attempt.changeKnown,
              attempt.hasSnapshot,
              attempt.snapshotKnown,
            ),
          ).toBe(response);
          if (attempt.authenticated && expected === 'fresh' && response) {
            const parent = ledger,
              original = [...parent];
            ledger = rememberSyncRequest(parent, id, attempt.issued, 128);
            expect([...parent]).toEqual(original);
            parent.clear();
            parent.set('mutated-candidate-parent', 0);
            oracle.push([id, attempt.issued]);
            lastResponse = clock;
          }
          expect([...ledger]).toEqual(oracle);
          expect(ledger.size).toBeLessThanOrEqual(128);
        }
      },
    ),
    { seed: 2011221, numRuns: 100 },
  );
});

test('calibrates replay retention at the maximum safe timestamp and the 46-entry dense-response boundary', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 46, max: 180 }),
      fc.integer({ min: 0, max: 10000 }),
      (count, offset) => {
        let ledger = new Map<string, number>();
        let last = 0;
        for (let index = 0; index < count; index++) {
          const now = offset + 2000 * (index + 1),
            issued = now + 30000;
          ledger = pruneSyncRequestReplays([...ledger.keys()], ledger, now);
          expect(
            syncResponseAllowed(now, last, true, false, false, false),
          ).toBe(true);
          ledger = rememberSyncRequest(ledger, `request-${index}`, issued, 128);
          last = now;
          expect(ledger.size).toBeLessThanOrEqual(46);
          expect(ledger.size).toBe(Math.min(index + 1, 46));
        }
        const maximum = Number.MAX_SAFE_INTEGER;
        const terminal = new Map([
          ['live', maximum - 60000],
          ['expired', maximum - 60001],
          ['future', maximum],
        ]);
        expect([
          ...pruneSyncRequestReplays(
            [...terminal.keys()],
            terminal,
            maximum,
          ).keys(),
        ]).toEqual(['live', 'future']);
      },
    ),
    { seed: 2011222, numRuns: 100 },
  );
});
