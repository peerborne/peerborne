import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  canAdmitPendingWelcome,
  insertPendingWelcomeValue,
  pendingWelcomeBudget,
  planPendingWelcomeAdmission,
  planPendingWelcomeRemoval,
  retainPendingWelcomeValues,
} from './policy/welcome-admission.js';

const label = (id: number) =>
  ['', '__proto__', 'constructor', '\ud800', '\u0000'][id] ?? `entry-${id}`;
const entries = fc.uniqueArray(
  fc.record({
    id: fc.integer({ min: 0, max: 31 }),
    bytes: fc.integer({ min: 1, max: 10485760 }),
    authenticated: fc.boolean(),
  }),
  { selector: (entry) => entry.id, maxLength: 16 },
);

test('native plans and owned value projections match a ranked-victim BigInt oracle', () => {
  fc.assert(
    fc.property(
      entries,
      fc.integer({ min: 0, max: 31 }),
      fc.integer({ min: 1, max: 10485760 }),
      fc.boolean(),
      fc.integer({ min: 1, max: 16 }),
      fc.integer({ min: 1, max: 20971520 }),
      (
        generated,
        id,
        incomingBytes,
        authenticated,
        maximumEntries,
        requestedLimit,
      ) => {
        const metadata = generated.map(({ id, ...entry }) => ({
          ...entry,
          key: label(id),
        }));
        const original = metadata.map((entry) => ({ ...entry }));
        const key = label(id),
          maximumBytes = Math.max(incomingBytes, requestedLimit);
        const total = (rows: typeof metadata) =>
          rows.reduce((sum, entry) => sum + BigInt(entry.bytes), 0n);
        const previous = metadata.find((entry) => entry.key === key);
        const protectedEntries = metadata.filter(
          (entry) => entry.authenticated,
        );
        const budget = pendingWelcomeBudget(metadata, key);
        expect(budget).toEqual({
          total: Number(total(metadata)),
          protectedBytes: Number(total(protectedEntries)),
          protectedCount: protectedEntries.length,
          previousBytes: previous?.bytes ?? 0,
        });
        let rows = metadata.filter((entry) => entry.key !== key);
        const victims = [...rows].sort(
          (left, right) =>
            Number(left.authenticated) - Number(right.authenticated),
        );
        const evicted: string[] = [];
        const fits = () =>
          rows.length < maximumEntries &&
          total(rows) + BigInt(incomingBytes) <= BigInt(maximumBytes);
        if (!previous || authenticated) {
          for (const victim of victims) {
            if (fits()) break;
            if (!authenticated && victim.authenticated) continue;
            rows = rows.filter((entry) => entry !== victim);
            evicted.push(victim.key);
          }
        }
        const admitted = (!previous || authenticated) && fits();
        if (!admitted) rows = metadata;
        const plan = planPendingWelcomeAdmission(
          metadata,
          key,
          incomingBytes,
          authenticated,
          maximumEntries,
          maximumBytes,
        );
        expect(plan).toEqual({
          admitted,
          replaced: admitted && previous !== undefined,
          kept: rows,
          evictedKeys: admitted ? evicted : [],
          retainedBytes: Number(
            total(rows) + (admitted ? BigInt(incomingBytes) : 0n),
          ),
        });
        expect(
          canAdmitPendingWelcome(
            previous !== undefined,
            authenticated,
            protectedEntries.length,
            Number(total(protectedEntries)),
            incomingBytes,
            maximumEntries,
            maximumBytes,
          ),
        ).toBe(admitted);
        const header = planPendingWelcomeAdmission(
          metadata,
          key,
          1,
          authenticated,
          maximumEntries,
          maximumBytes,
        );
        if (admitted) expect(header.admitted).toBe(true);
        expect(plan.kept).not.toBe(metadata);
        for (const entry of plan.kept)
          expect(metadata.includes(entry)).toBe(true);
        const removal = planPendingWelcomeRemoval(metadata, key);
        const removedRows = metadata.filter((entry) => entry.key !== key);
        expect(removal).toEqual({
          kept: removedRows,
          removed: previous !== undefined,
          retainedBytes: Number(total(removedRows)),
        });
        expect(removal.kept).not.toBe(metadata);
        const values = new Map(
          metadata.map((entry, index) => [
            entry.key,
            { index, payload: new Uint8Array([index]) },
          ]),
        );
        const before = [...values];
        const retained = retainPendingWelcomeValues(values, plan.kept);
        expect(retained).not.toBe(values);
        expect([...retained]).toEqual(
          plan.kept.map((entry) => [entry.key, values.get(entry.key)]),
        );
        for (const entry of plan.kept)
          expect(retained.get(entry.key)).toBe(values.get(entry.key));
        if (admitted) {
          const candidate = { index: 100, payload: new Uint8Array([100]) };
          const committed = insertPendingWelcomeValue(retained, key, candidate);
          expect(committed).not.toBe(retained);
          expect(committed.get(key)).toBe(candidate);
          expect(retained.has(key)).toBe(false);
          expect(committed.size).toBeLessThanOrEqual(maximumEntries);
          for (const entry of plan.kept)
            expect(committed.get(entry.key)).toBe(values.get(entry.key));
        }
        expect([...values]).toEqual(before);
        expect(metadata).toEqual(original);
        values.clear();
        expect(retained.size).toBe(plan.kept.length);
        (plan.kept as typeof metadata).push({
          key: 'changed-result',
          bytes: 1,
          authenticated: false,
        });
        expect(metadata).toEqual(original);
      },
    ),
    { seed: 2011317, numRuns: 200 },
  );
});
