import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  canRecordDocumentPublicationBinding,
  recordDocumentPublicationBinding,
  canRetainDocumentPublicationBindings,
  retainDocumentPublicationBindings,
  selectDocumentPublicationBindings,
  isAcceptedDocumentPublicationToken,
} from './policy/document-journal.js';

const token = (value: number) =>
  ['', '__proto__', 'constructor', '\uFEFF', '\ud800', '🔒'][value] ??
  `token-${value}`;
const canonical = (entries: Iterable<readonly [string, number]>) =>
  [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

test('calibrates native token-map ownership and restart histories against an immutable record ledger', () => {
  fc.assert(
    fc.property(
      fc.array(
        fc.record({
          kind: fc.constantFrom(
            'append',
            'checkpoint',
            'ack',
            'restart',
            'query',
          ),
          token: fc.integer({ min: 0, max: 40 }),
          anchored: fc.boolean(),
          compact: fc.boolean(),
          poison: fc.constantFrom('none', 'unknown', 'duplicate'),
          queryRevision: fc.oneof(
            fc.nat(200),
            fc.constant(Number.MAX_SAFE_INTEGER),
          ),
        }),
        { maxLength: 180 },
      ),
      (actions) => {
        const limit = 24,
          pendingLimit = 4;
        let ledger = new Map<string, number>(),
          model: Array<[string, number]> = [],
          pending: string[] = [],
          revision = 0;
        let history: Array<{
          revision: number;
          checkpoint: boolean;
          bindings: Array<[string, number]>;
        }> = [];
        for (const [index, action] of actions.entries()) {
          const identity = token(action.token);
          if (action.kind === 'ack')
            pending = pending.filter((value) => value !== identity);
          if (action.kind === 'append' || action.kind === 'checkpoint') {
            const before = ledger,
              snapshot = canonical(before);
            const checkpoint = action.compact || action.kind === 'checkpoint';
            let requested = [...pending];
            if (action.poison === 'unknown') requested.push(`unknown-${index}`);
            if (action.poison === 'duplicate' && requested.length)
              requested.push(requested[0]);
            let candidate = before,
              next = [...model];
            let valid = true;
            if (checkpoint) {
              const expected =
                requested.length <= pendingLimit &&
                requested.every(
                  (value, offset) =>
                    model.some(([key]) => key === value) &&
                    requested.indexOf(value) === offset,
                );
              const permitted = canRetainDocumentPublicationBindings(
                before,
                requested,
                pendingLimit,
              );
              expect(permitted).toBe(expected);
              valid = expected;
              if (permitted) {
                candidate = retainDocumentPublicationBindings(
                  before,
                  requested,
                  pendingLimit,
                );
                next = requested.map(
                  (key) => model.find(([value]) => value === key)!,
                );
              }
            }
            if (valid && action.kind === 'append') {
              const fresh =
                !model.some(([key]) => key === identity) && next.length < limit;
              const permitted =
                !before.has(identity) &&
                canRecordDocumentPublicationBinding(
                  candidate,
                  identity,
                  revision + 1,
                  revision + 1,
                  false,
                  limit,
                );
              expect(permitted).toBe(fresh);
              valid = fresh;
              if (permitted) {
                candidate = recordDocumentPublicationBinding(
                  candidate,
                  identity,
                  revision + 1,
                  limit,
                );
                next.push([identity, revision + 1]);
              }
            }
            expect(canonical(before)).toEqual(snapshot);
            const anchored =
              valid &&
              action.anchored &&
              (action.kind !== 'append' || pending.length < pendingLimit);
            ledger = selectDocumentPublicationBindings(
              before,
              candidate,
              anchored,
            );
            if (anchored) {
              revision++;
              model = next;
              if (action.kind === 'append') pending.push(identity);
              const record = {
                revision,
                checkpoint,
                bindings: checkpoint
                  ? [...next]
                  : [[identity, revision] as [string, number]],
              };
              history = checkpoint ? [record] : [...history, record];
            }
          }
          if (action.kind === 'restart') {
            let restored = new Map<string, number>();
            for (const record of history) {
              for (const [identity, bindingRevision] of record.bindings) {
                expect(
                  canRecordDocumentPublicationBinding(
                    restored,
                    identity,
                    bindingRevision,
                    record.revision,
                    record.checkpoint,
                    limit,
                  ),
                ).toBe(true);
                restored = recordDocumentPublicationBinding(
                  restored,
                  identity,
                  bindingRevision,
                  limit,
                );
              }
            }
            ledger = restored;
          }
          expect(canonical(ledger)).toEqual(canonical(model));
          expect(ledger.size).toBeLessThanOrEqual(limit);
          expect(pending.length).toBeLessThanOrEqual(pendingLimit);
          expect(pending.every((identity) => ledger.has(identity))).toBe(true);
          const expected =
            model.some(
              ([key, value]) =>
                key === identity && value === action.queryRevision,
            ) &&
            action.queryRevision > 0 &&
            action.queryRevision <= revision;
          expect(
            isAcceptedDocumentPublicationToken(
              ledger,
              identity,
              action.queryRevision,
              revision,
            ),
          ).toBe(expected);
        }
      },
    ),
    { seed: 2011201, numRuns: 100 },
  );
});

test('detaches candidate and checkpoint maps from mutable JavaScript inputs', () => {
  fc.assert(
    fc.property(
      fc.array(
        fc.tuple(
          fc.integer({ min: 0, max: 180 }),
          fc.integer({ min: 1, max: 10000 }),
        ),
        { maxLength: 144 },
      ),
      fc.array(fc.boolean(), { maxLength: 144 }),
      (entries, selected) => {
        const before = new Map(
          entries.map(([key, revision]) => [token(key), revision]),
        );
        const original = canonical(before);
        const pending = [...before.keys()]
          .filter((_, index) => selected[index])
          .slice(0, 16);
        const retained = retainDocumentPublicationBindings(before, pending, 16);
        const expected = canonical(
          pending.map((key) => [key, before.get(key)!] as [string, number]),
        );
        const candidate = recordDocumentPublicationBinding(
          before,
          'fresh',
          10001,
          145,
        );
        expect(canonical(before)).toEqual(original);
        before.clear();
        before.set('changed-parent', 1);
        expect(canonical(retained)).toEqual(expected);
        expect(canonical(candidate)).toEqual(
          canonical([...original, ['fresh', 10001]]),
        );
        candidate.clear();
        retained.clear();
        expect([...before]).toEqual([['changed-parent', 1]]);
      },
    ),
    { seed: 2011202, numRuns: 120 },
  );
});
