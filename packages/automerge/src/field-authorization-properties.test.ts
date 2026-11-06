import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import * as A from '@automerge/automerge';
import { assertDocumentOperationsAllowed } from '@peerborne/core';
import {
  AutomergeProvider,
  AutomergeJSONSerializer,
} from './peerborne-automerge.js';
import { AutomergeOperationIndex } from './operation-targets.js';
import { fieldDocumentFixture } from '../../core/src/__testutils__/field-authorization.js';

type State = {
  profile?: { name: string; permissions: number };
  allowed: number;
  items: { value: number }[];
};
const initial = () =>
  A.from<State>(
    {
      profile: { name: 'seed', permissions: 1 },
      allowed: 0,
      items: [{ value: 1 }],
    },
    { actor: 'aa' },
  );
const pathsOf = (paths: readonly (readonly string[])[]) =>
  [...new Set(paths.map((path) => JSON.stringify(path)))].sort();

test('inspects actual native operations and denies ancestor replacement and unrelated map fields', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 4 }),
      fc.integer({ min: -1000, max: 1000 }),
      (kind, value) => {
        const provider = new AutomergeProvider<State>(),
          session = provider.createDocumentSession(initial());
        const plan = session.prepareLocal(
          '',
          (draft) => {
            if (kind === 0) draft.profile!.name = String(value);
            if (kind === 1) draft.profile!.permissions = value;
            if (kind === 2) delete draft.profile;
            if (kind === 3)
              draft.profile = { name: String(value), permissions: value };
            if (kind === 4) draft.items[0].value = value;
          },
          { inspectOperations: true },
        );
        const expected =
          kind === 0
            ? [['profile', 'name']]
            : kind === 1
              ? [['profile', 'permissions']]
              : kind === 4
                ? [['items']]
                : kind === 2
                  ? [['profile']]
                  : [
                      ['profile'],
                      ['profile', 'name'],
                      ['profile', 'permissions'],
                    ];
        expect(pathsOf(plan.operationPaths!())).toEqual(pathsOf(expected));
        if (kind === 0)
          expect(() =>
            assertDocumentOperationsAllowed(plan, [['profile', 'name']]),
          ).not.toThrow();
        else
          expect(() =>
            assertDocumentOperationsAllowed(plan, [['profile', 'name']]),
          ).toThrow(/signed field grants/);
        expect(session.document.profile?.permissions).toBe(1);
        plan.discard();
        session.close();
        A.free(session.document);
      },
    ),
    {
      seed: 2012311,
      numRuns: 45,
      examples: [
        [0, 2],
        [1, 2],
        [2, 2],
        [3, 2],
        [4, 2],
      ],
    },
  );
});

test('rejects hidden losing writes even when the visible document projection does not change', () => {
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 1000 }), (value) => {
      const base = initial();
      const winning = A.change(A.clone(base, { actor: 'ff' }), (draft) => {
        draft.profile!.permissions = 9999;
        draft.allowed = 1;
      });
      const losing = A.change(A.clone(base, { actor: '01' }), (draft) => {
        draft.profile!.permissions = value;
      });
      const session = new AutomergeProvider<State>().createDocumentSession(
        A.clone(winning),
      );
      const plan = session.prepareRemote(A.getChanges(base, losing), {
        inspectOperations: true,
      });
      const [projection] = A.applyChanges(
        A.clone(winning),
        A.getChanges(base, losing),
      );
      expect(projection.profile!.permissions).toBe(
        winning.profile!.permissions,
      );
      // Use a real winning concurrent value, not a visible-diff authorization oracle.
      expect(plan.operationPaths!()).toEqual([['profile', 'permissions']]);
      expect(() =>
        assertDocumentOperationsAllowed(plan, [['allowed']]),
      ).toThrow(/signed field grants/);
      plan.discard();
      expect(session.document.allowed).toBe(1);
      session.close();
      for (const doc of [base, winning, losing, projection, session.document])
        A.free(doc);
    }),
    { seed: 2012312, numRuns: 25 },
  );
});

test('the encrypted document boundary rejects signed out-of-scope native changes before WAL admission', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 2, max: 1000 }), async (value) => {
      const f = await fieldDocumentFixture(
        new AutomergeProvider<State>(),
        new AutomergeJSONSerializer(),
        [['allowed']],
      );
      const base = initial();
      const receiver = f.create(A.clone(base), false, true),
        attacker = f.create(A.clone(base), true),
        honest = f.create(A.clone(base));
      await receiver.activate();
      const stages = jest.spyOn(f.store, 'stage');
      const bad = await attacker.change((draft) => {
        draft.profile!.permissions = value;
      });
      await expect(receiver.receive(bad)).rejects.toThrow(
        /signed field grants/,
      );
      expect(stages).not.toHaveBeenCalled();
      expect(receiver.document.profile!.permissions).toBe(1);
      expect((await f.store.load(f.storageKey)).entries).toHaveLength(0);
      await expect(
        honest.change((draft) => {
          draft.profile!.permissions = value;
        }),
      ).rejects.toThrow(/signed field grants/);
      const good = await honest.change((draft) => {
        draft.allowed = value;
      });
      expect(await receiver.receive(good)).toBe(true);
      expect(await receiver.receive(good)).toBe(false);
      expect(receiver.document.allowed).toBe(value);
      expect(receiver.document.profile!.permissions).toBe(1);
      expect(stages).toHaveBeenCalledTimes(1);
      const documents = [receiver.document, attacker.document, honest.document];
      for (const document of [receiver, attacker, honest])
        await document.close();
      stages.mockRestore();
      for (const doc of [base, ...documents]) A.free(doc);
    }),
    { seed: 2012315, numRuns: 8 },
  );
});

test('native pred-reference and operation-boundary fuzzing cannot relabel a protected mutation as an allowed write', () => {
  fc.assert(
    fc.property(
      fc.constantFrom('set', 'del', 'inc', 'makeMap'),
      fc.integer({ min: 0, max: 5 }),
      fc.boolean(),
      (action, mode, allowed) => {
        const base = A.from({ allowed: 1, protected: 2 }, { actor: 'aa' });
        const history = A.decodeChange(A.getAllChanges(base)[0]);
        const index = history.ops.findIndex(
          (op) => op.key === (mode === 1 ? 'allowed' : 'protected'),
        );
        const known = `${history.startOp + index}@${history.actor}`;
        const pred =
          mode === 0
            ? []
            : mode === 3
              ? ['999999@cc']
              : mode === 4
                ? [known, known]
                : mode === 5
                  ? ['1@bb']
                  : [known];
        const session = new AutomergeProvider<{
          allowed?: number;
          protected: number;
        }>().createDocumentSession(A.clone(base));
        let plan: ReturnType<typeof session.prepareRemote> | undefined;
        try {
          const frame = A.encodeChange({
            actor: 'bb',
            seq: 1,
            startOp: history.startOp + history.ops.length,
            deps: A.getHeads(base),
            time: 0,
            message: '',
            ops: [
              {
                action,
                obj: '_root',
                key: allowed ? 'allowed' : 'protected',
                pred,
                ...(action === 'set' || action === 'inc'
                  ? { value: 3, datatype: 'int' }
                  : {}),
              },
            ],
          });
          plan = session.prepareRemote([frame], { inspectOperations: true });
          assertDocumentOperationsAllowed(plan, [['allowed']]);
          plan.commit();
          expect(session.document.protected).toBe(2);
        } catch (error) {
          // Rejection is valid; an assertion failure after a successful commit must escape.
          if (plan && !plan.isCurrent()) throw error;
          plan?.discard();
          expect(session.document.protected).toBe(2);
        } finally {
          session.close();
          A.free(base);
          A.free(session.document);
        }
      },
    ),
    { seed: 2012316, numRuns: 96 },
  );
});

test('bounds native actor identifiers before expanding them into the authorization ancestry index', () => {
  fc.assert(
    fc.property(fc.integer({ min: 64, max: 1024 }), (bytes) => {
      const base = A.from({ allowed: {} }, { actor: 'aa'.repeat(bytes) });
      const session = new AutomergeProvider<{
        allowed: { value?: number };
      }>().createDocumentSession(base);
      if (bytes > 64) {
        expect(() =>
          session.prepareLocal(
            '',
            (draft) => {
              draft.allowed.value = 1;
            },
            { inspectOperations: true },
          ),
        ).toThrow(/actor exceeds bounds/);
        expect(session.document.allowed.value).toBeUndefined();
      } else {
        const plan = session.prepareLocal(
          '',
          (draft) => {
            draft.allowed.value = 1;
          },
          { inspectOperations: true },
        );
        assertDocumentOperationsAllowed(plan, [['allowed']]);
        plan.discard();
      }
      session.close();
      A.free(session.document);
    }),
    { seed: 2012317, numRuns: 12, examples: [[64], [65], [1024]] },
  );
});

test('mixed unrestricted and scoped writers retain the incremental ancestry index across new objects', () => {
  const index = jest.spyOn(AutomergeOperationIndex, 'from');
  try {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0, max: 100 }), {
          minLength: 3,
          maxLength: 12,
        }),
        (values) => {
          index.mockClear();
          const initial = A.from<{
            profiles: Record<string, { value: number }>;
          }>({ profiles: {} }, { actor: 'aa' });
          const session = new AutomergeProvider<{
            profiles: Record<string, { value: number }>;
          }>().createDocumentSession(initial);
          session
            .prepareLocal(
              '',
              (draft) => {
                draft.profiles.seed = { value: 0 };
              },
              { inspectOperations: true },
            )
            .commit();
          for (const [position, value] of values.entries()) {
            const key = `item-${position}`;
            session
              .prepareLocal('', (draft) => {
                draft.profiles[key] = { value };
              })
              .commit();
            const scoped = session.prepareLocal(
              '',
              (draft) => {
                draft.profiles[key].value = value + 1;
              },
              { inspectOperations: true },
            );
            expect(scoped.operationPaths!()).toEqual([
              ['profiles', key, 'value'],
            ]);
            assertDocumentOperationsAllowed(scoped, [['profiles']]);
            scoped.commit();
          }
          expect(index).toHaveBeenCalledTimes(1);
          session.close();
          A.free(session.document);
        },
      ),
      { seed: 2012318, numRuns: 12 },
    );
  } finally {
    index.mockRestore();
  }
});

test('native counters, Unicode text splices and rich-text marks retain their container targets', () => {
  fc.assert(
    fc.property(
      fc.constantFrom('hello', 'é', '💻', '🐻‍❄️'),
      fc.integer({ min: 1, max: 20 }),
      (text, value) => {
        type Rich = { profile: { name: string }; counter: A.Counter };
        const initial = A.from<Rich>(
          { profile: { name: 'seed' }, counter: new A.Counter(1) },
          { actor: 'aa' },
        );
        const session = new AutomergeProvider<Rich>().createDocumentSession(
          initial,
        );
        const plan = session.prepareLocal(
          '',
          (draft) => {
            A.splice(draft, ['profile', 'name'], 0, 1, text);
            A.mark(
              draft,
              ['profile', 'name'],
              { start: 0, end: 1 },
              'bold',
              true,
            );
            draft.counter.increment(value);
          },
          { inspectOperations: true },
        );
        expect(pathsOf(plan.operationPaths!())).toEqual(
          pathsOf([['counter'], ['profile', 'name']]),
        );
        expect(() =>
          assertDocumentOperationsAllowed(plan, [['profile', 'name']]),
        ).toThrow();
        assertDocumentOperationsAllowed(plan, [
          ['profile', 'name'],
          ['counter'],
        ]);
        plan.commit();
        expect(session.document.profile.name).toBe(text + 'eed');
        expect(session.document.counter.value).toBe(value + 1);
        session.close();
        A.free(session.document);
      },
    ),
    { seed: 2012319, numRuns: 16 },
  );
});

test('real counter predecessor fuzzing admits a valid increment and preserves protected counters under forgery', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 100 }),
      fc.integer({ min: 0, max: 3 }),
      (value, mode) => {
        type Counters = { allowed: A.Counter; protected: A.Counter };
        const base = A.from<Counters>(
          { allowed: new A.Counter(1), protected: new A.Counter(2) },
          { actor: 'aa' },
        );
        const change = A.decodeChange(A.getAllChanges(base)[0]);
        const reference = (key: string) =>
          `${change.startOp + change.ops.findIndex((op) => op.key === key)}@${change.actor}`;
        const increment = (pred: string[]) =>
          A.encodeChange({
            actor: 'bb',
            seq: 1,
            startOp: change.startOp + change.ops.length,
            deps: A.getHeads(base),
            time: 0,
            message: '',
            ops: [{ action: 'inc', obj: '_root', key: 'allowed', pred, value }],
          });
        const valid = new AutomergeProvider<Counters>().createDocumentSession(
          A.clone(base),
        );
        const accepted = valid.prepareRemote(
          [increment([reference('allowed')])],
          { inspectOperations: true },
        );
        assertDocumentOperationsAllowed(accepted, [['allowed']]);
        accepted.commit();
        expect(valid.document.allowed.value).toBe(1 + value);
        expect(valid.document.protected.value).toBe(2);
        const hostile = new AutomergeProvider<Counters>().createDocumentSession(
          A.clone(base),
        );
        const pred =
          mode === 0
            ? [reference('protected')]
            : mode === 1
              ? [reference('allowed'), reference('protected')]
              : mode === 2
                ? [reference('protected'), reference('protected')]
                : ['999999@cc'];
        let plan: ReturnType<typeof hostile.prepareRemote> | undefined;
        try {
          plan = hostile.prepareRemote([increment(pred)], {
            inspectOperations: true,
          });
          assertDocumentOperationsAllowed(plan, [['allowed']]);
          plan.commit();
        } catch {
          plan?.discard();
        }
        expect(hostile.document.protected.value).toBe(2);
        const continuation = hostile.prepareLocal(
          '',
          (draft) => {
            draft.protected.increment(1);
          },
          { inspectOperations: true },
        );
        assertDocumentOperationsAllowed(continuation, [['protected']]);
        continuation.commit();
        expect(hostile.document.protected.value).toBe(3);
        valid.close();
        hostile.close();
        for (const doc of [base, valid.document, hostile.document]) A.free(doc);
      },
    ),
    {
      seed: 2012320,
      numRuns: 32,
      examples: [
        [1, 0],
        [1, 1],
        [1, 2],
        [1, 3],
      ],
    },
  );
});

test('tracks immutable object ancestry after a parent is deleted and treats sequence descendants atomically', () => {
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 1000 }), (value) => {
      const base = initial();
      const removed = A.change(A.clone(base, { actor: 'ff' }), (draft) => {
        delete draft.profile;
      });
      const hidden = A.change(A.clone(base, { actor: '01' }), (draft) => {
        draft.profile!.permissions = value;
      });
      const session = new AutomergeProvider<State>().createDocumentSession(
        A.clone(removed),
      );
      const plan = session.prepareRemote(A.getChanges(base, hidden), {
        inspectOperations: true,
      });
      expect(session.document.profile).toBeUndefined();
      expect(plan.operationPaths!()).toEqual([['profile', 'permissions']]);
      expect(() =>
        assertDocumentOperationsAllowed(plan, [['profile', 'name']]),
      ).toThrow();
      plan.discard();
      const sequence = session.prepareLocal(
        '',
        (draft) => {
          draft.items[0].value = value;
        },
        { inspectOperations: true },
      );
      expect(sequence.operationPaths!()).toEqual([['items']]);
      expect(() =>
        assertDocumentOperationsAllowed(sequence, [['items', '0']]),
      ).toThrow();
      assertDocumentOperationsAllowed(sequence, [['items']]);
      sequence.commit();
      session.close();
      for (const doc of [base, removed, hidden, session.document]) A.free(doc);
    }),
    { seed: 2012313, numRuns: 20 },
  );
});

test('inspects deletion and insertion targets before discard and rebuilds no history index for accepted ordinary edits', () => {
  const index = jest.spyOn(AutomergeOperationIndex, 'from');
  try {
    fc.assert(
      fc.property(
        fc.array(fc.boolean(), { minLength: 15, maxLength: 40 }),
        (accepted) => {
          index.mockClear();
          const session = new AutomergeProvider<State>().createDocumentSession(
            initial(),
          );
          let expected = 0;
          for (let position = 0; position < accepted.length; position++) {
            const plan = session.prepareLocal(
              '',
              (draft) => {
                draft.allowed = position + 1;
              },
              { inspectOperations: true },
            );
            assertDocumentOperationsAllowed(plan, [['allowed']]);
            if (accepted[position]) {
              plan.commit();
              expected = position + 1;
            } else plan.discard();
            expect(session.document.allowed).toBe(expected);
          }
          expect(index).toHaveBeenCalledTimes(1);
          session.close();
          A.free(session.document);
        },
      ),
      { seed: 2012314, numRuns: 15 },
    );
  } finally {
    index.mockRestore();
  }
});
