import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { change, clone, getChanges, init } from '@automerge/automerge';
import type { Doc } from '@automerge/automerge';
import { DocumentCausalDependencyError } from '@peerborne/core';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import { crossAuthorReorderScenario } from '../../core/src/__testutils__/coordinated-scenarios.js';

jest.mock('@helia/unixfs', () => ({ unixfs: () => ({}) }));

type State = Record<string, number>;
const adapter = {
  crdt: new AutomergeProvider<State>(),
  serializer: new AutomergeJSONSerializer(),
  edit: (label: string) => (draft: State) => {
    draft[label] = label.length;
  },
  read: (document: Doc<State>) => JSON.parse(JSON.stringify(document)),
};

test('applies a causal chain from two Automerge authors in any arrival order', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.shuffledSubarray([0, 1, 2, 3, 4, 5], { minLength: 6, maxLength: 6 }),
      async (order) => {
        const result = await crossAuthorReorderScenario(adapter, (chain) =>
          order.map((index) => chain[index]),
        );
        expect(result.errors).toEqual([]);
        const [reordered, ...others] = result.reordered;
        for (const view of others) expect(reordered).toEqual(view);
        expect(Object.keys(reordered as State)).toHaveLength(9);
        const [final, ...rest] = result.final;
        for (const view of rest) expect(final).toEqual(view);
        expect(Object.keys(final as State)).toHaveLength(11);
      },
    ),
    {
      seed: 202611252,
      numRuns: 6,
      examples: [[[1, 0, 2, 3, 4, 5]], [[5, 4, 3, 2, 1, 0]]],
    },
  );
}, 60_000);

test('names missing Automerge dependencies before staging and is ready once they apply', () => {
  const base = change(init<State>(), (draft) => {
    draft.base = 1;
  });
  const first = change(clone(base), (draft) => {
    draft.first = 1;
  });
  const second = change(first, (draft) => {
    draft.second = 1;
  });
  const dependency = getChanges(base, first),
    dependent = getChanges(first, second);
  const session = new AutomergeProvider<State>().createDocumentSession(
    clone(base),
  );
  let miss: unknown;
  try {
    session.prepareRemote(dependent);
  } catch (error) {
    miss = error;
  }
  expect(miss).toBeInstanceOf(DocumentCausalDependencyError);
  const ready = (miss as DocumentCausalDependencyError).ready!;
  expect(ready()).toBe(false);
  session.prepareRemote(dependency).commit();
  expect(ready()).toBe(true);
  session.prepareRemote(dependent).commit();
  expect({ ...session.document }).toEqual({ base: 1, first: 1, second: 1 });
  session.close();
});
