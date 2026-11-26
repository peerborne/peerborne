import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import type { Doc } from '@automerge/automerge';
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
