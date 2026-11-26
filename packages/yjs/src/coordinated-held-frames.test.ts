import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import type { Doc } from 'yjs';
import { YjsJSONSerializer, YjsProvider } from './peerborne-yjs.js';
import { crossAuthorReorderScenario } from '../../core/src/__testutils__/coordinated-scenarios.js';

jest.mock('@helia/unixfs', () => ({ unixfs: () => ({}) }));

const adapter = {
  crdt: new YjsProvider(),
  serializer: new YjsJSONSerializer(),
  edit: (label: string) => (document: Doc) => {
    const text = document.getText('t');
    text.insert(text.length, `${label};`);
  },
  read: (document: Doc) => document.getText('t').toString(),
};

const labels = (view: unknown) =>
  (view as string).split(';').filter(Boolean).sort();

test('applies a causal chain from two Yjs text authors in any arrival order', async () => {
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
        expect(labels(reordered)).toHaveLength(9);
        const [final, ...rest] = result.final;
        for (const view of rest) expect(final).toEqual(view);
        expect(labels(final)).toHaveLength(11);
      },
    ),
    {
      seed: 202611253,
      numRuns: 6,
      examples: [[[1, 0, 2, 3, 4, 5]], [[5, 4, 3, 2, 1, 0]]],
    },
  );
}, 60_000);
