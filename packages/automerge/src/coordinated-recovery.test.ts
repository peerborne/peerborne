import { expect, jest, test } from '@jest/globals';
import type { Doc } from '@automerge/automerge';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import {
  lostFrameRedeliveryScenario,
  missedTailCatchUpScenario,
} from '../../core/src/__testutils__/coordinated-scenarios.js';

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

test('resumes an Automerge member that missed a writer’s tail through the controller checkpoint', async () => {
  const { errors, views } = await missedTailCatchUpScenario(adapter);
  expect(errors).toEqual([]);
  for (const view of views)
    expect(view).toEqual({ ctl: 3, four: 4, one: 3, three: 5, two: 3 });
}, 30_000);

test('recovers a lost Automerge frame from a causal chain through redelivery', async () => {
  const { errors, held, views } = await lostFrameRedeliveryScenario(adapter);
  expect(errors).toEqual([]);
  expect(held).toEqual({});
  for (const view of views)
    expect(view).toEqual({ c0: 2, c1: 2, c2: 2, c3: 2 });
}, 30_000);
