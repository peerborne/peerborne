import { expect, jest, test } from '@jest/globals';
import type { Doc } from '@automerge/automerge';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import {
  missedTailCatchUpScenario,
  retiredEpochScenario,
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

test('re-signs an Automerge edit written offline across an epoch change', async () => {
  const result = await retiredEpochScenario(adapter);
  expect(result.offline).toContain('Document change committed');
  expect(result.update).toEqual({
    resent: 2,
    waiting: 0,
    skipped: 0,
    dropped: 0,
    diverged: false,
  });
  expect(result.errors).toEqual([]);
  expect(result.leftover).toBe(0);
  for (const view of result.views)
    expect(view).toEqual({ afterReturn: 11, c0: 2, m1a: 3, offlineEdit: 11 });
}, 30_000);
