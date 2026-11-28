import { expect, jest, test } from '@jest/globals';
import type { Doc } from '@automerge/automerge';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import {
  authorityRecoveryBeforeOpenScenario,
  joinCatchUpScenario,
  lostFrameRedeliveryScenario,
  missedTailCatchUpScenario,
  missedWindowCatchUpScenario,
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

test('an Automerge member added in a new epoch converges without an application relay', async () => {
  const result = await joinCatchUpScenario(adapter);
  expect(result.traffic.requests).toContain(2);
  expect(result.traffic.checkpoints.length).toBeGreaterThan(0);
  expect(new Set(result.traffic.checkpoints)).toEqual(new Set([0]));
  expect(result).toMatchObject({ before: true, joined: true, after: true });
  expect(result.empty).toEqual({});
  for (const view of result.views)
    expect(view).toEqual({ first: 5, fourth: 6, second: 6, third: 5 });
}, 60_000);

test('an Automerge member that missed more frames than peers retain converges through a topic checkpoint', async () => {
  const result = await missedWindowCatchUpScenario(adapter);
  expect(result.traffic.redeliveries).toContain(2);
  expect(result.traffic.requests).toContain(2);
  expect(new Set(result.traffic.checkpoints)).toEqual(new Set([0]));
  expect(result).toMatchObject({
    joined: true,
    behind: true,
    recovered: true,
    live: true,
    held: false,
  });
  expect(Object.keys(result.views[2] as object)).toHaveLength(73);
  for (const view of result.views) expect(view).toEqual(result.views[2]);
}, 90_000);

test('recovers a lost Automerge frame from a causal chain through redelivery', async () => {
  const { errors, held, views } = await lostFrameRedeliveryScenario(adapter);
  expect(errors).toEqual([]);
  expect(held).toEqual({});
  for (const view of views)
    expect(view).toEqual({ c0: 2, c1: 2, c2: 2, c3: 2 });
}, 30_000);

test('re-signs an Automerge edit written offline across an epoch change', async () => {
  const result = await retiredEpochScenario(adapter);
  expect(result.offline).toContain('Document change committed');
  expect(result.update).toEqual({
    resent: 1,
    waiting: 0,
    skipped: 1,
    dropped: 0,
    diverged: false,
  });
  expect(result.errors).toEqual([]);
  expect(result.leftover).toBe(0);
  for (const view of result.views)
    expect(view).toEqual({ afterReturn: 11, c0: 2, m1a: 3, offlineEdit: 11 });
}, 30_000);

test('an Automerge controller recovers pending authority before it exposes content', async () => {
  const result = await authorityRecoveryBeforeOpenScenario(adapter);
  expect(result.errors).toEqual([]);
  expect(result.openRejected).toBe(true);
  expect(result.fenced).toBe(true);
  expect(result.reapplyRejected).toBe(true);
  expect(result.view).toEqual(result.expected);
}, 30_000);
