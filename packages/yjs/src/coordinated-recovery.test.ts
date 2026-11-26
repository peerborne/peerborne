import { expect, jest, test } from '@jest/globals';
import type { Doc } from 'yjs';
import { YjsJSONSerializer, YjsProvider } from './peerborne-yjs.js';
import {
  joinCatchUpScenario,
  lostFrameRedeliveryScenario,
  missedTailCatchUpScenario,
  missedWindowCatchUpScenario,
  retiredEpochScenario,
} from '../../core/src/__testutils__/coordinated-scenarios.js';

jest.mock('@helia/unixfs', () => ({ unixfs: () => ({}) }));

const adapter = {
  crdt: new YjsProvider(),
  serializer: new YjsJSONSerializer(),
  edit: (label: string) => (document: Doc) => {
    const text = document.getText('t');
    text.insert(text.length, `${label};`);
  },
  read: (document: Doc) =>
    document.getText('t').toString().split(';').filter(Boolean).sort(),
};

test('resumes a Yjs member that missed a writer’s tail through the controller checkpoint', async () => {
  const { errors, views } = await missedTailCatchUpScenario(adapter);
  expect(errors).toEqual([]);
  for (const view of views)
    expect(view).toEqual(['ctl', 'four', 'one', 'three', 'two']);
}, 30_000);

test('a Yjs member added in a new epoch converges without an application relay', async () => {
  const result = await joinCatchUpScenario(adapter);
  expect(result.traffic.requests).toContain(2);
  expect(result.traffic.checkpoints.length).toBeGreaterThan(0);
  expect(new Set(result.traffic.checkpoints)).toEqual(new Set([0]));
  expect(result).toMatchObject({ before: true, joined: true, after: true });
  expect(result.empty).toEqual([]);
  for (const view of result.views)
    expect(view).toEqual(['first', 'fourth', 'second', 'third']);
}, 60_000);

test('a Yjs member that missed more frames than peers retain converges through a topic checkpoint', async () => {
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
  expect(result.views[2]).toHaveLength(73);
  for (const view of result.views) expect(view).toEqual(result.views[2]);
}, 90_000);

test('recovers a lost Yjs frame from a causal chain through redelivery', async () => {
  const { errors, held, views } = await lostFrameRedeliveryScenario(adapter);
  expect(errors).toEqual([]);
  expect(held).toEqual([]);
  for (const view of views) expect(view).toEqual(['c0', 'c1', 'c2', 'c3']);
}, 30_000);

test('re-signs a Yjs edit written offline across an epoch change', async () => {
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
    expect(view).toEqual(['afterReturn', 'c0', 'm1a', 'offlineEdit']);
}, 30_000);
