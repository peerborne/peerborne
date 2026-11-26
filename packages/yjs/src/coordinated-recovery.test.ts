import { expect, jest, test } from '@jest/globals';
import type { Doc } from 'yjs';
import { YjsJSONSerializer, YjsProvider } from './peerborne-yjs.js';
import { missedTailCatchUpScenario } from '../../core/src/__testutils__/coordinated-scenarios.js';

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
