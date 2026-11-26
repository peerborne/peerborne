import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import * as Y from 'yjs';
import type { Doc } from 'yjs';
import { DocumentCausalDependencyError } from '@peerborne/core';
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

const replicaOf = (base: Doc, client: number) => {
  const doc = new Y.Doc();
  for (const [name, root] of base.share) {
    if (root instanceof Y.Map) doc.getMap(name);
    if (root instanceof Y.Text) doc.getText(name);
  }
  Y.applyUpdateV2(doc, Y.encodeStateAsUpdateV2(base));
  doc.clientID = client;
  return doc;
};
const since = (doc: Doc, base: Doc) =>
  Y.encodeStateAsUpdateV2(doc, Y.encodeStateVector(base));

function dependencyMiss(run: () => unknown): DocumentCausalDependencyError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(DocumentCausalDependencyError);
    return error as DocumentCausalDependencyError;
  }
  throw new Error('Expected a missing causal dependency');
}

test('keeps its mirror after a dependency miss and is ready once the named update applies', () => {
  const base = new Y.Doc();
  base.clientID = 10;
  base.getText('t').insert(0, 'base;');
  const first = replicaOf(base, 20);
  first.getText('t').insert(5, 'first;');
  const dependency = since(first, base);
  const second = replicaOf(first, 30);
  second.getText('t').insert(11, 'second;');
  const dependent = since(second, first);
  const unrelated = replicaOf(base, 40);
  unrelated.getMap('m').set('k', 1);
  const replica = replicaOf(base, 50);
  const provider = new YjsProvider();
  const snapshots = jest.spyOn(provider, 'getSnapshot');
  const session = provider.createDocumentSession(replica);
  session.prepareRemote(since(unrelated, base)).commit();
  snapshots.mockClear();
  const miss = dependencyMiss(() => session.prepareRemote(dependent));
  expect(miss.ready?.()).toBe(false);
  session.prepareRemote(dependency).commit();
  expect(miss.ready?.()).toBe(true);
  session.prepareRemote(dependent).commit();
  expect(snapshots).not.toHaveBeenCalled();
  expect(replica.getText('t').toString()).toBe('base;first;second;');
  session.close();
  for (const doc of [base, first, second, unrelated, replica]) doc.destroy();
});

test('holds a field-scoped update that an accepted deletion collected while its dependency is missing', () => {
  const base = new Y.Doc();
  base.clientID = 10;
  base.getMap('root').set('a', new Y.Map<unknown>([['x', 1]]));
  base.getMap('root').set('b', new Y.Map<unknown>([['c', 0]]));
  const map = (doc: Doc, key: string) =>
    doc.getMap('root').get(key) as Y.Map<unknown>;
  const deleter = replicaOf(base, 30);
  deleter.getMap('root').delete('a');
  const deletion = since(deleter, base);
  const other = replicaOf(base, 40);
  map(other, 'b').set('c', 1);
  const dependency = since(other, base);
  const sender = replicaOf(other, 20);
  map(sender, 'a').set('x', 2);
  map(sender, 'b').set('c', 2);
  const update = since(sender, other);
  const replica = replicaOf(base, 50);
  Y.applyUpdateV2(replica, deletion);
  const session = new YjsProvider().createDocumentSession(replica);
  const miss = dependencyMiss(() =>
    session.prepareRemote(update, { inspectOperations: true }),
  );
  expect(miss.ready?.()).toBe(false);
  session.prepareRemote(dependency).commit();
  expect(miss.ready?.()).toBe(true);
  const plan = session.prepareRemote(update, { inspectOperations: true });
  expect(plan.operationPaths!()).toContainEqual(['root', 'b', 'c']);
  plan.commit();
  expect(map(replica, 'b').get('c')).toBe(2);
  session.close();
  for (const doc of [base, deleter, other, sender, replica]) doc.destroy();
});
