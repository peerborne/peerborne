import { describe, expect, test } from '@jest/globals';
import { createCollection } from '@tanstack/db';
import { createDocumentStore, type DocumentHandle } from '@peerborne/store';
import { peerborneCollectionOptions } from './index.js';

type Row = { id: string; title: string };
type Data = { items: Record<string, Row> };
type Change = (data: Data) => void;

function fixture(duplicate = false) {
  const data: Data = { items: { a: { id: 'a', title: 'Initial' } } };
  const handlers = new Map<
    string,
    (data: Data, readers: string[], writers: string[], hashes: string[]) => void
  >();
  let opens = 0;
  let closes = 0;
  let writeError: Error | undefined;
  let openError: Error | undefined;
  let retireOnWrite = false;
  let retired = false;
  const emit = () => {
    for (const handler of handlers.values()) handler(data, [], [], []);
  };
  const source: DocumentHandle<Data, Change, string> = {
    document: data,
    get retired() {
      return retired;
    },
    async open() {
      opens++;
      if (openError) throw openError;
    },
    async close() {
      closes++;
    },
    async getReaders() {
      return [];
    },
    async getWriters() {
      return [];
    },
    async change(change) {
      if (retired) throw new Error('Document was retired');
      if (retireOnWrite) {
        change(data);
        retired = true;
        throw new Error(
          'Document was retired: the change could not be rolled back',
        );
      }
      if (writeError) throw writeError;
      change(data);
      emit();
    },
    subscribe(id, handler) {
      handlers.set(id, handler);
    },
    unsubscribe(id) {
      handlers.delete(id);
    },
    subscribeDeliveryState() {},
    unsubscribeDeliveryState() {},
  };
  const store = createDocumentStore(() => source);
  const createProjection = () =>
    createCollection(
      peerborneCollectionOptions({
        id: `fixture-${Math.random()}`,
        store,
        getKey: (row: Row) => row.id,
        select: (doc) =>
          duplicate ? [doc.items.a, doc.items.a] : Object.values(doc.items),
        mutate: (mutations) => (doc) => {
          for (const mutation of mutations) {
            if (mutation.type === 'delete') delete doc.items[mutation.key];
            else if (mutation.type === 'insert')
              doc.items[mutation.key] = mutation.value;
            else Object.assign(doc.items[mutation.key], mutation.changes);
          }
        },
      }),
    );
  const collection = createProjection();
  return {
    data,
    collection,
    createProjection,
    store,
    handlers,
    emit,
    get opens() {
      return opens;
    },
    get closes() {
      return closes;
    },
    denyWrite() {
      writeError = new Error('Read only');
    },
    denyOpen() {
      openError = new Error('Open denied');
    },
    allowOpen() {
      openError = undefined;
    },
    retireOnWrite() {
      retireOnWrite = true;
    },
    async cleanup() {
      await collection.cleanup();
      await Promise.resolve();
      await store.stop();
    },
  };
}

describe('experimental TanStack DB collection', () => {
  test('construction is inert and projections detach rows from mutable CRDT state', async () => {
    const f = fixture();
    expect(f.opens).toBe(0);
    await f.collection.preload();
    expect(f.opens).toBe(1);
    expect(f.collection.get('a')?.title).toBe('Initial');
    f.data.items.a.title = 'Remote';
    expect(f.collection.get('a')?.title).toBe('Initial');
    f.emit();
    expect(f.collection.get('a')?.title).toBe('Remote');
    delete f.data.items.a;
    f.emit();
    expect(f.collection.has('a')).toBe(false);
    await f.cleanup();
    expect(f.handlers.size).toBe(0);
  });

  test('insert, field update and deletion flow through the document mutation boundary', async () => {
    const f = fixture();
    await f.collection.preload();
    await f.collection.insert({ id: 'b', title: 'Added' }).when('settled');
    expect(f.data.items.b.title).toBe('Added');
    await f.collection
      .update('b', (row) => {
        row.title = 'Edited';
      })
      .when('settled');
    expect(f.data.items.b.title).toBe('Edited');
    expect(f.collection.get('b')?.title).toBe('Edited');
    await f.collection.delete('b').when('settled');
    expect(f.data.items.b).toBeUndefined();
    expect(f.collection.has('b')).toBe(false);
    await f.cleanup();
  });

  test('an insert before any query starts sync opens the document first', async () => {
    const f = fixture();
    expect(f.opens).toBe(0);
    await f.collection.insert({ id: 'b', title: 'Added' }).when('settled');
    expect(f.opens).toBe(1);
    expect(f.data.items.b.title).toBe('Added');
    expect(f.collection.get('a')?.title).toBe('Initial');
    expect(f.collection.get('b')?.title).toBe('Added');
    await f.cleanup();
  });

  test('failed writes reject and roll back optimistic UI state', async () => {
    const f = fixture();
    await f.collection.preload();
    f.denyWrite();
    const transaction = f.collection.update('a', (row) => {
      row.title = 'Denied';
    });
    await expect(transaction.when('settled')).rejects.toThrow('Read only');
    expect(f.data.items.a.title).toBe('Initial');
    expect(f.collection.get('a')?.title).toBe('Initial');
    await f.cleanup();
  });

  test('a retired document fails the collection instead of projecting the discarded edit', async () => {
    const f = fixture();
    await f.collection.preload();
    const statuses: string[] = [];
    f.store.subscribe(() => statuses.push(f.store.getSnapshot().status));
    f.retireOnWrite();
    const transaction = f.collection.update('a', (row) => {
      row.title = 'Discarded';
    });
    await expect(transaction.when('settled')).rejects.toThrow('retired');
    expect(f.data.items.a.title).toBe('Discarded');
    expect(f.collection.health.hasErrors).toBe(true);
    expect(f.collection.get('a')?.title).toBe('Initial');
    f.emit();
    expect(f.collection.get('a')?.title).toBe('Initial');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(statuses).toEqual(['retired', 'closed']);
    expect(f.closes).toBe(1);
    await f.cleanup();
    expect(f.handlers.size).toBe(0);
  });

  test('a collection restarted after a transient open failure retries the open', async () => {
    const f = fixture();
    f.denyOpen();
    await expect(f.collection.preload()).rejects.toThrow('Open denied');
    expect(f.opens).toBe(1);
    expect(f.store.getSnapshot().status).toBe('error');
    await f.collection.cleanup();

    f.allowOpen();
    const restarted = f.createProjection();
    await restarted.preload();
    expect(f.opens).toBe(2);
    expect(restarted.get('a')?.title).toBe('Initial');
    await restarted.cleanup();
    await f.cleanup();
  });

  test('initial source failures reject preload instead of leaving it pending', async () => {
    const f = fixture();
    f.denyOpen();
    await expect(f.collection.preload()).rejects.toThrow('Open denied');
    await f.cleanup();
  });

  test('duplicate projection keys fail initial sync and release document ownership', async () => {
    const f = fixture(true);
    await expect(f.collection.preload()).rejects.toThrow('Duplicate key');
    await f.cleanup();
    expect(f.handlers.size).toBe(0);
  });
});
