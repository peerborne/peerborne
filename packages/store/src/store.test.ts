import { describe, expect, test } from '@jest/globals';
import { createDocumentStore } from './index.js';
import { deferred, TestDocument } from './test-utils.js';

describe('framework-independent document store', () => {
  test('construction and snapshot subscriptions perform no I/O during SSR', () => {
    const source = new TestDocument();
    const store = createDocumentStore(source);
    const unsubscribe = store.subscribe(() => {});
    expect(store.getSnapshot()).toBe(store.getServerSnapshot());
    expect(store.getSnapshot()).toBe(store.getSnapshot());
    expect(source.openCount).toBe(0);
    expect(source.handlers.size).toBe(0);
    unsubscribe();
  });

  test('publishes new snapshots for in-place CRDT updates and detached ACL arrays', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(source);
    await store.start();
    const before = store.getSnapshot();
    source.document.title = 'Remote';
    source.emit();
    expect(store.getSnapshot()).not.toBe(before);
    expect(store.getSnapshot().data).toBe(before.data);
    expect(store.getSnapshot().revision).toBeGreaterThan(before.revision);
    source.readers.push('another');
    expect(store.getSnapshot().readers).toEqual(['reader']);
    expect(Object.isFrozen(store.getSnapshot().readers)).toBe(true);
    expect(store.getServerSnapshot().status).toBe('idle');
    await store.stop();
  });

  test('shares one open across consumers and closes only after the final release', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(source);
    const first = store.connect();
    const second = store.connect();
    await store.start();
    first();
    first();
    await Promise.resolve();
    expect(source.closeCount).toBe(0);
    second();
    await Promise.resolve();
    await store.stop();
    expect(source.openCount).toBe(1);
    expect(source.closeCount).toBe(1);
    expect(source.handlers.size).toBe(0);
    expect(store.getSnapshot().data).toBeUndefined();
  });

  test('a StrictMode-style release/reconnect does not close the shared handle', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(source);
    store.connect()();
    const release = store.connect();
    await store.start();
    expect(source.openCount).toBe(1);
    expect(source.closeCount).toBe(0);
    release();
    await Promise.resolve();
    await store.stop();
  });

  test('release during a pending open eventually cleans up without leaking handlers', async () => {
    const gate = deferred();
    const source = new TestDocument();
    source.openGate = gate.promise;
    const store = createDocumentStore(source);
    const release = store.connect();
    await Promise.resolve();
    release();
    await Promise.resolve();
    gate.resolve();
    await store.stop();
    expect(source.closeCount).toBe(1);
    expect(source.handlers.size).toBe(0);
    expect(store.getSnapshot().status).toBe('closed');
  });

  test('open failures are observable and release the failed subscription', async () => {
    const source = new TestDocument();
    source.openError = new Error('Denied');
    const store = createDocumentStore(source);
    await expect(store.start()).rejects.toThrow('Denied');
    expect(store.getSnapshot().status).toBe('error');
    expect(source.handlers.size).toBe(0);
    source.openError = undefined;
    await store.start();
    expect(store.getSnapshot().status).toBe('ready');
    await store.stop();
  });

  test('preserves mutation promises and serializes close after pending writes', async () => {
    const source = new TestDocument();
    const gate = deferred();
    source.writeGate = gate.promise;
    const store = createDocumentStore(source);
    await store.start();
    const writing = store.change((data) => {
      data.title = 'Saved';
    });
    const stopping = store.stop();
    await Promise.resolve();
    expect(source.closeCount).toBe(0);
    gate.resolve();
    await writing;
    await stopping;
    expect(source.document.title).toBe('Saved');
    expect(source.closeCount).toBe(1);
  });

  test('mutation rejection reaches both the caller and the snapshot', async () => {
    const source = new TestDocument();
    source.writeError = new Error('Read only');
    const store = createDocumentStore(source);
    await expect(store.change(() => {})).rejects.toThrow('Read only');
    expect(store.getSnapshot().status).toBe('ready');
    expect(store.getSnapshot().error).toBe(source.writeError);
    source.writeError = undefined;
    await store.change((data) => {
      data.title = 'Retry';
    });
    expect(store.getSnapshot().error).toBeUndefined();
    await store.stop();
  });

  test('does not replace newer membership notifications with stale initialization reads', async () => {
    const source = new TestDocument();
    const gate = deferred();
    source.readGate = gate.promise;
    const store = createDocumentStore(source);
    const starting = store.start();
    await Promise.resolve();
    source.readers = ['new-reader'];
    source.emit();
    source.readers = ['stale-read'];
    gate.resolve();
    await starting;
    expect(store.getSnapshot().readers).toEqual(['new-reader']);
    await store.stop();
  });

  test('supports externally owned document lifecycles', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(source, { manageLifecycle: false });
    await store.start();
    await store.stop();
    expect(source.openCount).toBe(0);
    expect(source.closeCount).toBe(0);
    expect(source.handlers.size).toBe(0);
  });

  test('subscription setup failures are observable and clean up the handle', async () => {
    const source = new TestDocument();
    source.subscribe = () => {
      throw new Error('Subscribe failed');
    };
    const store = createDocumentStore(source);
    await expect(store.start()).rejects.toThrow('Subscribe failed');
    expect(store.getSnapshot().status).toBe('error');
    expect(source.closeCount).toBe(1);
  });

  test('an unsubscribe failure does not skip closing the document', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(source);
    await store.start();
    source.unsubscribe = () => {
      throw new Error('Unsubscribe failed');
    };
    await expect(store.stop()).rejects.toThrow('Unsubscribe failed');
    expect(source.closeCount).toBe(1);
    expect(store.getSnapshot().status).toBe('error');
    expect(store.getSnapshot().data).toBeUndefined();
  });
});
