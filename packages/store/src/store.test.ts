import { describe, expect, test } from '@jest/globals';
import { createDocumentStore } from './index.js';
import { deferred, TestDocument } from './test-utils.js';

const settle = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

describe('framework-independent document store', () => {
  test('construction and snapshot subscriptions perform no I/O during SSR', () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    const unsubscribe = store.subscribe(() => {});
    expect(store.getSnapshot()).toBe(store.getServerSnapshot());
    expect(store.getSnapshot()).toBe(store.getSnapshot());
    expect(source.openCount).toBe(0);
    expect(source.handlers.size).toBe(0);
    unsubscribe();
  });

  test('publishes new snapshots for in-place CRDT updates and detached ACL arrays', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
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
    const store = createDocumentStore(() => source);
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
    const store = createDocumentStore(() => source);
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
    const store = createDocumentStore(() => source);
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
    const store = createDocumentStore(() => source);
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
    const store = createDocumentStore(() => source);
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
    const store = createDocumentStore(() => source);
    await store.start();
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

  test('exposes a committed but undelivered change until a later change is published', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    await store.start();
    const offline = new Error('PublishError.NoPeersSubscribedToTopic');
    source.undeliveredError = offline;
    await store.change((data) => {
      data.title = 'Offline';
    });
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready',
      data: { title: 'Offline' },
      error: undefined,
      deliveryFailure: { changeId: 'cid-1', error: offline },
    });

    source.document.title = 'Remote';
    source.emit();
    expect(store.getSnapshot().deliveryFailure?.changeId).toBe('cid-1');

    source.undeliveredError = undefined;
    await store.change((data) => {
      data.title = 'Online';
    });
    expect(store.getSnapshot().deliveryFailure).toBeUndefined();
    await store.stop();
    expect(source.deliveryHandlers.size).toBe(0);
  });

  test('a delivery failure clears once a later local frame is published outside the store', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(source, { manageLifecycle: false });
    await store.start();
    source.undeliveredError = new Error('NoPeersSubscribedToTopic');
    await store.change((data) => {
      data.title = 'Offline';
    });
    expect(store.getSnapshot().deliveryFailure?.changeId).toBe('cid-1');

    source.undeliveredError = undefined;
    await source.change((data) => {
      data.title = 'Online, carries the earlier change';
    });
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready',
      data: { title: 'Online, carries the earlier change' },
      deliveryFailure: undefined,
    });
    await store.stop();
  });

  test('starts with the delivery failure that the handle already holds', async () => {
    const source = new TestDocument();
    source.deliveryFailure = {
      documentPath: '/test',
      changeId: 'cid-0',
      error: new Error('NoPeersSubscribedToTopic'),
    };
    const store = createDocumentStore(source, { manageLifecycle: false });
    await store.start();
    expect(store.getSnapshot().deliveryFailure).toBe(source.deliveryFailure);
    await store.stop();
  });

  test('the final release keeps a document with an undelivered change open for a remount', async () => {
    const handles: TestDocument[] = [];
    const store = createDocumentStore(() => {
      const handle = new TestDocument();
      handle.reopenable = false;
      handles.push(handle);
      return handle;
    });
    const release = store.connect();
    await settle();
    handles[0].undeliveredError = new Error('NoPeersSubscribedToTopic');
    await store.change((data) => {
      data.title = 'Typed offline';
    });
    release();
    await settle();
    expect(handles[0].closeCount).toBe(0);
    expect(store.getSnapshot().status).toBe('ready');

    const remount = store.connect();
    await settle();
    expect(handles).toHaveLength(1);
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready',
      data: { title: 'Typed offline' },
      deliveryFailure: { changeId: 'cid-1' },
    });

    handles[0].undeliveredError = undefined;
    await store.change((data) => {
      data.title = 'Delivered';
    });
    remount();
    await settle();
    expect(handles[0].closeCount).toBe(1);
    expect(store.getSnapshot().status).toBe('closed');
  });

  test('a delivery failure cleared after the final release closes the document', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    const release = store.connect();
    await settle();
    source.undeliveredError = new Error('NoPeersSubscribedToTopic');
    await store.change((data) => {
      data.title = 'Offline';
    });
    release();
    await settle();
    expect(source.closeCount).toBe(0);

    source.undeliveredError = undefined;
    await source.change((data) => {
      data.title = 'Delivered by an editor';
    });
    await settle();
    expect(source.closeCount).toBe(1);
    await expect(store.change(() => {})).rejects.toThrow(
      'Document store is closed',
    );
  });

  test('closeDelay keeps the document open for a remount within the delay', async () => {
    const handles: TestDocument[] = [];
    const store = createDocumentStore(
      () => {
        const handle = new TestDocument();
        handles.push(handle);
        return handle;
      },
      { closeDelay: 40 },
    );
    const release = store.connect();
    await settle();
    await store.change((data) => {
      data.title = 'Kept';
    });
    release();
    await settle(10);
    expect(handles[0].closeCount).toBe(0);

    const remount = store.connect();
    await settle(60);
    expect(handles).toHaveLength(1);
    expect(handles[0].closeCount).toBe(0);
    expect(store.getSnapshot().data).toEqual({ title: 'Kept' });

    remount();
    await settle(60);
    expect(handles[0].closeCount).toBe(1);
    expect(store.getSnapshot().status).toBe('closed');
  });

  test('rejects an invalid closeDelay', () => {
    for (const closeDelay of [-1, Number.NaN, 2 ** 31])
      expect(() =>
        createDocumentStore(() => new TestDocument(), { closeDelay }),
      ).toThrow(RangeError);
    for (const undeliveredCloseDelay of [-1, Number.NaN, 2 ** 31])
      expect(() =>
        createDocumentStore(() => new TestDocument(), {
          undeliveredCloseDelay,
        }),
      ).toThrow(RangeError);
  });

  test('undeliveredCloseDelay bounds how long an undelivered change keeps the document open', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source, {
      undeliveredCloseDelay: 40,
    });
    const release = store.connect();
    await settle();
    source.undeliveredError = new Error('NoPeersSubscribedToTopic');
    await store.change(() => {});
    release();
    await settle(10);
    expect(source.closeCount).toBe(0);
    await settle(60);
    expect(source.closeCount).toBe(1);
    expect(store.getSnapshot().status).toBe('closed');
  });

  test('an Infinity undeliveredCloseDelay holds the document until the change is delivered', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source, {
      undeliveredCloseDelay: Infinity,
    });
    const release = store.connect();
    await settle();
    source.undeliveredError = new Error('NoPeersSubscribedToTopic');
    await store.change(() => {});
    release();
    await settle(20);
    expect(source.closeCount).toBe(0);
    source.setDeliveryFailure(undefined);
    await settle();
    expect(source.closeCount).toBe(1);
  });

  test('a change after the final release rejects instead of reopening the document', async () => {
    const handles: TestDocument[] = [];
    const store = createDocumentStore(() => {
      const handle = new TestDocument();
      handles.push(handle);
      return handle;
    });
    const release = store.connect();
    await settle();
    release();
    await settle();
    expect(store.getSnapshot().status).toBe('closed');
    await expect(
      store.change((data) => {
        data.title = 'Late';
      }),
    ).rejects.toThrow('Document store is closed');
    expect(handles).toHaveLength(1);
    expect(handles[0]).toMatchObject({ openCount: 1, closeCount: 1 });
    expect(handles[0].document.title).toBe('Initial');
    expect(store.getSnapshot().status).toBe('closed');
  });

  test('a change to a store that was never opened rejects without opening it', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    await expect(store.change(() => {})).rejects.toThrow(
      'Document store is closed',
    );
    expect(source.openCount).toBe(0);
    expect(store.getSnapshot().status).toBe('idle');
  });

  test('an explicitly started store stays open after the final release', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    await store.start();
    store.connect()();
    await settle();
    expect(source.closeCount).toBe(0);
    await store.change((data) => {
      data.title = 'Imperative';
    });
    expect(store.getSnapshot().data).toEqual({ title: 'Imperative' });
    await store.stop();
    expect(source.closeCount).toBe(1);
  });

  test('a retired handle moves the store to retired and stops projecting its data', async () => {
    const retiring = new TestDocument();
    retiring.reopenable = false;
    const fresh = new TestDocument();
    const handles = [retiring, fresh];
    const store = createDocumentStore(() => handles.shift()!);
    const release = store.connect();
    await settle();
    retiring.writeError = new Error('QuotaExceededError');
    retiring.retireOnWriteError = true;
    await expect(
      store.change((data) => {
        data.title = 'Discarded';
      }),
    ).rejects.toBe(retiring.writeError);
    expect(store.getSnapshot()).toMatchObject({
      status: 'retired',
      data: undefined,
      error: retiring.writeError,
    });

    retiring.emit();
    expect(store.getSnapshot().status).toBe('retired');
    await expect(store.change(() => {})).rejects.toThrow('retired');
    expect(store.getSnapshot().status).toBe('retired');

    await store.stop();
    await store.start();
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready',
      data: { title: 'Initial' },
    });
    expect(retiring.closeCount).toBe(1);
    expect(fresh.openCount).toBe(1);
    release();
    await store.stop();
  });

  test('a retired store without consumers closes its handle', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    const release = store.connect();
    await settle();
    source.undeliveredError = new Error('NoPeersSubscribedToTopic');
    await store.change(() => {});
    release();
    await settle();
    expect(source.closeCount).toBe(0);
    source.undeliveredError = undefined;
    source.writeError = new Error('QuotaExceededError');
    source.retireOnWriteError = true;
    await expect(store.change(() => {})).rejects.toBe(source.writeError);
    await settle();
    expect(source.closeCount).toBe(1);
    expect(store.getSnapshot().status).toBe('closed');
  });

  test('an unmanaged store over a retired handle starts as retired', async () => {
    const source = new TestDocument();
    source.retired = true;
    const store = createDocumentStore(source, { manageLifecycle: false });
    await store.start();
    expect(store.getSnapshot()).toMatchObject({
      status: 'retired',
      data: undefined,
    });
    await store.stop();
    expect(source.closeCount).toBe(0);
  });

  test('a handle factory can restore state before the store opens the handle', async () => {
    const restored = deferred();
    const source = new TestDocument();
    const store = createDocumentStore(async () => {
      await restored.promise;
      source.document = { title: 'Restored' };
      return source;
    });
    const starting = store.start();
    await Promise.resolve();
    expect(store.getSnapshot().status).toBe('opening');
    expect(source.openCount).toBe(0);
    restored.resolve();
    await starting;
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready',
      data: { title: 'Restored' },
    });
    expect(source.openCount).toBe(1);
    await store.stop();
  });

  test('does not replace newer membership notifications with stale initialization reads', async () => {
    const source = new TestDocument();
    const gate = deferred();
    source.readGate = gate.promise;
    const store = createDocumentStore(() => source);
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

  test('reopens a fresh handle after the final release closed the previous one', async () => {
    const handles: TestDocument[] = [];
    const store = createDocumentStore(() => {
      const handle = new TestDocument();
      handle.reopenable = false;
      handle.document = { title: `Handle ${handles.length + 1}` };
      handles.push(handle);
      return handle;
    });
    store.connect()();
    await Promise.resolve();
    await store.stop();
    expect(store.getSnapshot().status).toBe('closed');

    const release = store.connect();
    await store.start();
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready',
      data: { title: 'Handle 2' },
    });
    await store.change((data) => {
      data.title = 'Edited';
    });
    expect(
      handles.map(({ openCount, closeCount }) => [openCount, closeCount]),
    ).toEqual([
      [1, 1],
      [1, 0],
    ]);
    expect(handles[1].document.title).toBe('Edited');
    expect(handles[0].handlers.size).toBe(0);
    release();
    await Promise.resolve();
    await store.stop();
    expect(handles[1].closeCount).toBe(1);
  });

  test('retries a failed open with a fresh handle', async () => {
    const failed = new TestDocument();
    failed.openError = new Error('Denied');
    const fresh = new TestDocument();
    const handles = [failed, fresh];
    const store = createDocumentStore(() => handles.shift()!);
    await expect(store.start()).rejects.toThrow('Denied');
    expect(failed.closeCount).toBe(1);
    await store.start();
    expect(store.getSnapshot().status).toBe('ready');
    expect(fresh.openCount).toBe(1);
    await store.stop();
  });

  test('requires a handle factory exactly when it manages the lifecycle', () => {
    const source = new TestDocument();
    expect(() => createDocumentStore(source as never)).toThrow(TypeError);
    expect(() =>
      createDocumentStore((() => source) as never, { manageLifecycle: false }),
    ).toThrow(TypeError);
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
    const store = createDocumentStore(() => source);
    await expect(store.start()).rejects.toThrow('Subscribe failed');
    expect(store.getSnapshot().status).toBe('error');
    expect(source.closeCount).toBe(1);
  });

  test('an unsubscribe failure does not skip closing the document', async () => {
    const source = new TestDocument();
    const store = createDocumentStore(() => source);
    await store.start();
    source.unsubscribe = () => {
      throw new Error('Unsubscribe failed');
    };
    await expect(store.stop()).rejects.toThrow('Unsubscribe failed');
    expect(source.closeCount).toBe(1);
    expect(store.getSnapshot().status).toBe('error');
    expect(store.getSnapshot().data).toBeUndefined();
  });

  test.each(['start', 'stop'] as const)(
    'reports %s cleanup failures in operation order',
    async (operation) => {
      const source = new TestDocument();
      const store = createDocumentStore(() => source);
      const openError = new Error('Open failed');
      const unsubscribeError = new Error('Unsubscribe failed');
      const closeError = new Error('Close failed');
      if (operation === 'stop') await store.start();
      else source.openError = openError;

      const calls: string[] = [];
      source.unsubscribe = () => {
        calls.push('unsubscribe');
        throw unsubscribeError;
      };
      source.close = async () => {
        calls.push('close');
        throw closeError;
      };

      await expect(store[operation]()).rejects.toBeInstanceOf(AggregateError);
      expect(calls).toEqual(['unsubscribe', 'close']);
      expect(store.getSnapshot()).toMatchObject({
        status: 'error',
        error: {
          message:
            operation === 'start'
              ? 'Document open and cleanup failed'
              : 'Document cleanup failed',
          errors:
            operation === 'start'
              ? [openError, unsubscribeError, closeError]
              : [unsubscribeError, closeError],
        },
      });
    },
  );
});
