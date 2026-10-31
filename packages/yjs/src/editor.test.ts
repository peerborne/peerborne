import { describe, expect, jest, test } from '@jest/globals';
import { Doc, applyUpdateV2, encodeStateAsUpdateV2 } from 'yjs';
import { createYjsEditorBridge, type YjsEditorSource } from './editor.js';
import { YjsProvider } from './peerborne-yjs.js';

function fixture() {
  const provider = new YjsProvider();
  const document = new Doc();
  const handlers = new Map<
    string,
    (doc: Doc, readers: string[], writers: string[], hashes: string[]) => void
  >();
  const changes: Uint8Array[] = [];
  const source: YjsEditorSource<string> = {
    document,
    change: jest.fn(async (change: (doc: Doc) => void) => {
      const [, update] = provider.localChange(document, 'Editor', change);
      changes.push(update);
      for (const handler of handlers.values()) handler(document, [], [], []);
    }),
    subscribe(id, handler) {
      handlers.set(id, handler);
    },
    unsubscribe(id) {
      handlers.delete(id);
    },
  };
  return { source, document, handlers, changes };
}

describe('Yjs editor bridge', () => {
  test('captures editor deltas through the authoritative mutation boundary', async () => {
    const { source, document, changes } = fixture();
    document.getText('body').insert(0, 'Initial');
    const bridge = createYjsEditorBridge(source);
    expect(bridge.document).not.toBe(document);
    bridge.document.getText('body').insert(7, ' edited');
    expect(document.getText('body').toString()).toBe('Initial');
    await bridge.flush();
    expect(document.getText('body').toString()).toBe('Initial edited');
    expect(source.change).toHaveBeenCalledTimes(1);
    const peer = new Doc();
    applyUpdateV2(peer, encodeStateAsUpdateV2(document));
    bridge.document.getText('body').insert(14, ' again');
    await bridge.flush();
    applyUpdateV2(peer, changes[1]);
    expect(peer.getText('body').toString()).toBe('Initial edited again');
    await bridge.destroy();
  });

  test('remote updates reach the editor without generating another write', async () => {
    const { source, handlers, document } = fixture();
    const bridge = createYjsEditorBridge(source);
    document.getText('body').insert(0, 'Remote');
    for (const handler of handlers.values()) handler(document, [], [], []);
    await bridge.flush();
    expect(bridge.document.getText('body').toString()).toBe('Remote');
    expect(source.change).not.toHaveBeenCalled();
    await bridge.destroy();
    expect(handlers.size).toBe(0);
    expect(bridge.document.isDestroyed).toBe(true);
  });

  test('authorization failures do not mutate the source and halt later writes', async () => {
    const { source, document } = fixture();
    const error = new Error('Read only');
    source.change = jest.fn(async () => {
      throw error;
    });
    const onError = jest.fn();
    const bridge = createYjsEditorBridge(source, { onError });
    bridge.document.getText('body').insert(0, 'Denied');
    bridge.document.getText('body').insert(6, ' later');
    await expect(bridge.flush()).rejects.toBe(error);
    expect(document.getText('body').toString()).toBe('');
    expect(source.change).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledTimes(1);
    await expect(bridge.destroy()).rejects.toBe(error);
    expect(bridge.document.isDestroyed).toBe(true);
  });

  test('destroy drains pending writes and detaches subscriptions immediately', async () => {
    const { source, document, handlers } = fixture();
    let resolve!: () => void;
    const gate = new Promise<void>((done) => {
      resolve = done;
    });
    const original = source.change;
    source.change = async (change) => {
      await gate;
      await original(change);
    };
    const bridge = createYjsEditorBridge(source);
    bridge.document.getText('body').insert(0, 'Saved');
    const destroying = bridge.destroy();
    expect(handlers.size).toBe(0);
    expect(bridge.document.isDestroyed).toBe(false);
    resolve();
    await destroying;
    expect(document.getText('body').toString()).toBe('Saved');
    expect(bridge.document.isDestroyed).toBe(true);
    await bridge.destroy();
  });
});
