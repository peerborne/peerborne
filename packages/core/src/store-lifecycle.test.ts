import { describe, expect, jest, test } from '@jest/globals';
import {
  closeHeliaStores,
  openHeliaStores,
} from './store-lifecycle.js';

describe('Helia store lifecycle', () => {
  test('opens each distinct configured store and closes in reverse order', async () => {
    const calls: string[] = [];
    const datastore = {
      open: jest.fn(async () => calls.push('open datastore')),
      close: jest.fn(async () => calls.push('close datastore')),
    };
    const blockstore = {
      open: jest.fn(async () => calls.push('open blockstore')),
      close: jest.fn(async () => calls.push('close blockstore')),
    };

    const opened = await openHeliaStores(
      datastore,
      blockstore,
      datastore,
      {},
    );
    await closeHeliaStores(opened);

    expect(calls).toEqual([
      'open datastore',
      'open blockstore',
      'close blockstore',
      'close datastore',
    ]);
  });

  test('waits for each close before starting the next', async () => {
    let releaseFirstClose!: () => void;
    const firstCloseFinished = new Promise<void>((resolve) => {
      releaseFirstClose = resolve;
    });
    const first = {
      open: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
    };
    const second = {
      open: jest.fn(async () => undefined),
      close: jest.fn(async () => firstCloseFinished),
    };

    const closing = closeHeliaStores([first, second]);
    await Promise.resolve();

    expect(second.close).toHaveBeenCalledTimes(1);
    expect(first.close).not.toHaveBeenCalled();

    releaseFirstClose();
    await closing;
    expect(first.close).toHaveBeenCalledTimes(1);
  });

  test('continues closing stores after a close fails', async () => {
    const first = {
      open: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
    };
    const second = {
      open: jest.fn(async () => undefined),
      close: jest.fn(async () => {
        throw new Error('synthetic close failure');
      }),
    };

    await expect(
      closeHeliaStores([first, second]),
    ).resolves.toBeUndefined();
    expect(first.close).toHaveBeenCalledTimes(1);
  });

  test('closes already-opened stores when a later open fails', async () => {
    const first = {
      open: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
    };
    const failure = new Error('synthetic open failure');
    const second = {
      open: jest.fn(async () => {
        throw failure;
      }),
    };

    await expect(openHeliaStores(first, second)).rejects.toBe(failure);
    expect(first.close).toHaveBeenCalledTimes(1);
  });
});
