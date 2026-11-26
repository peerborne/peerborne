import { describe, expect, jest, test } from '@jest/globals';
import {
  MAX_REMOTE_BLOCK_RETRY_DELAY_MS,
  REMOTE_BLOCK_RETRY_DELAY_MS,
  RemoteBlockFetchDeadlineError,
  RemoteBlockFetches,
} from './remote-block-fetch.js';

const block = new Uint8Array([1]);

// Bitswap's wantBlock settles only when the block arrives or the read aborts.
function wantBlock(signal: AbortSignal): Promise<Uint8Array> {
  return new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason), {
      once: true,
    });
  });
}

function clock() {
  let now = 0;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

describe('remote block fetches for one message', () => {
  test('abort a read that never settles at the deadline and start no more', async () => {
    const fetches = new RemoteBlockFetches(20);
    const scope = fetches.begin();

    await expect(scope.fetch('missing', wantBlock)).rejects.toBeInstanceOf(
      RemoteBlockFetchDeadlineError,
    );
    const read = jest.fn(async () => block);
    await expect(scope.fetch('other', read)).resolves.toBeUndefined();
    expect(read).not.toHaveBeenCalled();
    expect(scope.signal.aborted).toBe(true);
    expect(fetches.isBackedOff('missing')).toBe(true);
    expect(fetches.isBackedOff('other')).toBe(false);
    scope.end();
  });

  test('start at most the configured number of reads', async () => {
    const scope = new RemoteBlockFetches(10_000, 2).begin();
    const read = jest.fn(async () => block);

    await expect(scope.fetch('a', read)).resolves.toBe(block);
    await expect(scope.fetch('b', read)).resolves.toBe(block);
    await expect(scope.fetch('c', read)).resolves.toBeUndefined();
    expect(read).toHaveBeenCalledTimes(2);
    scope.end();
  });

  test('end() aborts reads still in flight', async () => {
    const scope = new RemoteBlockFetches().begin();
    const pending = scope.fetch('missing', wantBlock);

    scope.end();
    await expect(pending).rejects.toBeInstanceOf(RemoteBlockFetchDeadlineError);
    expect(scope.signal.aborted).toBe(true);
  });

  test('pass a read the caller signal and the scope signal together', async () => {
    const scope = new RemoteBlockFetches().begin();
    const caller = new AbortController();
    const pending = scope.fetch('missing', wantBlock, caller.signal);

    caller.abort(new Error('load cancelled'));
    await expect(pending).rejects.toThrow('load cancelled');
    expect(scope.signal.aborted).toBe(false);
    scope.end();
  });
});

describe('remote block fetch failures', () => {
  test('delay the next fetch of a failed block, doubling up to the maximum', async () => {
    const time = clock();
    const fetches = new RemoteBlockFetches(10_000, 8, time.now);
    const fail = jest.fn(async (): Promise<Uint8Array> => {
      throw new Error('not found');
    });
    const failOnce = async () => {
      const scope = fetches.begin();
      await expect(scope.fetch('cid', fail)).rejects.toThrow('not found');
      scope.end();
    };

    await failOnce();
    const scope = fetches.begin();
    await expect(scope.fetch('cid', fail)).resolves.toBeUndefined();
    scope.end();
    expect(fail).toHaveBeenCalledTimes(1);

    let delay = REMOTE_BLOCK_RETRY_DELAY_MS;
    for (let failures = 1; failures < 12; failures++) {
      time.advance(delay - 1);
      expect(fetches.isBackedOff('cid')).toBe(true);
      time.advance(1);
      expect(fetches.isBackedOff('cid')).toBe(false);
      await failOnce();
      delay = Math.min(delay * 2, MAX_REMOTE_BLOCK_RETRY_DELAY_MS);
    }
    expect(delay).toBe(MAX_REMOTE_BLOCK_RETRY_DELAY_MS);
    time.advance(MAX_REMOTE_BLOCK_RETRY_DELAY_MS);

    const retry = fetches.begin();
    await expect(retry.fetch('cid', async () => block)).resolves.toBe(block);
    retry.end();
    await failOnce();
    time.advance(REMOTE_BLOCK_RETRY_DELAY_MS);
    expect(fetches.isBackedOff('cid')).toBe(false);
  });

  test('do not count a close or a caller cancellation as a failure of the block', async () => {
    const fetches = new RemoteBlockFetches();
    const scope = fetches.begin();
    const closed = scope.fetch('closed', wantBlock);
    const caller = new AbortController();
    const cancelled = scope.fetch('cancelled', wantBlock, caller.signal);

    caller.abort(new Error('cancelled'));
    fetches.abortAll();
    await expect(cancelled).rejects.toThrow('cancelled');
    await expect(closed).rejects.toThrow('Document closed');
    expect(fetches.isBackedOff('closed')).toBe(false);
    expect(fetches.isBackedOff('cancelled')).toBe(false);
    scope.end();

    const reopened = fetches.begin();
    await expect(reopened.fetch('closed', async () => block)).resolves.toBe(
      block,
    );
    reopened.end();
  });

  test('remember a bounded number of failed blocks, forgetting the oldest', async () => {
    const fetches = new RemoteBlockFetches(10_000, 2048, () => 0);
    const scope = fetches.begin();
    const fail = async (): Promise<Uint8Array> => {
      throw new Error('not found');
    };
    for (let index = 0; index <= 1024; index++) {
      await expect(scope.fetch(`cid-${index}`, fail)).rejects.toThrow();
    }
    scope.end();

    expect(fetches.isBackedOff('cid-0')).toBe(false);
    expect(fetches.isBackedOff('cid-1')).toBe(true);
    expect(fetches.isBackedOff('cid-1024')).toBe(true);
  });
});

describe('prefetching the blocks of received messages', () => {
  test('returns the blocks it read and leaves out the ones it could not', async () => {
    const fetches = new RemoteBlockFetches(50);
    const scope = fetches.begin();
    const read = jest.fn((cid: string, signal: AbortSignal) =>
      cid === 'missing' ? wantBlock(signal) : Promise.resolve(block),
    );

    const blocks = await fetches.prefetch(
      scope,
      ['present', 'missing', 'other'],
      read,
      8,
    );
    expect([...blocks.keys()].sort()).toEqual(['other', 'present']);
    expect(fetches.isBackedOff('missing')).toBe(true);
    scope.end();
  });

  test('runs one message at a time, and a waiting message stops when its scope aborts', async () => {
    const fetches = new RemoteBlockFetches();
    const first = fetches.begin();
    let releaseFirst!: () => void;
    const firstRead = new Promise<Uint8Array>((resolve) => {
      releaseFirst = () => resolve(block);
    });
    const firstBlocks = fetches.prefetch(first, ['a'], () => firstRead, 8);

    const second = fetches.begin();
    const secondRead = jest.fn(async () => block);
    const waiting = fetches.prefetch(second, ['b'], secondRead, 8);
    second.end();
    await expect(waiting).resolves.toEqual(new Map());
    expect(secondRead).not.toHaveBeenCalled();

    const third = fetches.begin();
    const thirdRead = jest.fn(async () => block);
    const queued = fetches.prefetch(third, ['c'], thirdRead, 8);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(thirdRead).not.toHaveBeenCalled();

    releaseFirst();
    await expect(firstBlocks).resolves.toEqual(new Map([['a', block]]));
    await expect(queued).resolves.toEqual(new Map([['c', block]]));
    for (const scope of [first, second, third]) scope.end();
  });
});
