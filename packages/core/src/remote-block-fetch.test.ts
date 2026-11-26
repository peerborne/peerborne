import { describe, expect, jest, test } from '@jest/globals';
import {
  MAX_REMOTE_BLOCK_RETRY_DELAY_MS,
  PrefetchedBlockBudgetError,
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

const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

describe('remote block fetches for one message', () => {
  test('abort a read that never settles at the deadline and start no more', async () => {
    const fetches = new RemoteBlockFetches({ deadlineMs: 20 });
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

  test('start the deadline at the first fetch, not when the scope begins', async () => {
    const scope = new RemoteBlockFetches({ deadlineMs: 30 }).begin();
    await delay(60);

    expect(scope.signal.aborted).toBe(false);
    await expect(scope.fetch('a', async () => block)).resolves.toBe(block);
    scope.end();
  });

  test('start at most the configured number of reads', async () => {
    const scope = new RemoteBlockFetches({ maxFetches: 2 }).begin();
    const read = jest.fn(async () => block);

    await expect(scope.fetch('a', read)).resolves.toBe(block);
    await expect(scope.fetch('b', read)).resolves.toBe(block);
    await expect(scope.fetch('c', read)).resolves.toBeUndefined();
    expect(read).toHaveBeenCalledTimes(2);
    scope.end();
  });

  test('end() aborts reads in flight without counting them as failures', async () => {
    const fetches = new RemoteBlockFetches();
    const scope = fetches.begin();
    const pending = scope.fetch('missing', wantBlock);

    scope.end();
    await expect(pending).rejects.toBeInstanceOf(RemoteBlockFetchDeadlineError);
    expect(scope.signal.aborted).toBe(true);
    expect(fetches.isBackedOff('missing')).toBe(false);
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
    const fetches = new RemoteBlockFetches({ now: time.now });
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

    let retryDelay = REMOTE_BLOCK_RETRY_DELAY_MS;
    for (let failures = 1; failures < 12; failures++) {
      time.advance(retryDelay - 1);
      expect(fetches.isBackedOff('cid')).toBe(true);
      time.advance(1);
      expect(fetches.isBackedOff('cid')).toBe(false);
      await failOnce();
      retryDelay = Math.min(retryDelay * 2, MAX_REMOTE_BLOCK_RETRY_DELAY_MS);
    }
    expect(retryDelay).toBe(MAX_REMOTE_BLOCK_RETRY_DELAY_MS);
    time.advance(MAX_REMOTE_BLOCK_RETRY_DELAY_MS);

    const retry = fetches.begin();
    await expect(retry.fetch('cid', async () => block)).resolves.toBe(block);
    retry.end();
    await failOnce();
    time.advance(REMOTE_BLOCK_RETRY_DELAY_MS);
    expect(fetches.isBackedOff('cid')).toBe(false);
  });

  test('do not count a read that started with under half the deadline left', async () => {
    const time = clock();
    const fetches = new RemoteBlockFetches({ deadlineMs: 40, now: time.now });
    const scope = fetches.begin();
    const first = scope.fetch('first', wantBlock);
    time.advance(30);
    const late = scope.fetch('late', wantBlock);

    await expect(first).rejects.toBeInstanceOf(RemoteBlockFetchDeadlineError);
    await expect(late).rejects.toBeInstanceOf(RemoteBlockFetchDeadlineError);
    expect(fetches.isBackedOff('first')).toBe(true);
    expect(fetches.isBackedOff('late')).toBe(false);
    scope.end();
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
    const fetches = new RemoteBlockFetches({ maxFetches: 2048, now: () => 0 });
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
  test('returns the blocks it read, leaves out the rest and then starts no fetch', async () => {
    const fetches = new RemoteBlockFetches({ deadlineMs: 50 });
    const scope = fetches.begin();
    const read = jest.fn((cid: string, signal: AbortSignal) =>
      cid === 'missing' ? wantBlock(signal) : Promise.resolve(block),
    );

    const blocks = await scope.prefetch(
      ['present', 'missing', 'other'],
      read,
      8,
    );
    expect([...blocks.keys()].sort()).toEqual(['other', 'present']);
    expect(fetches.isBackedOff('missing')).toBe(true);
    await expect(scope.fetch('later', async () => block)).resolves.toBe(
      undefined,
    );
    scope.end();
  });

  test('runs one message at a time without using a waiting message deadline', async () => {
    const fetches = new RemoteBlockFetches({ deadlineMs: 200 });
    const first = fetches.begin();
    const firstBlocks = first.prefetch(
      ['a'],
      () => delay(120).then(() => block),
      8,
    );
    const second = fetches.begin();
    const secondRead = jest.fn(() => delay(120).then(() => block));
    const secondBlocks = second.prefetch(['b'], secondRead, 8);
    await delay(10);
    expect(secondRead).not.toHaveBeenCalled();

    // The second read ends more than one deadline after its scope began.
    await expect(firstBlocks).resolves.toEqual(new Map([['a', block]]));
    await expect(secondBlocks).resolves.toEqual(new Map([['b', block]]));
    for (const scope of [first, second]) scope.end();
  });

  test('a message waiting behind more than one deadline gives up', async () => {
    const fetches = new RemoteBlockFetches({ deadlineMs: 30 });
    const scopes = [fetches.begin(), fetches.begin(), fetches.begin()];
    const reads = scopes.map(() =>
      jest.fn((_cid: string, signal: AbortSignal) => wantBlock(signal)),
    );
    const nextTurn = () => new Promise((resolve) => setImmediate(resolve));
    const first = scopes[0]!.prefetch(['cid-0'], reads[0]!, 8);
    await nextTurn();
    expect(reads[0]).toHaveBeenCalledTimes(1);
    const queued = [1, 2].map((index) =>
      scopes[index]!.prefetch([`cid-${index}`], reads[index]!, 8),
    );

    await expect(Promise.all([first, ...queued])).resolves.toEqual([
      new Map(),
      new Map(),
      new Map(),
    ]);
    expect(reads[1]).toHaveBeenCalledTimes(1);
    expect(reads[2]).not.toHaveBeenCalled();
    expect(fetches.isBackedOff('cid-0')).toBe(true);
    expect(fetches.isBackedOff('cid-1')).toBe(true);
    expect(fetches.isBackedOff('cid-2')).toBe(false);
    for (const scope of scopes) scope.end();
  });

  test('holds prefetched bytes against the document budget until the message ends', async () => {
    const fetches = new RemoteBlockFetches({ maxPrefetchedBytes: 4 });
    const read = async (
      _cid: string,
      _signal: AbortSignal,
      consumeBytes: (byteLength: number) => void,
    ) => {
      consumeBytes(3);
      return new Uint8Array(3);
    };
    const first = fetches.begin();
    await expect(first.prefetch(['a'], read, 8)).resolves.toHaveProperty(
      'size',
      1,
    );
    expect(fetches.heldBytes).toBe(3);

    const second = fetches.begin();
    await expect(second.prefetch(['b'], read, 8)).resolves.toEqual(new Map());
    expect(fetches.heldBytes).toBe(3);
    expect(fetches.isBackedOff('b')).toBe(false);

    first.end();
    expect(fetches.heldBytes).toBe(0);
    const third = fetches.begin();
    await expect(third.prefetch(['b'], read, 8)).resolves.toHaveProperty(
      'size',
      1,
    );
    third.end();
    second.end();
    expect(fetches.heldBytes).toBe(0);
    expect(new PrefetchedBlockBudgetError()).toBeInstanceOf(RangeError);
  });
});
