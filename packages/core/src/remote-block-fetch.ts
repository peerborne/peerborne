/** Time the block fetches for one received message may take, from the first. */
export const REMOTE_BLOCK_FETCH_DEADLINE_MS = 10_000;
/** Blocks one received message may fetch. */
export const MAX_REMOTE_BLOCK_FETCHES = 8;
/** Prefetched block bytes one document holds for messages waiting to apply. */
export const MAX_PREFETCHED_BLOCK_BYTES = 64 * 1024 * 1024;
/** Delay before a block that could not be fetched is fetched again. */
export const REMOTE_BLOCK_RETRY_DELAY_MS = 15_000;
/** Longest delay, reached by doubling after each further failure. */
export const MAX_REMOTE_BLOCK_RETRY_DELAY_MS = 5 * 60_000;
/**
 * Time a load or an invitation waits for a block it needs while none of the
 * block's bytes arrive.
 */
export const LOAD_BLOCK_FETCH_DEADLINE_MS = 10_000;
const MAX_FAILED_BLOCKS = 1024;

export class RemoteBlockFetchDeadlineError extends Error {
  constructor() {
    super('Remote block fetch deadline exceeded');
    this.name = 'RemoteBlockFetchDeadlineError';
  }
}

/**
 * Run `read` with a signal that also aborts once `ms` pass without the read
 * reporting progress, so a slow transfer continues while a stalled one ends.
 */
export async function readWithin<T>(
  read: (signal: AbortSignal, progress: () => void) => Promise<T>,
  signal?: AbortSignal,
  ms: number = LOAD_BLOCK_FETCH_DEADLINE_MS,
): Promise<T> {
  const deadline = new AbortController();
  const expire = () => deadline.abort(new RemoteBlockFetchDeadlineError());
  let timer = setTimeout(expire, ms);
  const progress = (): void => {
    if (deadline.signal.aborted) return;
    clearTimeout(timer);
    timer = setTimeout(expire, ms);
  };
  try {
    return await read(
      signal === undefined
        ? deadline.signal
        : AbortSignal.any([signal, deadline.signal]),
      progress,
    );
  } finally {
    clearTimeout(timer);
  }
}

export class PrefetchedBlockBudgetError extends RangeError {
  constructor() {
    super('Prefetched block bytes exceed the document budget');
    this.name = 'PrefetchedBlockBudgetError';
  }
}

/** The block fetches started for one received message. */
export interface RemoteBlockFetchScope {
  /** Aborted at the message's deadline, at `end()` or when the document closes. */
  readonly signal: AbortSignal;
  /**
   * Run `read` for the block `cid` names, with a signal that also aborts at
   * the deadline or close. The first fetch starts the deadline. Resolves
   * undefined without reading once the message has used its fetches or its
   * deadline, after `prefetch()`, or while `cid` waits out a retry delay.
   *
   * A rejection delays the next fetch of `cid`, unless it came from a close,
   * `signal` (the caller's own cancellation), `end()`, the prefetch budget, or
   * a deadline that the read started with less than half of left.
   */
  fetch<T>(
    cid: string,
    read: (signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T | undefined>;
  /**
   * Fetch the blocks `cids` name, `concurrency` at a time, once the
   * prefetches of the document's earlier messages finish, waiting at most one
   * deadline for them. Their bytes count against the document's prefetch
   * budget until `end()`. Blocks that cannot be fetched are left out, and the
   * scope starts no fetch afterwards.
   */
  prefetch(
    cids: readonly string[],
    read: (
      cid: string,
      signal: AbortSignal,
      consumeBytes: (byteLength: number) => void,
    ) => Promise<Uint8Array>,
    concurrency: number,
  ): Promise<Map<string, Uint8Array>>;
  /** Abort what is in flight, stop the deadline and release prefetched bytes. */
  end(): void;
}

export interface RemoteBlockFetchOptions {
  readonly deadlineMs?: number;
  readonly maxFetches?: number;
  readonly maxPrefetchedBytes?: number;
  readonly now?: () => number;
}

function abortedOrSettled(
  previous: Promise<void>,
  signal: AbortSignal,
  waitMs: number,
): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const done = (settled: boolean): void => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      resolve(settled);
    };
    const onAbort = (): void => done(false);
    const timer = setTimeout(() => done(false), waitMs);
    signal.addEventListener('abort', onAbort, { once: true });
    void previous.then(() => done(true));
  });
}

function whenAborted(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) resolve();
    else signal.addEventListener('abort', () => resolve(), { once: true });
  });
}

/**
 * Bounds the blocks a document fetches from peers for the ordinary sync
 * messages it receives. Bitswap waits for a wanted block until the read is
 * aborted, so a block that no reachable peer holds, or a CID nobody holds at
 * all, would otherwise stall the message that cited it. A block that cannot
 * be fetched is a missing dependency: the message applies without it, and a
 * later message citing the CID fetches it only after a retry delay that
 * doubles with each failure.
 */
export class RemoteBlockFetches {
  readonly deadlineMs: number;
  readonly maxFetches: number;
  readonly maxPrefetchedBytes: number;
  private readonly now: () => number;
  private closing = new AbortController();
  private prefetching: Promise<void> = Promise.resolve();
  private prefetchedBytes = 0;
  private readonly failures = new Map<
    string,
    { readonly count: number; readonly retryAt: number }
  >();

  constructor(options: RemoteBlockFetchOptions = {}) {
    this.deadlineMs = options.deadlineMs ?? REMOTE_BLOCK_FETCH_DEADLINE_MS;
    this.maxFetches = options.maxFetches ?? MAX_REMOTE_BLOCK_FETCHES;
    this.maxPrefetchedBytes =
      options.maxPrefetchedBytes ?? MAX_PREFETCHED_BLOCK_BYTES;
    this.now = options.now ?? Date.now;
  }

  /** Prefetched block bytes held for messages that have not ended. */
  get heldBytes(): number {
    return this.prefetchedBytes;
  }

  /** Abort every fetch in progress. Fetches started later are unaffected. */
  abortAll(reason: unknown = new Error('Document closed')): void {
    const closing = this.closing;
    this.closing = new AbortController();
    closing.abort(reason);
  }

  /** Whether `cid` failed recently and waits out its retry delay. */
  isBackedOff(cid: string): boolean {
    const failure = this.failures.get(cid);
    return failure !== undefined && failure.retryAt > this.now();
  }

  /** Start the fetches of one message. */
  begin(): RemoteBlockFetchScope {
    const closing = this.closing.signal;
    const deadline = new AbortController();
    const scopeSignal = AbortSignal.any([closing, deadline.signal]);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let deadlineAt = Infinity;
    let expired = false;
    let started = 0;
    let sealed = false;
    let heldBytes = 0;

    const fetch = async <T>(
      cid: string,
      read: (signal: AbortSignal) => Promise<T>,
      signal?: AbortSignal,
    ): Promise<T | undefined> => {
      if (
        sealed ||
        scopeSignal.aborted ||
        started >= this.maxFetches ||
        this.isBackedOff(cid)
      )
        return undefined;
      if (timer === undefined) {
        deadlineAt = this.now() + this.deadlineMs;
        timer = setTimeout(() => {
          expired = true;
          deadline.abort(new RemoteBlockFetchDeadlineError());
        }, this.deadlineMs);
      }
      started++;
      const fullWindow = deadlineAt - this.now() >= this.deadlineMs / 2;
      try {
        const result = await read(
          signal === undefined
            ? scopeSignal
            : AbortSignal.any([signal, scopeSignal]),
        );
        this.failures.delete(cid);
        return result;
      } catch (error) {
        const blockFailed =
          !closing.aborted &&
          !signal?.aborted &&
          !(error instanceof PrefetchedBlockBudgetError) &&
          (!scopeSignal.aborted || (expired && fullWindow));
        if (blockFailed) this.recordFailure(cid);
        throw error;
      }
    };

    const prefetch: RemoteBlockFetchScope['prefetch'] = async (
      cids,
      read,
      concurrency,
    ) => {
      const blocks = new Map<string, Uint8Array>();
      const previous = this.prefetching;
      let release!: () => void;
      this.prefetching = new Promise<void>((resolve) => {
        release = resolve;
      });
      try {
        if (!(await abortedOrSettled(previous, scopeSignal, this.deadlineMs)))
          return blocks;
        let next = 0;
        const worker = async (): Promise<void> => {
          while (next < cids.length && !sealed) {
            const cid = cids[next++]!;
            let reserved = 0;
            const consumeBytes = (byteLength: number): void => {
              if (this.prefetchedBytes + byteLength > this.maxPrefetchedBytes)
                throw new PrefetchedBlockBudgetError();
              this.prefetchedBytes += byteLength;
              reserved += byteLength;
            };
            try {
              const block = await fetch(cid, (signal) =>
                read(cid, signal, consumeBytes),
              );
              if (block !== undefined && !sealed) {
                blocks.set(cid, block);
                heldBytes += reserved;
                reserved = 0;
              }
            } catch {
              // The block stays a missing dependency of the message.
            } finally {
              this.prefetchedBytes -= reserved;
            }
          }
        };
        // A read that ignores the deadline cannot hold up later messages.
        await Promise.race([
          Promise.all(
            Array.from({ length: Math.min(concurrency, cids.length) }, worker),
          ),
          whenAborted(scopeSignal),
        ]);
        return blocks;
      } finally {
        sealed = true;
        // A message that stopped waiting releases its turn only after the
        // earlier prefetch ends.
        void previous.then(release);
      }
    };

    return {
      signal: scopeSignal,
      fetch,
      prefetch,
      end: () => {
        clearTimeout(timer);
        sealed = true;
        deadline.abort(new RemoteBlockFetchDeadlineError());
        this.prefetchedBytes -= heldBytes;
        heldBytes = 0;
      },
    };
  }

  private recordFailure(cid: string): void {
    const count = (this.failures.get(cid)?.count ?? 0) + 1;
    const delay = Math.min(
      MAX_REMOTE_BLOCK_RETRY_DELAY_MS,
      REMOTE_BLOCK_RETRY_DELAY_MS * 2 ** Math.min(count - 1, 16),
    );
    this.failures.delete(cid);
    this.failures.set(cid, { count, retryAt: this.now() + delay });
    if (this.failures.size > MAX_FAILED_BLOCKS)
      this.failures.delete(this.failures.keys().next().value!);
  }
}
