/** Overall time the block fetches for one received message may take. */
export const REMOTE_BLOCK_FETCH_DEADLINE_MS = 10_000;
/** Blocks one received message may fetch. */
export const MAX_REMOTE_BLOCK_FETCHES = 8;
/** Delay before a block that could not be fetched is fetched again. */
export const REMOTE_BLOCK_RETRY_DELAY_MS = 15_000;
/** Longest delay, reached by doubling after each further failure. */
export const MAX_REMOTE_BLOCK_RETRY_DELAY_MS = 5 * 60_000;
const MAX_FAILED_BLOCKS = 1024;

export class RemoteBlockFetchDeadlineError extends Error {
  constructor() {
    super('Remote block fetch deadline exceeded');
    this.name = 'RemoteBlockFetchDeadlineError';
  }
}

/** The block fetches started for one received message. */
export interface RemoteBlockFetchScope {
  /** Aborted at the message's deadline, at `end()` or when the document closes. */
  readonly signal: AbortSignal;
  /**
   * Run `read` for the block `cid` names, with a signal that also aborts
   * at the deadline or close. Resolves undefined without reading once the
   * message has used its fetches or its deadline, or while `cid` waits out a
   * retry delay. A rejection delays the next fetch of `cid`, unless the
   * document closed or `signal`, the caller's own cancellation, aborted.
   */
  fetch<T>(
    cid: string,
    read: (signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T | undefined>;
  /** Abort what is still in flight and stop the deadline timer. */
  end(): void;
}

/**
 * Bounds the blocks a document fetches from peers for the messages it
 * receives. Bitswap waits for a wanted block until the read is aborted, so a
 * block that no reachable peer holds, or a CID nobody holds at all, would
 * otherwise stall the message that cited it. A block that cannot be fetched
 * is a missing dependency: the message applies without it, and the CID is
 * fetched again after a retry delay that doubles with each failure.
 */
export class RemoteBlockFetches {
  private closing = new AbortController();
  private prefetching: Promise<void> = Promise.resolve();
  private readonly failures = new Map<
    string,
    { readonly count: number; readonly retryAt: number }
  >();

  constructor(
    readonly deadlineMs = REMOTE_BLOCK_FETCH_DEADLINE_MS,
    readonly maxFetches = MAX_REMOTE_BLOCK_FETCHES,
    private readonly now: () => number = Date.now,
  ) {}

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

  /** Start the fetches of one message under one deadline. */
  begin(): RemoteBlockFetchScope {
    const closing = this.closing.signal;
    const deadline = new AbortController();
    const timer = setTimeout(
      () => deadline.abort(new RemoteBlockFetchDeadlineError()),
      this.deadlineMs,
    );
    const scopeSignal = AbortSignal.any([closing, deadline.signal]);
    let started = 0;
    return {
      signal: scopeSignal,
      fetch: async (cid, read, signal) => {
        if (
          scopeSignal.aborted ||
          started >= this.maxFetches ||
          this.isBackedOff(cid)
        )
          return undefined;
        started++;
        try {
          const result = await read(
            signal === undefined
              ? scopeSignal
              : AbortSignal.any([signal, scopeSignal]),
          );
          this.failures.delete(cid);
          return result;
        } catch (error) {
          if (!closing.aborted && !signal?.aborted) this.recordFailure(cid);
          throw error;
        }
      },
      end: () => {
        clearTimeout(timer);
        deadline.abort(new RemoteBlockFetchDeadlineError());
      },
    };
  }

  /**
   * Read the blocks `cids` name for one message, `concurrency` at a time,
   * once the prefetches of earlier messages finish, so prefetching holds no
   * more blocks in memory than fetching inside the state queue did. Waiting
   * counts against the message's deadline. Blocks that cannot be fetched are
   * left out.
   */
  async prefetch(
    scope: RemoteBlockFetchScope,
    cids: readonly string[],
    read: (cid: string, signal: AbortSignal) => Promise<Uint8Array>,
    concurrency: number,
  ): Promise<Map<string, Uint8Array>> {
    const previous = this.prefetching;
    let release!: () => void;
    this.prefetching = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      await new Promise<void>((resolve) => {
        if (scope.signal.aborted) return resolve();
        scope.signal.addEventListener('abort', () => resolve(), {
          once: true,
        });
        void previous.then(resolve);
      });
      const blocks = new Map<string, Uint8Array>();
      let next = 0;
      const worker = async (): Promise<void> => {
        while (next < cids.length) {
          const cid = cids[next++]!;
          try {
            const block = await scope.fetch(cid, (signal) => read(cid, signal));
            if (block !== undefined) blocks.set(cid, block);
          } catch {
            // The block stays a missing dependency of the message.
          }
        }
      };
      await Promise.all(
        Array.from({ length: Math.min(concurrency, cids.length) }, worker),
      );
      return blocks;
    } finally {
      // A message that stopped waiting at its deadline releases its turn only
      // after the earlier prefetch ends.
      void previous.then(release);
    }
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
