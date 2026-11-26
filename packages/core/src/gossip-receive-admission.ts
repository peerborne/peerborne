import {
  DEFAULT_DOCUMENT_OPERATION_BYTES,
  DEFAULT_DOCUMENT_OPERATION_COUNT,
  GroupDocumentOperationBudget,
} from './group-document-operation.js';
import {
  copyUnsharedUint8Array,
  unsharedUint8ArrayByteLength,
} from './utils.js';

// Both receive paths share these credits across all local document instances.
const aggregateGossipBudget = new GroupDocumentOperationBudget(
  64,
  64 * 1024 * 1024,
);

// Subscriptions holding a deferred frame, keyed by the budget they wait on.
const waitingForCapacity = new WeakMap<
  GroupDocumentOperationBudget,
  Set<GossipReceiveAdmission>
>();

function waiters(budget: GroupDocumentOperationBudget) {
  let set = waitingForCapacity.get(budget);
  if (set === undefined) {
    set = new Set();
    waitingForCapacity.set(budget, set);
  }
  return set;
}

interface DeferredFrame {
  readonly arrival: number;
  readonly frame: Uint8Array;
  readonly operation: (frame: Uint8Array) => Promise<unknown>;
}

export class GossipReceiveAdmission {
  private open = true;
  private nextArrival = 0;
  private readonly arrivals = new WeakMap<Uint8Array, number>();
  private deferred?: DeferredFrame;

  constructor(
    private readonly localBudget = new GroupDocumentOperationBudget(
      DEFAULT_DOCUMENT_OPERATION_COUNT,
      DEFAULT_DOCUMENT_OPERATION_BYTES,
    ),
    private readonly aggregateBudget = aggregateGossipBudget,
  ) {}

  get active(): boolean {
    return this.open;
  }

  /** Ciphertext bytes retained for the deferred frame, if any. */
  get deferredBytes(): number {
    return this.deferred?.frame.byteLength ?? 0;
  }

  close(): void {
    this.open = false;
    this.deferred = undefined;
    waitingForCapacity.get(this.aggregateBudget)?.delete(this);
  }

  /**
   * Run `operation` on a detached copy of `input` under the shared budgets.
   * A frame that finds no capacity is skipped. With `retry`, the most recently
   * arrived skipped frame is kept instead and passed to `retry` once capacity
   * frees. Later frames carry earlier changes inline, so the latest one
   * recovers a burst without an unbounded queue. Arrival order is fixed when a
   * given `input` is first seen, so a frame reaching a second receive stage
   * keeps its original position.
   */
  async run<T>(
    input: Uint8Array,
    operation: (frame: Uint8Array) => Promise<T>,
    retry?: (frame: Uint8Array) => Promise<unknown>,
  ): Promise<T | undefined> {
    if (!this.open) return;
    let length: number;
    try {
      length = unsharedUint8ArrayByteLength(
        input,
        1,
        this.localBudget.maxBytes,
        'GossipSub sync frame',
      );
    } catch {
      return undefined;
    }
    const arrival = this.arrival(input);
    const release = this.reserve(length);
    if (release === undefined) {
      if (retry !== undefined) this.defer(arrival, input, length, retry);
      return undefined;
    }
    try {
      let frame: Uint8Array;
      try {
        frame = copyUnsharedUint8Array(
          input,
          length,
          length,
          'GossipSub sync frame',
        );
      } catch {
        return undefined;
      }
      return await operation(frame);
    } finally {
      // Closing a subscription does not cancel work already inside a provider.
      release();
    }
  }

  private arrival(input: Uint8Array): number {
    let arrival = this.arrivals.get(input);
    if (arrival === undefined) {
      arrival = this.nextArrival++;
      this.arrivals.set(input, arrival);
    }
    return arrival;
  }

  private reserve(length: number): (() => void) | undefined {
    let releaseLocal: (() => void) | undefined;
    let releaseAggregate: () => void;
    try {
      releaseLocal = this.localBudget.reserve(length);
      releaseAggregate = this.aggregateBudget.reserve(length);
    } catch {
      releaseLocal?.();
      return undefined;
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      releaseAggregate();
      releaseLocal!();
      this.drain();
      for (const waiter of [...waiters(this.aggregateBudget)]) waiter.drain();
    };
  }

  private defer(
    arrival: number,
    input: Uint8Array,
    length: number,
    operation: (frame: Uint8Array) => Promise<unknown>,
  ): void {
    if (this.deferred !== undefined && this.deferred.arrival > arrival) return;
    let frame: Uint8Array;
    try {
      frame = copyUnsharedUint8Array(
        input,
        length,
        length,
        'GossipSub sync frame',
      );
    } catch {
      return;
    }
    this.deferred = { arrival, frame, operation };
    waiters(this.aggregateBudget).add(this);
  }

  private drain(): void {
    const deferred = this.deferred;
    if (deferred === undefined || !this.open) {
      waitingForCapacity.get(this.aggregateBudget)?.delete(this);
      return;
    }
    const release = this.reserve(deferred.frame.byteLength);
    if (release === undefined) return;
    this.deferred = undefined;
    waitingForCapacity.get(this.aggregateBudget)?.delete(this);
    void (async () => {
      try {
        await deferred.operation(deferred.frame);
      } catch {
        // `retry` owns failure reporting, as the caller of `run` does.
      } finally {
        release();
      }
    })();
  }
}
