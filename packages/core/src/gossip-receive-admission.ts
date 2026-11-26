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

/** Senders whose latest skipped frame one subscription keeps. */
export const MAX_KEPT_FRAME_SENDERS = 8;

export class GossipReceiveAdmission {
  private open = true;
  private nextArrival = 0;
  private readonly arrivals = new WeakMap<Uint8Array, number>();
  // Latest skipped frame per sender, so one sender cannot displace another's.
  private readonly deferred = new Map<string, DeferredFrame>();

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

  /** Ciphertext bytes retained in kept frames. */
  get deferredBytes(): number {
    let bytes = 0;
    for (const { frame } of this.deferred.values()) bytes += frame.byteLength;
    return bytes;
  }

  close(): void {
    this.open = false;
    this.deferred.clear();
    waitingForCapacity.get(this.aggregateBudget)?.delete(this);
  }

  /**
   * Run `operation` on a detached copy of `input` under the shared budgets.
   * A frame that finds no capacity is skipped. With `retry`, the most recently
   * arrived skipped frame from each `sender` is kept instead and passed to
   * `retry` once capacity frees. A writer's later frames carry its earlier
   * changes inline, so its latest one recovers a burst without an unbounded
   * queue, and a frame from another sender cannot displace it. At most
   * `MAX_KEPT_FRAME_SENDERS` senders and the local byte budget are kept; the
   * oldest kept frame is dropped first. Arrival order is fixed when a given
   * `input` is first seen, so a frame reaching a second receive stage keeps
   * its original position.
   */
  async run<T>(
    input: Uint8Array,
    operation: (frame: Uint8Array) => Promise<T>,
    retry?: (frame: Uint8Array) => Promise<unknown>,
    sender = '',
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
      if (retry !== undefined)
        this.defer(sender, arrival, input, length, retry);
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
    sender: string,
    arrival: number,
    input: Uint8Array,
    length: number,
    operation: (frame: Uint8Array) => Promise<unknown>,
  ): void {
    const kept = this.deferred.get(sender);
    if (kept !== undefined && kept.arrival > arrival) return;
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
    this.deferred.delete(sender);
    this.deferred.set(sender, { arrival, frame, operation });
    while (
      this.deferred.size > MAX_KEPT_FRAME_SENDERS ||
      this.deferredBytes > this.localBudget.maxBytes
    ) {
      this.deferred.delete(this.oldestKept()!);
    }
    waiters(this.aggregateBudget).add(this);
  }

  private oldestKept(): string | undefined {
    let oldest: [string, number] | undefined;
    for (const [sender, { arrival }] of this.deferred)
      if (oldest === undefined || arrival < oldest[1])
        oldest = [sender, arrival];
    return oldest?.[0];
  }

  private drain(): void {
    while (this.open && this.deferred.size > 0) {
      const sender = this.oldestKept()!;
      const kept = this.deferred.get(sender)!;
      const release = this.reserve(kept.frame.byteLength);
      if (release === undefined) return;
      this.deferred.delete(sender);
      void (async () => {
        try {
          await kept.operation(kept.frame);
        } catch {
          // `retry` owns failure reporting, as the caller of `run` does.
        } finally {
          release();
        }
      })();
    }
    waitingForCapacity.get(this.aggregateBudget)?.delete(this);
  }
}
