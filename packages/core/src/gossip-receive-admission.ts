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

/** Senders whose latest skipped frame one subscription retains. */
export const MAX_KEPT_FRAME_SENDERS = 8;

/**
 * What a cheap check of a skipped frame found. A sync request is evicted
 * before an ordinary sync frame when kept frames exceed their bounds.
 */
export type SkippedFrameKind = 'sync' | 'request';

// Subscriptions holding a kept frame, keyed by the budget they wait on.
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

interface RetainedFrame {
  readonly sender: string;
  readonly arrival: number;
  readonly frame: Uint8Array;
  readonly operation: (frame: Uint8Array) => Promise<unknown>;
  // Aggregate credit held while the frame waits.
  release: () => void;
  kind?: SkippedFrameKind;
}

function oldest(
  frames: Iterable<RetainedFrame>,
  preferred?: (frame: RetainedFrame) => boolean,
): RetainedFrame | undefined {
  let found: RetainedFrame | undefined;
  for (const frame of frames) {
    if (preferred && !preferred(frame)) continue;
    if (found === undefined || frame.arrival < found.arrival) found = frame;
  }
  return found;
}

export class GossipReceiveAdmission {
  private open = true;
  private nextArrival = 0;
  private readonly arrivals = new WeakMap<Uint8Array, number>();
  // Latest skipped frame per sender that passed the check.
  private readonly kept = new Map<string, RetainedFrame>();
  // Latest skipped frame per sender still waiting for the check.
  private readonly candidates = new Map<string, RetainedFrame>();
  private checking = false;

  constructor(
    private readonly localBudget = new GroupDocumentOperationBudget(
      DEFAULT_DOCUMENT_OPERATION_COUNT,
      DEFAULT_DOCUMENT_OPERATION_BYTES,
    ),
    private readonly aggregateBudget = aggregateGossipBudget,
    private readonly check: (
      frame: Uint8Array,
    ) => Promise<SkippedFrameKind | undefined> = async () => 'sync',
  ) {}

  get active(): boolean {
    return this.open;
  }

  /** Ciphertext bytes retained in kept frames. */
  get keptBytes(): number {
    let bytes = 0;
    for (const { frame } of this.kept.values()) bytes += frame.byteLength;
    return bytes;
  }

  close(): void {
    this.open = false;
    for (const frame of [...this.kept.values(), ...this.candidates.values()])
      frame.release();
    this.kept.clear();
    this.candidates.clear();
    waitingForCapacity.get(this.aggregateBudget)?.delete(this);
    this.notifyWaiters();
  }

  /**
   * Run `operation` on a detached copy of `input` under the shared budgets.
   * A frame that finds no capacity is skipped. With `retry`, the latest
   * skipped frame of each `sender` is checked by `check`, one at a time, and
   * kept until capacity frees, when it is passed to `retry`. A writer's later
   * frames carry its earlier changes inline, so its latest one recovers a
   * burst without an unbounded queue. A frame that fails the check is never
   * kept, and a sender's frame is only replaced by a newer one of its own.
   * Waiting and kept frames each hold a shared credit, and at most
   * `MAX_KEPT_FRAME_SENDERS` senders and the local byte budget are kept: sync
   * requests are dropped first, then the oldest frame. Arrival order is fixed
   * when a given `input` is first seen, so a frame reaching a second receive
   * stage keeps its original position.
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
      if (retry !== undefined) this.skip(sender, arrival, input, length, retry);
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
      this.notifyWaiters();
    };
  }

  private notifyWaiters(): void {
    for (const waiter of [...waiters(this.aggregateBudget)]) waiter.drain();
  }

  private discard(frame: RetainedFrame): void {
    frame.release();
    this.notifyWaiters();
  }

  private skip(
    sender: string,
    arrival: number,
    input: Uint8Array,
    length: number,
    operation: (frame: Uint8Array) => Promise<unknown>,
  ): void {
    if ((this.kept.get(sender)?.arrival ?? -1) > arrival) return;
    if ((this.candidates.get(sender)?.arrival ?? -1) > arrival) return;
    let release: () => void;
    try {
      release = this.aggregateBudget.reserve(length);
    } catch {
      return;
    }
    let frame: Uint8Array;
    try {
      frame = copyUnsharedUint8Array(
        input,
        length,
        length,
        'GossipSub sync frame',
      );
    } catch {
      release();
      return;
    }
    const replaced = this.candidates.get(sender);
    this.candidates.delete(sender);
    if (replaced) this.discard(replaced);
    this.candidates.set(sender, { sender, arrival, frame, operation, release });
    while (this.candidates.size > MAX_KEPT_FRAME_SENDERS) {
      const evicted = oldest(this.candidates.values())!;
      this.candidates.delete(evicted.sender);
      this.discard(evicted);
    }
    if (!this.checking) {
      this.checking = true;
      void this.checkCandidates();
    }
  }

  private async checkCandidates(): Promise<void> {
    try {
      for (
        let next = oldest(this.candidates.values());
        next !== undefined && this.open;
        next = oldest(this.candidates.values())
      ) {
        this.candidates.delete(next.sender);
        let kind: SkippedFrameKind | undefined;
        try {
          kind = await this.check(next.frame);
        } catch {
          // A failed check only drops the candidate.
        }
        if (kind !== undefined && this.open) {
          next.kind = kind;
          this.keep(next);
        } else {
          this.discard(next);
        }
      }
    } finally {
      this.checking = false;
    }
  }

  private keep(frame: RetainedFrame): void {
    const kept = this.kept.get(frame.sender);
    if (kept !== undefined && kept.arrival > frame.arrival) {
      this.discard(frame);
      return;
    }
    this.kept.delete(frame.sender);
    if (kept) this.discard(kept);
    this.kept.set(frame.sender, frame);
    while (
      this.kept.size > MAX_KEPT_FRAME_SENDERS ||
      this.keptBytes > this.localBudget.maxBytes
    ) {
      const evicted =
        oldest(this.kept.values(), ({ kind }) => kind === 'request') ??
        oldest(this.kept.values())!;
      this.kept.delete(evicted.sender);
      this.discard(evicted);
    }
    waiters(this.aggregateBudget).add(this);
    this.drain();
  }

  private drain(): void {
    while (this.open && this.kept.size > 0) {
      const kept = oldest(this.kept.values())!;
      this.kept.delete(kept.sender);
      // The kept frame's own shared credit becomes its processing credit.
      kept.release();
      const release = this.reserve(kept.frame.byteLength);
      if (release === undefined) {
        try {
          kept.release = this.aggregateBudget.reserve(kept.frame.byteLength);
          this.kept.set(kept.sender, kept);
        } catch {
          // Shared capacity was taken meanwhile; the frame is dropped.
        }
        return;
      }
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
