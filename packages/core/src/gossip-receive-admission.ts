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

/** Senders whose latest skipped, authenticated frame one subscription keeps. */
export const MAX_KEPT_FRAME_SENDERS = 8;

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

interface SkippedFrame {
  readonly sender: string;
  readonly arrival: number;
  readonly frame: Uint8Array;
  readonly operation: (frame: Uint8Array) => Promise<unknown>;
}

export class GossipReceiveAdmission {
  private open = true;
  private nextArrival = 0;
  private readonly arrivals = new WeakMap<Uint8Array, number>();
  // Latest authenticated skipped frame per sender.
  private readonly kept = new Map<string, SkippedFrame>();
  private authenticating = false;
  // Latest skipped frame waiting for the single authentication slot.
  private candidate?: SkippedFrame;

  constructor(
    private readonly localBudget = new GroupDocumentOperationBudget(
      DEFAULT_DOCUMENT_OPERATION_COUNT,
      DEFAULT_DOCUMENT_OPERATION_BYTES,
    ),
    private readonly aggregateBudget = aggregateGossipBudget,
    private readonly authenticate: (
      frame: Uint8Array,
    ) => Promise<boolean> = async () => true,
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
    this.kept.clear();
    this.candidate = undefined;
    waitingForCapacity.get(this.aggregateBudget)?.delete(this);
  }

  /**
   * Run `operation` on a detached copy of `input` under the shared budgets.
   * A frame that finds no capacity is skipped. With `retry`, a skipped frame
   * is checked by `authenticate` (one at a time, so a newer arrival replaces
   * one waiting for the check) and, if it passes, kept as its `sender`'s
   * latest frame until capacity frees. A writer's later frames carry its
   * earlier changes inline, so its latest one recovers a burst without an
   * unbounded queue, and a frame that fails authentication never displaces a
   * kept one. At most `MAX_KEPT_FRAME_SENDERS` senders and the local byte
   * budget are kept; the oldest is dropped first. Arrival order is fixed when
   * a given `input` is first seen, so a frame reaching a second receive stage
   * keeps its original position.
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
      for (const waiter of [...waiters(this.aggregateBudget)]) waiter.drain();
    };
  }

  private skip(
    sender: string,
    arrival: number,
    input: Uint8Array,
    length: number,
    operation: (frame: Uint8Array) => Promise<unknown>,
  ): void {
    const kept = this.kept.get(sender);
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
    const skipped = { sender, arrival, frame, operation };
    if (this.authenticating) {
      if (this.candidate === undefined || this.candidate.arrival <= arrival)
        this.candidate = skipped;
      return;
    }
    this.authenticating = true;
    void this.authenticateSkipped(skipped);
  }

  private async authenticateSkipped(first: SkippedFrame): Promise<void> {
    let next: SkippedFrame | undefined = first;
    try {
      while (next !== undefined && this.open) {
        let authentic = false;
        try {
          authentic = (await this.authenticate(next.frame)) === true;
        } catch {
          // An authentication failure only drops the candidate.
        }
        if (authentic && this.open) this.keep(next);
        next = this.candidate;
        this.candidate = undefined;
      }
    } finally {
      this.authenticating = false;
      this.candidate = undefined;
    }
  }

  private keep(skipped: SkippedFrame): void {
    const kept = this.kept.get(skipped.sender);
    if (kept !== undefined && kept.arrival > skipped.arrival) return;
    this.kept.delete(skipped.sender);
    this.kept.set(skipped.sender, skipped);
    while (
      this.kept.size > MAX_KEPT_FRAME_SENDERS ||
      this.keptBytes > this.localBudget.maxBytes
    ) {
      this.kept.delete(this.oldestKept()!);
    }
    waiters(this.aggregateBudget).add(this);
    this.drain();
  }

  private oldestKept(): string | undefined {
    let oldest: SkippedFrame | undefined;
    for (const kept of this.kept.values())
      if (oldest === undefined || kept.arrival < oldest.arrival) oldest = kept;
    return oldest?.sender;
  }

  private drain(): void {
    while (this.open && this.kept.size > 0) {
      const sender = this.oldestKept()!;
      const kept = this.kept.get(sender)!;
      const release = this.reserve(kept.frame.byteLength);
      if (release === undefined) return;
      this.kept.delete(sender);
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
