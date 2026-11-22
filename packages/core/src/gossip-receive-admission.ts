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

export class GossipReceiveAdmission {
  private open = true;

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

  close(): void {
    this.open = false;
  }

  async run<T>(
    input: Uint8Array,
    operation: (frame: Uint8Array) => Promise<T>,
  ): Promise<T | undefined> {
    if (!this.open) return;
    let releaseLocal: (() => void) | undefined;
    let releaseAggregate: (() => void) | undefined;
    try {
      let frame: Uint8Array;
      try {
        const length = unsharedUint8ArrayByteLength(
          input,
          1,
          this.localBudget.maxBytes,
          'GossipSub sync frame',
        );
        releaseLocal = this.localBudget.reserve(length);
        releaseAggregate = this.aggregateBudget.reserve(length);
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
      releaseAggregate?.();
      releaseLocal?.();
    }
  }
}
