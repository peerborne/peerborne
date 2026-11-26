import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

/**
 * Largest serialized sync message one GossipSub document frame carries.
 *
 * `@libp2p/gossipsub` length-prefixes every outbound RPC with
 * `it-length-prefixed`'s fixed 4 MiB limit, and the receiver applies the same
 * default. A longer RPC is not sent: `publish()` resolves with no recipients.
 * The remaining 512 KiB covers encryption, the GossipSub envelope and topic,
 * and control messages piggybacked on the same RPC.
 */
export const MAX_GOSSIP_SYNC_MESSAGE_BYTES = 3.5 * 1024 * 1024;

/**
 * A writer compacts its retained change tree once a published sync message
 * exceeds this size, so the next frame has room for a change of up to
 * `MAX_GOSSIP_SYNC_MESSAGE_BYTES - GOSSIP_RETAINED_TREE_HIGH_BYTES`.
 */
export const GOSSIP_RETAINED_TREE_HIGH_BYTES = 2 * 1024 * 1024;

/** Change payload bytes a byte-bound compaction keeps inline. */
export const GOSSIP_RETAINED_TREE_KEEP_BYTES = 1024 * 1024;

/**
 * Largest serialized sync message sent directly over `syncFrameV1` when it does
 * not fit a GossipSub frame. The margin covers the path header and encryption.
 */
export const MAX_DIRECT_SYNC_MESSAGE_BYTES =
  MAX_SHARED_PROTOCOL_REQUEST_BYTES - 64 * 1024;

/** Slowest transfer rate a `syncFrameV1` exchange is given time for. */
const SYNC_FRAME_MIN_BYTES_PER_SECOND = 128 * 1024;
const SYNC_FRAME_BASE_TIMEOUT_MS = 5_000;

/**
 * Deadline for sending, or receiving, a `syncFrameV1` frame of `bytes`. The
 * receiver cannot know the size in advance, so it allows the maximum.
 */
export function syncFrameTimeoutMs(
  bytes = MAX_SHARED_PROTOCOL_REQUEST_BYTES,
): number {
  return (
    SYNC_FRAME_BASE_TIMEOUT_MS +
    Math.ceil((bytes * 1000) / SYNC_FRAME_MIN_BYTES_PER_SECOND)
  );
}

/** A sync message cannot be delivered in one frame. */
export class GossipFrameLimitError extends RangeError {
  constructor(limit = MAX_DIRECT_SYNC_MESSAGE_BYTES) {
    super(`Sync message exceeds the ${limit}-byte frame limit`);
    this.name = 'GossipFrameLimitError';
  }
}
