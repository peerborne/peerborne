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
 * Largest frame one change may need on its own. Every frame also carries the
 * retained tree, which compaction keeps within the same bound, so a change
 * and its inherited history always fit `MAX_GOSSIP_SYNC_MESSAGE_BYTES`.
 */
export const MAX_CHANGE_FRAME_BYTES = MAX_GOSSIP_SYNC_MESSAGE_BYTES / 2;

/** A writer compacts once its retained tree serializes larger than this. */
export const RETAINED_TREE_HIGH_BYTES = MAX_CHANGE_FRAME_BYTES;

/** Change payload bytes a size-bound compaction keeps inline. */
export const RETAINED_TREE_KEEP_BYTES = 512 * 1024;

/** A change or sync message cannot be published in one GossipSub frame. */
export class GossipFrameLimitError extends RangeError {
  constructor(
    readonly byteLength: number,
    readonly limit: number,
    /** The local edit could not be undone, so the instance was retired. */
    readonly retired = false,
  ) {
    super(
      `Sync frame of ${byteLength} bytes exceeds the ${limit}-byte limit` +
        (retired
          ? '; the document instance was retired, reopen it from accepted state'
          : ''),
    );
    this.name = 'GossipFrameLimitError';
  }
}
