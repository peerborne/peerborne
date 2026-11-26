import { expect, test } from '@jest/globals';
import {
  GOSSIP_RETAINED_TREE_HIGH_BYTES,
  GOSSIP_RETAINED_TREE_KEEP_BYTES,
  MAX_DIRECT_SYNC_MESSAGE_BYTES,
  MAX_GOSSIP_SYNC_MESSAGE_BYTES,
  syncFrameTimeoutMs,
} from './gossip-frame.js';
import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

test('frame limits leave room for the GossipSub envelope and a new change', () => {
  expect(MAX_GOSSIP_SYNC_MESSAGE_BYTES).toBeLessThan(4 * 1024 * 1024);
  expect(GOSSIP_RETAINED_TREE_KEEP_BYTES).toBeLessThan(
    GOSSIP_RETAINED_TREE_HIGH_BYTES,
  );
  expect(GOSSIP_RETAINED_TREE_HIGH_BYTES).toBeLessThan(
    MAX_GOSSIP_SYNC_MESSAGE_BYTES,
  );
  expect(MAX_DIRECT_SYNC_MESSAGE_BYTES).toBeLessThan(
    MAX_SHARED_PROTOCOL_REQUEST_BYTES,
  );
});

test('a direct frame deadline grows with its size and the receiver allows the largest', () => {
  const small = syncFrameTimeoutMs(1024);
  const large = syncFrameTimeoutMs(MAX_DIRECT_SYNC_MESSAGE_BYTES);
  expect(small).toBeGreaterThanOrEqual(5_000);
  expect(large).toBeGreaterThan(small);
  // A full frame is given time at 128 KiB/s.
  expect(large).toBeGreaterThanOrEqual(
    (MAX_DIRECT_SYNC_MESSAGE_BYTES / (128 * 1024)) * 1000,
  );
  expect(syncFrameTimeoutMs()).toBeGreaterThanOrEqual(large);
});
