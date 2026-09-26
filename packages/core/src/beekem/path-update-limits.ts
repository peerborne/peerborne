import { MAX_BEEKEM_TREE_LEAVES } from './types.js';

/**
 * Maximum internal nodes on a v1 leaf-to-root direct path: a left-balanced
 * tree at the shared 8,192-leaf ceiling has at most 13.
 */
export const MAX_V1_PATH_NODES = Math.ceil(Math.log2(MAX_BEEKEM_TREE_LEAVES));

/**
 * Minimum non-empty ECIES ciphertext size for a v1 private path key: salt (32)
 * + ephemeral P-256 key (65) + nonce (12) + AES-GCM tag (16).
 */
export const MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES = 125;

/** Maximum ECIES ciphertext size for a v1 private path key. */
export const MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES = 4096;
