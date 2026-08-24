/**
 * BeeKEM type definitions for ratchet tree group key agreement.
 *
 * Based on Ink & Switch's Keyhive specification for local-first
 * CRDT applications with causal ordering.
 */

/**
 * A node in the BeeKEM ratchet tree.
 */
export type TreeNode = LeafNode | InternalNode;

/**
 * Leaf node containing a member's ECDH key pair.
 */
export interface LeafNode {
  type: 'leaf';
  /** Index in the tree (even indices are leaves). */
  index: number;
  /** Member's ECDH public key. Null means the leaf is blanked (removed member). */
  publicKey: CryptoKey | null;
  /** Member's ECDH private key (only set for the local member). */
  privateKey?: CryptoKey;
}

/**
 * Internal node with derived key material.
 * May have conflict keys from concurrent updates.
 */
export interface InternalNode {
  type: 'internal';
  /** Index in the tree (odd indices are internal). */
  index: number;
  /** Derived public key for this subtree. */
  publicKey: CryptoKey | null;
  /** Derived private key (only available if we are in this subtree). */
  privateKey?: CryptoKey;
  /** Conflict keys from concurrent updates (BeeKEM-specific). */
  conflictKeys?: CryptoKey[];
}

/**
 * Path update message: encrypted key pairs along a path from leaf to root.
 */
export interface PathUpdate {
  /** Index of the leaf that initiated the update. */
  senderLeafIndex: number;
  /** Sender's new leaf public key (raw exported ECDH public key). */
  senderLeafPublicKey: Uint8Array;
  /** Encrypted node updates along the path to root. */
  nodes: PathNodeUpdate[];
}

/**
 * A single node update in a path update message.
 */
export interface PathNodeUpdate {
  /** Tree node index. */
  nodeIndex: number;
  /** New public key for this node (raw exported ECDH public key). */
  publicKey: Uint8Array;
  /** Encrypted private key for the sibling subtree. */
  encryptedPrivateKey: Uint8Array;
}

/**
 * A node public key entry in a welcome message (public key only, no private material).
 */
export interface WelcomeNodePublicKey {
  /** Tree node index. */
  nodeIndex: number;
  /** Raw exported ECDH public key (null if the node is blanked). */
  publicKey: Uint8Array | null;
}

/**
 * Welcome message for a new member joining the group.
 */
export interface BeeKEMWelcome {
  /** The new member's leaf index. */
  leafIndex: number;
  /** Path keys from the new leaf to root, encrypted to the new member. */
  pathKeys: PathNodeUpdate[];
  /**
   * Public keys for all tree nodes not covered by pathKeys or the new member's
   * own leaf. Includes peer leaves and internal nodes so the joiner can
   * reconstruct the full tree for hash verification and future path updates.
   */
  treeNodePublicKeys: WelcomeNodePublicKey[];
  /** Serialized tree state hash for verification. */
  treeHash: Uint8Array;
}
