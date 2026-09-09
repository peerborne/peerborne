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

/** One authenticated ancestor-key bundle sealed to a copath resolution node. */
export interface EncryptedPathKeyBundle {
  /** Tree node whose public key was used to seal the bundle. */
  recipientNodeIndex: number;
  /** ECIES ciphertext containing private path keys from this level to root. */
  ciphertext: Uint8Array;
}

/** A v2 path node with one bundle per non-blank copath resolution node. */
export interface PathNodeUpdateV2 extends PathNodeUpdate {
  encryptedPathKeyBundles: EncryptedPathKeyBundle[];
}

/**
 * Parent-bound, ordered update used by the BeeKEM PathUpdate v2 protocol.
 * The full public snapshot commits to the resulting tree, while
 * `parentTreeHash` prevents a higher-generation stale fork from replacing the
 * receiver's current membership state.
 */
export interface PathUpdateV2 extends PathUpdate {
  version: 2;
  generation: number;
  /** Hash of the exact generation immediately preceding this update. */
  parentTreeHash: Uint8Array;
  numLeaves: number;
  nodes: PathNodeUpdateV2[];
  treeNodePublicKeys: WelcomeNodePublicKey[];
  treeHash: Uint8Array;
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
  /** Sender generation. Omitted on the legacy v1 Welcome shape. */
  generation?: number;
  /** Exact leaf count. Omitted on the legacy v1 Welcome shape. */
  numLeaves?: number;
  /** Explicit protocol version. Omitted on the legacy v1 Welcome shape. */
  version?: 2;
}

/** Generation-bearing Welcome required by the BeeKEM Welcome v2 protocol. */
export interface BeeKEMWelcomeV2 extends BeeKEMWelcome {
  version: 2;
  generation: number;
  numLeaves: number;
}

/**
 * V2 wire-codec leaf bound.
 *
 * The conservative limit bounds decoded work and keeps a largest-shape V2
 * PathUpdate below the document protocol's 10 MiB frame limit. State engines
 * that emit V2 values MUST enforce the same bound before serialization.
 */
export const MAX_BEEKEM_TREE_LEAVES = 1 << 13;
