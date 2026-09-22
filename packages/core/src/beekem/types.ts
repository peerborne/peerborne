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

/** One authenticated ancestor-key bundle sealed to a copath resolution node. */
export interface EncryptedPathKeyBundle {
  /** Tree node whose public key was used to seal the bundle. */
  recipientNodeIndex: number;
  /** ECIES ciphertext containing private path keys from this level to root. */
  ciphertext: Uint8Array;
}

/** A v2 path node with one bundle per non-blank copath resolution node. */
export interface PathNodeUpdateV2 {
  nodeIndex: number;
  publicKey: Uint8Array;
  encryptedPathKeyBundles: EncryptedPathKeyBundle[];
}

/**
 * Parent-bound, ordered update used by the BeeKEM PathUpdate v2 protocol.
 * The full public snapshot commits to the resulting tree, while
 * `parentTreeHash` prevents a higher-generation stale fork from replacing the
 * receiver's current membership state.
 */
export interface PathUpdateV2 {
  senderLeafIndex: number;
  senderLeafPublicKey: Uint8Array;
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
 * A private ancestor key delivered in a Welcome.
 */
export interface WelcomePathKey {
  /** Tree node index. */
  nodeIndex: number;
  /** New public key for this node (raw exported ECDH public key). */
  publicKey: Uint8Array;
  /** Private key sealed to the recipient or preceding Welcome path key. */
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

/** Generation-bearing Welcome required by the BeeKEM Welcome v2 protocol. */
export interface BeeKEMWelcomeV2 {
  leafIndex: number;
  pathKeys: WelcomePathKey[];
  treeNodePublicKeys: WelcomeNodePublicKey[];
  treeHash: Uint8Array;
  version: 2;
  generation: number;
  numLeaves: number;
}

/**
 * V2 wire-codec leaf bound.
 *
 * The conservative limit bounds tree traversal and per-update structural
 * work. Transport senders separately enforce the document protocol's frame
 * limit on the complete signed and framed request.
 */
export const MAX_BEEKEM_TREE_LEAVES = 1 << 13;
