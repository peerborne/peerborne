import {
  TreeNode,
  LeafNode,
  InternalNode,
  PathUpdate,
  PathNodeUpdate,
  BeeKEMWelcome,
  WelcomeNodePublicKey,
} from './types.js';
import * as TreeMath from './tree-math.js';
import { eciesSeal, eciesOpen } from '../ecies.js';

/** ECDH curve used for tree key pairs. */
const ECDH_CURVE = 'P-256';
const ECDH_ALGO = { name: 'ECDH', namedCurve: ECDH_CURVE };

/** Cast Uint8Array to ArrayBuffer for WebCrypto API compatibility. */
function toBuffer(data: Uint8Array): ArrayBuffer {
  return (data.buffer as ArrayBuffer).slice(
    data.byteOffset,
    data.byteOffset + data.byteLength,
  );
}

/**
 * BeeKEM: Binary ratchet tree for decentralized group key agreement.
 *
 * Based on Ink & Switch's Keyhive specification.
 * Provides forward secrecy and post-compromise security with O(log n)
 * cost per operation.
 *
 * Tree layout uses left-balanced binary tree indexing:
 * - Leaf nodes (even indices) hold member ECDH key pairs
 * - Internal nodes (odd indices) hold derived key pairs
 * - The root node's key material is the shared group secret
 */
export class BeeKEM {
  private _nodes: Map<number, TreeNode> = new Map();
  private _numLeaves: number = 0;
  private _myLeafIndex: number = -1;

  /**
   * Initialize as the first member of a new group.
   * Creates a single-leaf tree with the creator's key pair.
   */
  async initialize(privateKey: CryptoKey, publicKey: CryptoKey): Promise<void> {
    this._nodes.clear();
    this._numLeaves = 1;
    this._myLeafIndex = 0;

    const leaf: LeafNode = {
      type: 'leaf',
      index: 0,
      publicKey,
      privateKey,
    };
    this._nodes.set(0, leaf);
  }

  /**
   * Add a new member to the group.
   * Creates a new leaf and derives keys along the path to root.
   * Returns a path update message to broadcast and a welcome for the new member.
   */
  async addMember(memberPublicKey: CryptoKey): Promise<{
    pathUpdate: PathUpdate;
    welcome: BeeKEMWelcome;
    rootSecret: Uint8Array;
  }> {
    // Add new leaf at next position
    const newLeafPos = this._numLeaves;
    const newLeafIndex = TreeMath.leafToNodeIndex(newLeafPos);
    this._numLeaves++;

    const newLeaf: LeafNode = {
      type: 'leaf',
      index: newLeafIndex,
      publicKey: memberPublicKey,
    };
    this._nodes.set(newLeafIndex, newLeaf);

    // Generate fresh key material along our path to root
    const { pathUpdate, rootSecret } = await this._updatePath();

    // Build welcome message for the new member
    const welcome = await this._buildWelcome(newLeafIndex, memberPublicKey);

    return { pathUpdate, welcome, rootSecret };
  }

  /**
   * Remove a member from the group.
   * Blanks the member's leaf and all nodes on their direct path.
   * Returns a path update with fresh key material.
   */
  async removeMember(memberLeafIndex: number): Promise<{
    pathUpdate: PathUpdate;
    rootSecret: Uint8Array;
  }> {
    // Blank the removed member's leaf
    const blankedLeaf: LeafNode = {
      type: 'leaf',
      index: memberLeafIndex,
      publicKey: null,
    };
    this._nodes.set(memberLeafIndex, blankedLeaf);

    // Blank all internal nodes on the removed member's direct path
    const removedPath = TreeMath.directPath(memberLeafIndex, this._numLeaves);
    for (const nodeIndex of removedPath) {
      const blankedNode: InternalNode = {
        type: 'internal',
        index: nodeIndex,
        publicKey: null,
      };
      this._nodes.set(nodeIndex, blankedNode);
    }

    // Generate fresh key pair for our leaf
    const newKeyPair = await crypto.subtle.generateKey(ECDH_ALGO, true, [
      'deriveBits',
    ]);
    const myLeaf: LeafNode = {
      type: 'leaf',
      index: this._myLeafIndex,
      publicKey: newKeyPair.publicKey,
      privateKey: newKeyPair.privateKey,
    };
    this._nodes.set(this._myLeafIndex, myLeaf);

    // Re-derive path keys from our leaf to root
    return this._updatePath();
  }

  /**
   * Perform a self-update for post-compromise security.
   * Generates fresh key material along our path.
   */
  async update(): Promise<{
    pathUpdate: PathUpdate;
    rootSecret: Uint8Array;
  }> {
    // Generate new ECDH key pair for our leaf
    const newKeyPair = await crypto.subtle.generateKey(ECDH_ALGO, true, [
      'deriveBits',
    ]);
    const myLeaf: LeafNode = {
      type: 'leaf',
      index: this._myLeafIndex,
      publicKey: newKeyPair.publicKey,
      privateKey: newKeyPair.privateKey,
    };
    this._nodes.set(this._myLeafIndex, myLeaf);

    // Re-derive all internal node keys on our path to root
    return this._updatePath();
  }

  /**
   * Process a path update from another member.
   * Decrypts the relevant encrypted key and derives the new root.
   */
  async processPathUpdate(update: PathUpdate): Promise<Uint8Array> {
    // Update the sender's leaf with their new public key
    const senderLeafPublicKey = await crypto.subtle.importKey(
      'raw',
      toBuffer(update.senderLeafPublicKey),
      ECDH_ALGO,
      true,
      [],
    );
    const senderLeaf: LeafNode = {
      type: 'leaf',
      index: update.senderLeafIndex,
      publicKey: senderLeafPublicKey,
    };
    this._nodes.set(update.senderLeafIndex, senderLeaf);

    // Find where our copath intersects the update path
    const myCopath = TreeMath.copath(this._myLeafIndex, this._numLeaves);
    const myDirectPath = TreeMath.directPath(
      this._myLeafIndex,
      this._numLeaves,
    );

    // The update path consists of internal nodes from the sender's leaf to root.
    // We need to find the first node in the update that is on our direct path.
    // At that node, the encrypted private key is encrypted to the resolution
    // of the subtree on OUR side (the sender's copath), so we can decrypt it
    // using a private key from our subtree.
    let decryptedPrivateKey: CryptoKey | null = null;
    let intersectionIdx = -1;

    for (let i = 0; i < update.nodes.length; i++) {
      const pathNode = update.nodes[i];
      const dpIdx = myDirectPath.indexOf(pathNode.nodeIndex);
      if (dpIdx >= 0) {
        // This update node is on our direct path.
        // The sender encrypted this node's private key to the resolution of
        // the subtree on OUR side (the sender's copath at this level).
        // Find the child of this node on our side and look for a private key.
        const childOnOurSide = this._findChildOnOurSide(pathNode.nodeIndex);
        if (childOnOurSide !== undefined) {
          const childNode = this._nodes.get(childOnOurSide);
          if (childNode?.privateKey) {
            decryptedPrivateKey = await this._decryptNodeKey(
              pathNode.encryptedPrivateKey,
              childNode.privateKey,
            );
          } else {
            // Walk down our subtree to find any node with a private key
            const resolved = await this._resolveSubtreeKey(childOnOurSide);
            if (resolved) {
              decryptedPrivateKey = await this._decryptNodeKey(
                pathNode.encryptedPrivateKey,
                resolved,
              );
            }
          }
        }

        intersectionIdx = i;
        break;
      }
    }

    if (!decryptedPrivateKey || intersectionIdx === -1) {
      throw new Error(
        'Cannot process path update: no intersection found with our path',
      );
    }

    // Import the public key for the intersection node
    const intersectionNode = update.nodes[intersectionIdx];
    const intersectionPublicKey = await crypto.subtle.importKey(
      'raw',
      toBuffer(intersectionNode.publicKey),
      ECDH_ALGO,
      true,
      [],
    );

    // Set the intersection node
    const intNode: InternalNode = {
      type: 'internal',
      index: intersectionNode.nodeIndex,
      publicKey: intersectionPublicKey,
      privateKey: decryptedPrivateKey,
    };
    this._nodes.set(intersectionNode.nodeIndex, intNode);

    // Update all remaining nodes above the intersection (toward root)
    // with their public keys, and derive private keys where possible
    for (let i = intersectionIdx + 1; i < update.nodes.length; i++) {
      const pathNode = update.nodes[i];
      const publicKey = await crypto.subtle.importKey(
        'raw',
        toBuffer(pathNode.publicKey),
        ECDH_ALGO,
        true,
        [],
      );

      // If this node is on our direct path, we can derive its private key
      // from the child on our side
      const childOnOurSide = this._findChildOnOurSide(pathNode.nodeIndex);
      const childNode = childOnOurSide !== undefined
        ? this._nodes.get(childOnOurSide)
        : undefined;
      let privateKey: CryptoKey | undefined;

      if (childNode?.privateKey) {
        // Decrypt this node's private key
        privateKey = await this._decryptNodeKey(
          pathNode.encryptedPrivateKey,
          childNode.privateKey,
        );
      }

      const node: InternalNode = {
        type: 'internal',
        index: pathNode.nodeIndex,
        publicKey,
        privateKey,
      };
      this._nodes.set(pathNode.nodeIndex, node);
    }

    // Also update nodes below the intersection from the sender's side
    for (let i = 0; i < intersectionIdx; i++) {
      const pathNode = update.nodes[i];
      const publicKey = await crypto.subtle.importKey(
        'raw',
        toBuffer(pathNode.publicKey),
        ECDH_ALGO,
        true,
        [],
      );
      const node: InternalNode = {
        type: 'internal',
        index: pathNode.nodeIndex,
        publicKey,
      };
      this._nodes.set(pathNode.nodeIndex, node);
    }

    return this.getRootSecret();
  }

  /**
   * Process a welcome message to join an existing group.
   */
  async processWelcome(
    welcome: BeeKEMWelcome,
    privateKey: CryptoKey,
    publicKey: CryptoKey,
  ): Promise<Uint8Array> {
    this._myLeafIndex = welcome.leafIndex;

    // Derive numLeaves conservatively from the leaf index and the max
    // path key node indices. The leaf index gives us a lower bound;
    // internal node indices on the path may imply a larger tree.
    const leafBasedCount =
      TreeMath.nodeToLeafIndex(welcome.leafIndex) + 1;
    let maxFromPath = leafBasedCount;
    for (const pk of welcome.pathKeys) {
      // Each internal node index implies a minimum tree width
      const implied =
        TreeMath.nodeToLeafIndex(
          pk.nodeIndex % 2 === 0 ? pk.nodeIndex : pk.nodeIndex + 1,
        ) + 1;
      if (implied > maxFromPath) maxFromPath = implied;
    }
    this._numLeaves = Math.max(this._numLeaves, maxFromPath);

    // Set up our leaf node
    const myLeaf: LeafNode = {
      type: 'leaf',
      index: welcome.leafIndex,
      publicKey,
      privateKey,
    };
    this._nodes.set(welcome.leafIndex, myLeaf);

    // Decrypt path keys using our private key for the first one,
    // then derive the rest up the tree
    let currentPrivateKey = privateKey;

    for (const pathKey of welcome.pathKeys) {
      const nodePublicKey = await crypto.subtle.importKey(
        'raw',
        toBuffer(pathKey.publicKey),
        ECDH_ALGO,
        true,
        [],
      );

      // Decrypt the private key for this node
      const nodePrivateKey = await this._decryptNodeKey(
        pathKey.encryptedPrivateKey,
        currentPrivateKey,
      );

      const node: InternalNode = {
        type: 'internal',
        index: pathKey.nodeIndex,
        publicKey: nodePublicKey,
        privateKey: nodePrivateKey,
      };
      this._nodes.set(pathKey.nodeIndex, node);

      // Use this node's private key to decrypt the next level
      currentPrivateKey = nodePrivateKey;
    }

    // Install all tree node public keys so we have the full tree state
    for (const nodeEntry of welcome.treeNodePublicKeys) {
      if (nodeEntry.publicKey) {
        const pubKey = await crypto.subtle.importKey(
          'raw',
          toBuffer(nodeEntry.publicKey),
          ECDH_ALGO,
          true,
          [],
        );
        const isLeaf = TreeMath.isLeaf(nodeEntry.nodeIndex);
        const node: TreeNode = isLeaf
          ? { type: 'leaf', index: nodeEntry.nodeIndex, publicKey: pubKey }
          : { type: 'internal', index: nodeEntry.nodeIndex, publicKey: pubKey };
        this._nodes.set(nodeEntry.nodeIndex, node);
      } else {
        const isLeaf = TreeMath.isLeaf(nodeEntry.nodeIndex);
        const node: TreeNode = isLeaf
          ? { type: 'leaf', index: nodeEntry.nodeIndex, publicKey: null }
          : { type: 'internal', index: nodeEntry.nodeIndex, publicKey: null };
        this._nodes.set(nodeEntry.nodeIndex, node);
      }
    }

    // Verify tree hash matches the sender's snapshot
    const computedHash = await this._computeTreeHash();
    if (
      computedHash.byteLength !== welcome.treeHash.byteLength ||
      !computedHash.every((b, i) => b === welcome.treeHash[i])
    ) {
      throw new Error(
        'Welcome tree hash mismatch: reconstructed tree does not match sender state',
      );
    }

    return this.getRootSecret();
  }

  /**
   * Get the current root secret (shared by all members).
   * Exports the root node's private key material as raw bytes.
   */
  async getRootSecret(): Promise<Uint8Array> {
    if (this._numLeaves <= 0) {
      throw new Error('Tree is empty');
    }

    if (this._numLeaves === 1) {
      // Single member: root secret is derived from the leaf's key
      const leaf = this._nodes.get(0);
      if (!leaf?.privateKey) {
        throw new Error('No private key available for root secret derivation');
      }
      const exported = await crypto.subtle.exportKey('pkcs8', leaf.privateKey);
      // Hash the exported key to get a uniform-length secret
      const hash = await crypto.subtle.digest('SHA-256', exported);
      return new Uint8Array(hash);
    }

    const rootIndex = TreeMath.root(this._numLeaves);
    const rootNode = this._nodes.get(rootIndex);

    if (!rootNode?.privateKey) {
      throw new Error('Root secret not available: no private key at root node');
    }

    const exported = await crypto.subtle.exportKey('pkcs8', rootNode.privateKey);
    // Hash to get a uniform 32-byte secret
    const hash = await crypto.subtle.digest('SHA-256', exported);
    return new Uint8Array(hash);
  }

  /** Number of leaves in the tree (including blanked positions). */
  get memberCount(): number {
    return this._numLeaves;
  }

  /** Our leaf index in the tree. */
  get myLeafIndex(): number {
    return this._myLeafIndex;
  }

  /**
   * Find the node index of the leaf whose public key matches `publicKey`,
   * or `undefined` if no such (non-blanked) leaf exists.
   *
   * Used by `PeerborneDocument.removeReader` as the canonical source
   * of truth for leaf-index lookup during revocation: the writer's
   * in-memory `_readerLeafIndices` cache is wiped on process restart,
   * so revocation must be able to recover the leaf assignment from
   * tree state alone.
   *
   * Comparison is done over the raw exported ECDH public key bytes:
   * - `CryptoKey` inputs are exported via `crypto.subtle.exportKey('raw', ...)`
   *   so the caller doesn't need to pre-export.
   * - `Uint8Array` inputs are compared directly (assumed to be raw
   *   SEC1-uncompressed P-256 bytes, the same shape stored on the wire
   *   and accepted by `addMember` / `_registerBeeKEMReader`).
   *
   * Blanked leaves (publicKey === null) are skipped: their slot index
   * is meaningless to a "find this member" query, and a match against
   * a blanked leaf would let stale public-key references re-resolve to
   * an already-removed slot.
   *
   * Returns the **node index** (even-indexed tree slot), which is the
   * form `removeMember` consumes. Callers that need the dense
   * leaf-position form should convert via `TreeMath.nodeToLeafIndex`.
   */
  async findLeafByPublicKey(
    publicKey: CryptoKey | Uint8Array,
  ): Promise<number | undefined> {
    let target: Uint8Array;
    if (publicKey instanceof Uint8Array) {
      target = publicKey;
    } else {
      target = new Uint8Array(
        await crypto.subtle.exportKey('raw', publicKey),
      );
    }

    for (let leafPos = 0; leafPos < this._numLeaves; leafPos++) {
      const nodeIndex = TreeMath.leafToNodeIndex(leafPos);
      const node = this._nodes.get(nodeIndex);
      if (!node || node.type !== 'leaf' || !node.publicKey) {
        continue;
      }
      const leafRaw = new Uint8Array(
        await crypto.subtle.exportKey('raw', node.publicKey),
      );
      if (leafRaw.byteLength !== target.byteLength) continue;
      let match = true;
      for (let i = 0; i < leafRaw.byteLength; i++) {
        if (leafRaw[i] !== target[i]) {
          match = false;
          break;
        }
      }
      if (match) return nodeIndex;
    }
    return undefined;
  }

  /**
   * Remove blanked leaf nodes and their parent path nodes from the tree
   * when an entire subtree is blanked. This reclaims memory for nodes
   * that can never contribute to key derivation.
   */
  compact(): void {
    // Find blanked leaf indices
    const blankedLeaves: number[] = [];
    for (let i = 0; i < this._numLeaves; i++) {
      const nodeIndex = TreeMath.leafToNodeIndex(i);
      const node = this._nodes.get(nodeIndex);
      if (!node || node.publicKey === null) {
        blankedLeaves.push(nodeIndex);
      }
    }

    // For each blanked leaf, check if all nodes on its direct path
    // are also blanked. If so, remove the leaf and those path nodes.
    for (const leafIndex of blankedLeaves) {
      if (this._numLeaves <= 1) break;
      const path = TreeMath.directPath(leafIndex, this._numLeaves);
      const allBlanked = path.every((idx) => {
        const n = this._nodes.get(idx);
        return !n || n.publicKey === null;
      });
      if (allBlanked) {
        this._nodes.delete(leafIndex);
        for (const idx of path) {
          this._nodes.delete(idx);
        }
      }
    }
  }

  // ---- Private helpers ----

  /**
   * Generate fresh key pairs along our direct path and encrypt each
   * to the corresponding sibling subtree's resolution key.
   */
  private async _updatePath(): Promise<{
    pathUpdate: PathUpdate;
    rootSecret: Uint8Array;
  }> {
    // Export our leaf public key for inclusion in the PathUpdate
    const myLeaf = this._nodes.get(this._myLeafIndex);
    if (!myLeaf?.publicKey) {
      throw new Error('Cannot update path: no public key at our leaf');
    }
    const senderLeafPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', myLeaf.publicKey),
    );

    if (this._numLeaves === 1) {
      // Single member: no path to update
      const rootSecret = await this.getRootSecret();
      return {
        pathUpdate: {
          senderLeafIndex: this._myLeafIndex,
          senderLeafPublicKey,
          nodes: [],
        },
        rootSecret,
      };
    }

    const dp = TreeMath.directPath(this._myLeafIndex, this._numLeaves);
    const cp = TreeMath.copath(this._myLeafIndex, this._numLeaves);
    const pathNodes: PathNodeUpdate[] = [];

    for (let i = 0; i < dp.length; i++) {
      const nodeIndex = dp[i];
      const siblingIndex = cp[i];

      // Generate fresh ECDH key pair for this internal node
      const nodeKeyPair = await crypto.subtle.generateKey(ECDH_ALGO, true, [
        'deriveBits',
      ]);

      // Get the sibling's resolution public key (for encryption)
      const siblingPublicKey = await this._resolvePublicKey(siblingIndex);

      // Export the new public key
      const exportedPublicKey = new Uint8Array(
        await crypto.subtle.exportKey('raw', nodeKeyPair.publicKey),
      );

      // Encrypt the private key to the sibling's public key
      let encryptedPrivateKey: Uint8Array;
      if (siblingPublicKey) {
        encryptedPrivateKey = await this._encryptNodeKey(
          nodeKeyPair.privateKey,
          siblingPublicKey,
        );
      } else {
        // Sibling subtree is blank; encrypt with empty (will only work if
        // the subtree gets populated before needing to decrypt)
        encryptedPrivateKey = new Uint8Array(0);
      }

      // Store the node locally
      const internalNode: InternalNode = {
        type: 'internal',
        index: nodeIndex,
        publicKey: nodeKeyPair.publicKey,
        privateKey: nodeKeyPair.privateKey,
      };
      this._nodes.set(nodeIndex, internalNode);

      pathNodes.push({
        nodeIndex,
        publicKey: exportedPublicKey,
        encryptedPrivateKey,
      });
    }

    const rootSecret = await this.getRootSecret();

    return {
      pathUpdate: {
        senderLeafIndex: this._myLeafIndex,
        senderLeafPublicKey,
        nodes: pathNodes,
      },
      rootSecret,
    };
  }

  /**
   * Build a welcome message for a new member at the given leaf index.
   * Encrypts path keys so the new member can derive the root secret.
   */
  private async _buildWelcome(
    newLeafIndex: number,
    newMemberPublicKey: CryptoKey,
  ): Promise<BeeKEMWelcome> {
    const dp = TreeMath.directPath(newLeafIndex, this._numLeaves);
    const pathKeys: PathNodeUpdate[] = [];

    // The new member needs private keys for each node on their direct path.
    // Encrypt each node's private key: the first one to the new member's key,
    // subsequent ones to the previous node's key (forming a chain).
    let encryptionKey: CryptoKey = newMemberPublicKey;

    for (const nodeIndex of dp) {
      const node = this._nodes.get(nodeIndex);
      if (!node?.publicKey || !node.privateKey) {
        throw new Error(
          `Cannot build welcome: missing key at node ${nodeIndex}`,
        );
      }

      const exportedPublicKey = new Uint8Array(
        await crypto.subtle.exportKey('raw', node.publicKey),
      );

      // Encrypt this node's private key to the encryption key
      const encryptedPrivateKey = await this._encryptNodeKey(
        node.privateKey,
        encryptionKey,
      );

      pathKeys.push({
        nodeIndex,
        publicKey: exportedPublicKey,
        encryptedPrivateKey,
      });

      // Next level uses this node's public key for encryption
      encryptionKey = node.publicKey;
    }

    // Collect public keys for all tree nodes NOT already covered by pathKeys
    // or the new member's own leaf. This allows the joiner to reconstruct the
    // full tree state for hash verification and future path updates.
    const pathKeyIndices = new Set(dp);
    const treeNodePublicKeys: WelcomeNodePublicKey[] = [];
    for (const [nodeIndex, node] of this._nodes) {
      if (nodeIndex === newLeafIndex) continue; // skip new member's own leaf
      if (pathKeyIndices.has(nodeIndex)) continue; // already in pathKeys
      if (node.publicKey) {
        const exported = new Uint8Array(
          await crypto.subtle.exportKey('raw', node.publicKey),
        );
        treeNodePublicKeys.push({ nodeIndex, publicKey: exported });
      } else {
        treeNodePublicKeys.push({ nodeIndex, publicKey: null });
      }
    }

    // Tree hash for verification
    const treeHash = await this._computeTreeHash();

    return {
      leafIndex: newLeafIndex,
      pathKeys,
      treeNodePublicKeys,
      treeHash,
    };
  }

  /**
   * Encrypt a CryptoKey's PKCS8 representation using the shared ECIES
   * primitive in `ecies.ts` (P-256 ECDH ephemeral + HKDF-SHA-256 +
   * AES-256-GCM). The output format is documented in `ecies.ts`.
   */
  private async _encryptNodeKey(
    keyToEncrypt: CryptoKey,
    recipientPublicKey: CryptoKey,
  ): Promise<Uint8Array> {
    const exportedKey = new Uint8Array(
      await crypto.subtle.exportKey('pkcs8', keyToEncrypt),
    );
    return eciesSeal(exportedKey, recipientPublicKey);
  }

  /**
   * Decrypt a node key encrypted via `_encryptNodeKey` / ECIES, and
   * re-import the result as a P-256 ECDH private key.
   */
  private async _decryptNodeKey(
    encryptedData: Uint8Array,
    recipientPrivateKey: CryptoKey,
  ): Promise<CryptoKey> {
    const plaintext = await eciesOpen(encryptedData, recipientPrivateKey);

    // Import as ECDH private key.
    return crypto.subtle.importKey(
      'pkcs8',
      toBuffer(plaintext),
      ECDH_ALGO,
      true,
      ['deriveBits'],
    );
  }

  /**
   * Resolve the public key of a subtree rooted at the given node index.
   * If the node has a public key, return it.
   * If the node is blank, search its children for a non-blank key.
   */
  private async _resolvePublicKey(
    nodeIndex: number,
  ): Promise<CryptoKey | null> {
    const node = this._nodes.get(nodeIndex);
    if (node?.publicKey) return node.publicKey;

    // For internal nodes, try children
    if (TreeMath.isInternal(nodeIndex)) {
      const leftChild = TreeMath.left(nodeIndex);
      const rightChild = TreeMath.right(nodeIndex, this._numLeaves);

      const leftKey = await this._resolvePublicKey(leftChild);
      if (leftKey) return leftKey;

      const rightKey = await this._resolvePublicKey(rightChild);
      if (rightKey) return rightKey;
    }

    return null;
  }

  /**
   * Find a private key in our subtree by walking down from a given node.
   * Returns the private key if found, null otherwise.
   */
  private async _resolveSubtreeKey(
    nodeIndex: number,
  ): Promise<CryptoKey | null> {
    const node = this._nodes.get(nodeIndex);
    if (node?.privateKey) return node.privateKey;

    if (TreeMath.isInternal(nodeIndex)) {
      const leftChild = TreeMath.left(nodeIndex);
      const rightChild = TreeMath.right(nodeIndex, this._numLeaves);

      const leftKey = await this._resolveSubtreeKey(leftChild);
      if (leftKey) return leftKey;

      const rightKey = await this._resolveSubtreeKey(rightChild);
      if (rightKey) return rightKey;
    }

    return null;
  }

  /**
   * Find which child of a given node is on our side of the tree
   * (i.e., in the subtree that contains our leaf).
   */
  private _findChildOnOurSide(nodeIndex: number): number | undefined {
    if (TreeMath.isLeaf(nodeIndex)) return undefined;

    const leftChild = TreeMath.left(nodeIndex);
    const rightChild = TreeMath.right(nodeIndex, this._numLeaves);

    // Check which subtree contains our leaf
    if (this._isInSubtree(this._myLeafIndex, leftChild)) return leftChild;
    if (this._isInSubtree(this._myLeafIndex, rightChild)) return rightChild;

    return undefined;
  }

  /**
   * Check if a leaf index is within the subtree rooted at the given node.
   */
  private _isInSubtree(leafIndex: number, subtreeRoot: number): boolean {
    if (subtreeRoot === leafIndex) return true;

    if (TreeMath.isLeaf(subtreeRoot)) return false;

    const k = TreeMath.level(subtreeRoot);
    const halfSpan = 1 << k;
    const lo = subtreeRoot - halfSpan + 1;
    const hi = subtreeRoot + halfSpan - 1;

    return leafIndex >= lo && leafIndex <= hi;
  }

  /**
   * Compute a deterministic SHA-256 hash over all tree node public keys.
   * Format: for each non-null node, concatenate (nodeIndex as 4-byte BE || raw public key).
   * Nodes are iterated in index order for determinism.
   */
  private async _computeTreeHash(): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];

    // Collect all node indices and sort for deterministic ordering
    const sortedIndices = [...this._nodes.keys()].sort((a, b) => a - b);

    for (const nodeIndex of sortedIndices) {
      const node = this._nodes.get(nodeIndex);
      if (node?.publicKey) {
        // 4-byte big-endian node index
        const indexBytes = new Uint8Array(4);
        new DataView(indexBytes.buffer).setUint32(0, nodeIndex, false);
        parts.push(indexBytes);

        const exported = new Uint8Array(
          await crypto.subtle.exportKey('raw', node.publicKey),
        );
        parts.push(exported);
      }
    }

    // Concatenate all parts
    const totalLen = parts.reduce((sum, p) => sum + p.byteLength, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const part of parts) {
      combined.set(part, offset);
      offset += part.byteLength;
    }

    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }
}
