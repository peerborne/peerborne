import {
  TreeNode,
  LeafNode,
  InternalNode,
  PathUpdateV2,
  WelcomePathKey,
  PathNodeUpdateV2,
  BeeKEMWelcomeV2,
  MAX_BEEKEM_TREE_LEAVES,
  WelcomeNodePublicKey,
} from './types.js';
import * as TreeMath from './tree-math.js';
import {
  eciesSeal,
  eciesOpen,
  ECIES_P256_PUBLIC_KEY_LENGTH,
} from '../ecies.js';
import {
  snapshotDeepEnumerableData,
  copyUnsharedUint8Array,
} from '../utils.js';
import type { DeepDataSnapshotLimits } from '../utils.js';

/** ECDH curve used for tree key pairs. */
const isArrayBufferView = ArrayBuffer.isView;
const ECDH_CURVE = 'P-256';
const ECDH_ALGO = { name: 'ECDH', namedCurve: ECDH_CURVE };
const PATH_KEY_BUNDLE_MAGIC = new Uint8Array([0x53, 0x42, 0x4b, 0x42]);
const PATH_KEY_BUNDLE_VERSION = 1;
const MAX_PATH_KEYS = 64;
const MAX_PRIVATE_KEY_BYTES = 4096;
const BEEKEM_RUNTIME_INPUT_SNAPSHOT_LIMITS: DeepDataSnapshotLimits =
  Object.freeze({
    // The deepest supported shape is root -> path nodes -> bundle array ->
    // bundle -> ciphertext. Keep a little headroom without admitting an
    // attacker-controlled recursively nested graph.
    maxDepth: 8,
    // A maximum-width valid update contains the full public tree plus at most
    // one disjoint copath resolution across all path nodes. Count records,
    // arrays, and detached byte views with headroom above that legal shape.
    maxObjects: 12 * MAX_BEEKEM_TREE_LEAVES,
    maxProperties: 24 * MAX_BEEKEM_TREE_LEAVES,
    maxArrayLength: 2 * MAX_BEEKEM_TREE_LEAVES - 1,
    // Match the strict PathUpdate v2 wire decoder's aggregate byte budget.
    maxValueBytes: 8 * 1024 * 1024,
  });
const TREE_HASH_V2_DOMAIN = asciiBytes('peerborne:beekem:tree-hash:v2');
const SINGLE_MEMBER_ROOT_V2_DOMAIN = asciiBytes(
  'peerborne:beekem:single-member-root:v2',
);

function asciiBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit > 0x7f) {
      throw new TypeError('BeeKEM domain separators must be ASCII');
    }
    bytes[index] = codeUnit;
  }
  return bytes;
}

interface PrivatePathKey {
  nodeIndex: number;
  privateKey: CryptoKey;
}

/** Cast Uint8Array to ArrayBuffer for WebCrypto API compatibility. */
function toBuffer(data: Uint8Array): ArrayBuffer {
  return (data.buffer as ArrayBuffer).slice(
    data.byteOffset,
    data.byteOffset + data.byteLength,
  );
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < left.byteLength; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference === 0;
}

function bytesFingerprint(bytes: Uint8Array): string {
  let fingerprint = '';
  for (let index = 0; index < bytes.byteLength; index++) {
    fingerprint += bytes[index].toString(16).padStart(2, '0');
  }
  return fingerprint;
}

function snapshotBeeKEMRuntimeInput<T extends object>(
  value: T,
  field: string,
): T {
  const snapshot = snapshotDeepEnumerableData(
    value,
    field,
    BEEKEM_RUNTIME_INPUT_SNAPSHOT_LIMITS,
  );
  if (
    snapshot === null ||
    typeof snapshot !== 'object' ||
    Array.isArray(snapshot)
  ) {
    throw new TypeError(`${field} must be a plain object`);
  }
  return snapshot;
}

/**
 * BeeKEM: Binary ratchet tree for decentralized group key agreement.
 *
 * Based on Ink & Switch's Keyhive specification.
 * Tree paths are logarithmic. V2 updates additionally carry a linear public
 * snapshot and an exact parent commitment; every transition must be applied in
 * order, or the member must recover from persisted current ratchet state or a
 * fresh authenticated Welcome/remove-rejoin. An ordinary encrypted document
 * load cannot reconstruct private tree state.
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
  private _generation: number | null = null;
  private _lastAppliedV2UpdateDigest: Uint8Array | null = null;
  private _transitionTail: Promise<void> = Promise.resolve();
  private _pendingTransitionCount = 0;

  /** Copy stable tree state for a document membership transaction. */
  clone(): BeeKEM {
    if (this._pendingTransitionCount !== 0) {
      throw new Error('Cannot clone BeeKEM during a pending transition');
    }
    return this._copyState();
  }

  private _copyState(): BeeKEM {
    const state = this._snapshotState();
    const copy = new BeeKEM();
    copy._nodes = state.nodes;
    copy._numLeaves = state.numLeaves;
    copy._myLeafIndex = state.myLeafIndex;
    copy._generation = state.generation;
    copy._lastAppliedV2UpdateDigest = state.lastAppliedV2UpdateDigest;
    return copy;
  }

  /**
   * Initialize as the first member of a new group.
   * Creates a single-leaf tree with the creator's key pair.
   */
  async initialize(privateKey: CryptoKey, publicKey: CryptoKey): Promise<void> {
    return this._runTransition(async (staged) => {
      if (!(await staged._privateKeyMatchesPublicKey(privateKey, publicKey))) {
        throw new Error('BeeKEM founder private key does not match public key');
      }
      staged._nodes.clear();
      staged._numLeaves = 1;
      staged._myLeafIndex = 0;
      staged._generation = 0;
      staged._lastAppliedV2UpdateDigest = null;

      const leaf: LeafNode = {
        type: 'leaf',
        index: 0,
        publicKey,
        privateKey,
      };
      staged._nodes.set(0, leaf);
    });
  }

  /**
   * Add a new member to the group.
   * Creates a new leaf and derives keys along the path to root.
   * Returns a path update message to broadcast and a welcome for the new member.
   */
  async addMember(memberPublicKey: CryptoKey): Promise<{
    pathUpdate: PathUpdateV2;
    welcome: BeeKEMWelcomeV2;
    rootSecret: Uint8Array;
  }> {
    return this.addMemberTransactionally(
      memberPublicKey,
      async (result) => result,
    );
  }

  /**
   * Add a member and run a caller-supplied commit inside the same tree
   * transaction. If the commit rejects, every BeeKEM mutation is restored.
   */
  async addMemberTransactionally<T>(
    memberPublicKey: CryptoKey,
    commit: (result: {
      pathUpdate: PathUpdateV2;
      welcome: BeeKEMWelcomeV2;
      rootSecret: Uint8Array;
    }) => Promise<T>,
  ): Promise<T> {
    return this._runTransition(async (staged) => {
      if (staged._numLeaves >= MAX_BEEKEM_TREE_LEAVES) {
        throw new Error(
          `BeeKEM tree lifetime leaf limit of ${MAX_BEEKEM_TREE_LEAVES} reached`,
        );
      }
      if (await staged.hasLiveLeafWithPublicKey(memberPublicKey)) {
        throw new Error(
          'Cannot add member: KEM public key already belongs to a live BeeKEM leaf',
        );
      }
      const parentTreeHash = await staged._computeTreeHashV2(
        staged._nodes,
        staged._numLeaves,
      );
      // Add new leaf at next position
      const newLeafPos = staged._numLeaves;
      const newLeafIndex = TreeMath.leafToNodeIndex(newLeafPos);
      staged._numLeaves++;

      const newLeaf: LeafNode = {
        type: 'leaf',
        index: newLeafIndex,
        publicKey: memberPublicKey,
      };
      staged._nodes.set(newLeafIndex, newLeaf);

      // Appending a leaf can place it below an internal node that already has
      // a public key, while the committer (outside that subtree) does not hold
      // the matching private key. Leaving that node non-blank would make the
      // Welcome unable to transfer its private key to the new member. Future
      // updates would then encrypt once to that subtree node even though the
      // newcomer cannot decrypt it. Blank only those inaccessible join-path
      // nodes; the next snapshot's resolution expands them to descendant keys,
      // preserving access for every survivor and the new leaf.
      const committerPath = new Set(
        TreeMath.directPath(staged._myLeafIndex, staged._numLeaves),
      );
      for (const nodeIndex of TreeMath.directPath(
        newLeafIndex,
        staged._numLeaves,
      )) {
        if (committerPath.has(nodeIndex)) continue;
        const node = staged._nodes.get(nodeIndex);
        if (node?.publicKey && !node.privateKey) {
          staged._nodes.set(nodeIndex, {
            type: 'internal',
            index: nodeIndex,
            publicKey: null,
          });
        }
      }

      // Generate fresh key material along our path to root
      const { pathUpdate, rootSecret } =
        await staged._updatePath(parentTreeHash);

      // Build welcome message for the new member
      const welcome = await staged._buildWelcome(newLeafIndex, memberPublicKey);
      staged._validateWelcomeV2(welcome);

      return commit({ pathUpdate, welcome, rootSecret });
    });
  }

  /**
   * Remove a member from the group.
   * Blanks the member's leaf and all nodes on their direct path.
   * Returns a path update with fresh key material.
   */
  async removeMember(memberLeafIndex: number): Promise<{
    pathUpdate: PathUpdateV2;
    rootSecret: Uint8Array;
  }> {
    return this.removeMemberTransactionally(
      memberLeafIndex,
      async (result) => result,
    );
  }

  /**
   * Remove a member and run a caller-supplied commit inside the same tree
   * transaction. If the commit rejects, every BeeKEM mutation is restored.
   */
  async removeMemberTransactionally<T>(
    memberLeafIndex: number,
    commit: (result: {
      pathUpdate: PathUpdateV2;
      rootSecret: Uint8Array;
    }) => Promise<T>,
  ): Promise<T> {
    return this._runTransition(async (staged) => {
      const treeWidth = 2 * staged._numLeaves - 1;
      if (
        !Number.isSafeInteger(memberLeafIndex) ||
        memberLeafIndex < 0 ||
        memberLeafIndex >= treeWidth ||
        !TreeMath.isLeaf(memberLeafIndex)
      ) {
        throw new Error('Cannot remove member: invalid leaf index');
      }
      if (memberLeafIndex === staged._myLeafIndex) {
        throw new Error('Cannot remove the local BeeKEM member');
      }
      const memberLeaf = staged._nodes.get(memberLeafIndex);
      if (!memberLeaf || memberLeaf.type !== 'leaf' || !memberLeaf.publicKey) {
        throw new Error(
          'Cannot remove member: leaf is missing or already blank',
        );
      }
      const parentTreeHash = await staged._computeTreeHashV2(
        staged._nodes,
        staged._numLeaves,
      );
      // Blank the removed member's leaf
      const blankedLeaf: LeafNode = {
        type: 'leaf',
        index: memberLeafIndex,
        publicKey: null,
      };
      staged._nodes.set(memberLeafIndex, blankedLeaf);

      // Blank all internal nodes on the removed member's direct path
      const removedPath = TreeMath.directPath(
        memberLeafIndex,
        staged._numLeaves,
      );
      for (const nodeIndex of removedPath) {
        const blankedNode: InternalNode = {
          type: 'internal',
          index: nodeIndex,
          publicKey: null,
        };
        staged._nodes.set(nodeIndex, blankedNode);
      }

      // Generate fresh key pair for our leaf
      const newKeyPair = await crypto.subtle.generateKey(ECDH_ALGO, true, [
        'deriveBits',
      ]);
      const myLeaf: LeafNode = {
        type: 'leaf',
        index: staged._myLeafIndex,
        publicKey: newKeyPair.publicKey,
        privateKey: newKeyPair.privateKey,
      };
      staged._nodes.set(staged._myLeafIndex, myLeaf);

      // Re-derive path keys from our leaf to root
      return commit(await staged._updatePath(parentTreeHash));
    });
  }

  /**
   * Perform a self-update that rotates key material along our path.
   * This operation alone does not establish post-compromise security, secret
   * erasure, or recovery after a compromise.
   */
  async update(): Promise<{
    pathUpdate: PathUpdateV2;
    rootSecret: Uint8Array;
  }> {
    return this._runTransition(async (staged) => {
      const parentTreeHash = await staged._computeTreeHashV2(
        staged._nodes,
        staged._numLeaves,
      );
      // Generate new ECDH key pair for our leaf
      const newKeyPair = await crypto.subtle.generateKey(ECDH_ALGO, true, [
        'deriveBits',
      ]);
      const myLeaf: LeafNode = {
        type: 'leaf',
        index: staged._myLeafIndex,
        publicKey: newKeyPair.publicKey,
        privateKey: newKeyPair.privateKey,
      };
      staged._nodes.set(staged._myLeafIndex, myLeaf);

      // Re-derive all internal node keys on our path to root
      return staged._updatePath(parentTreeHash);
    });
  }

  /**
   * Process a path update from another member.
   * Decrypts the relevant encrypted key and derives the new root.
   */
  async processPathUpdate(update: PathUpdateV2): Promise<Uint8Array> {
    return this.processPathUpdateTransactionally(
      update,
      async (rootSecret) => rootSecret,
    );
  }

  /**
   * Apply an update and a caller-supplied commit as one BeeKEM transaction.
   * If validation, epoch binding, or durable key installation fails in the
   * callback, the ratchet state is restored to its exact prior snapshot.
   * The callback receives `duplicate` for an exact v2 replay so callers can
   * validate its epoch binding without appending the same durable key again.
   *
   * @internal Used by the document wire handler to couple tree advancement
   * with installation of the document key derived from the new root.
   */
  async processPathUpdateTransactionally<T>(
    update: PathUpdateV2,
    commit: (
      rootSecret: Uint8Array,
      disposition: 'applied' | 'duplicate',
    ) => Promise<T>,
  ): Promise<T> {
    let stableUpdate: PathUpdateV2;
    return this._runTransition(
      async (staged) => {
        const result = await staged._processPathUpdateV2(stableUpdate);
        return commit(result.rootSecret, result.disposition);
      },
      () => {
        stableUpdate = snapshotBeeKEMRuntimeInput(update, 'BeeKEM PathUpdate');
      },
    );
  }

  private async _processPathUpdateV2(update: PathUpdateV2): Promise<{
    rootSecret: Uint8Array;
    disposition: 'applied' | 'duplicate';
  }> {
    this._validatePathUpdateV2(update);
    const updateDigest = await this._computePathUpdateDigest(update);

    if (update.senderLeafIndex === this._myLeafIndex) {
      throw new Error('Cannot process our own BeeKEM path update');
    }

    if (this._generation !== null) {
      if (update.generation < this._generation) {
        throw new Error(
          `Cannot process stale BeeKEM generation ${update.generation}; current generation is ${this._generation}`,
        );
      }
      if (update.generation === this._generation) {
        if (
          this._lastAppliedV2UpdateDigest &&
          bytesEqual(this._lastAppliedV2UpdateDigest, updateDigest)
        ) {
          return {
            rootSecret: await this.getRootSecret(),
            disposition: 'duplicate',
          };
        }
        throw new Error(
          `Conflicting BeeKEM update at generation ${update.generation}`,
        );
      }
    } else {
      throw new Error(
        'Cannot apply a v2 BeeKEM PathUpdate without generation-bearing parent state',
      );
    }

    if (update.generation !== this._generation + 1) {
      throw new Error(
        `Cannot skip BeeKEM generations: expected ${this._generation + 1}, got ${update.generation}`,
      );
    }
    if (
      update.numLeaves !== this._numLeaves &&
      update.numLeaves !== this._numLeaves + 1
    ) {
      throw new Error(
        `BeeKEM v2 update leaf count must remain ${this._numLeaves} or append exactly one leaf`,
      );
    }
    const currentTreeHash = await this._computeTreeHashV2(
      this._nodes,
      this._numLeaves,
    );
    if (!bytesEqual(currentTreeHash, update.parentTreeHash)) {
      throw new Error('BeeKEM v2 update parent tree hash mismatch');
    }
    await this._validatePathUpdateLeafTransition(update);

    const senderPath = TreeMath.directPath(
      update.senderLeafIndex,
      update.numLeaves,
    );
    if (
      senderPath.length !== update.nodes.length ||
      senderPath.some((nodeIndex, i) => nodeIndex !== update.nodes[i].nodeIndex)
    ) {
      throw new Error('Invalid BeeKEM v2 update path for sender and tree size');
    }

    const nextNodes = await this._importTreeSnapshot(
      update.treeNodePublicKeys,
      update.numLeaves,
    );
    const snapshotHash = await this._computeTreeHashV2(
      nextNodes,
      update.numLeaves,
    );
    if (!bytesEqual(snapshotHash, update.treeHash)) {
      throw new Error('BeeKEM v2 tree snapshot hash mismatch');
    }

    // Keep unchanged private state below the sender/local-path intersection.
    // The update only delivers fresh private keys from that intersection to
    // the root; discarding an unchanged lower direct-path key would make the
    // next update from the opposite subtree impossible to decrypt. Exact
    // public-key equality is the authorization boundary: changed and blanked
    // nodes deliberately retain no prior private material.
    for (const [nodeIndex, currentNode] of this._nodes) {
      if (!currentNode.publicKey || !currentNode.privateKey) continue;
      const snapshotNode = nextNodes.get(nodeIndex);
      if (
        !snapshotNode?.publicKey ||
        !(await this._publicKeysEqual(
          currentNode.publicKey,
          snapshotNode.publicKey,
        ))
      ) {
        continue;
      }
      nextNodes.set(nodeIndex, {
        ...snapshotNode,
        privateKey: currentNode.privateKey,
      });
    }

    const snapshotSender = nextNodes.get(update.senderLeafIndex);
    if (
      !snapshotSender?.publicKey ||
      !(await this._publicKeyEqualsBytes(
        snapshotSender.publicKey,
        update.senderLeafPublicKey,
      ))
    ) {
      throw new Error('BeeKEM v2 sender leaf does not match tree snapshot');
    }

    const senderCopath = TreeMath.copath(
      update.senderLeafIndex,
      update.numLeaves,
    );
    for (let i = 0; i < update.nodes.length; i++) {
      const updateNode = update.nodes[i];
      const snapshotNode = nextNodes.get(updateNode.nodeIndex);
      if (
        !snapshotNode?.publicKey ||
        !(await this._publicKeyEqualsBytes(
          snapshotNode.publicKey,
          updateNode.publicKey,
        ))
      ) {
        throw new Error(
          `BeeKEM v2 path node ${updateNode.nodeIndex} does not match tree snapshot`,
        );
      }

      const expectedRecipients = this._resolvePublicKeys(
        senderCopath[i],
        update.numLeaves,
        nextNodes,
      ).map((entry) => entry.nodeIndex);
      const actualRecipients = updateNode.encryptedPathKeyBundles.map(
        (bundle) => bundle.recipientNodeIndex,
      );
      if (
        expectedRecipients.length !== actualRecipients.length ||
        expectedRecipients.some(
          (nodeIndex) => !actualRecipients.includes(nodeIndex),
        )
      ) {
        throw new Error(
          `BeeKEM v2 path node ${updateNode.nodeIndex} has an invalid copath bundle set`,
        );
      }
    }

    const currentLeaf = this._nodes.get(this._myLeafIndex);
    const snapshotLeaf = nextNodes.get(this._myLeafIndex);
    if (!snapshotLeaf?.publicKey) {
      throw new Error('Cannot process BeeKEM update: local member was removed');
    }
    if (
      !currentLeaf?.publicKey ||
      !currentLeaf.privateKey ||
      !(await this._publicKeysEqual(
        currentLeaf.publicKey,
        snapshotLeaf.publicKey,
      ))
    ) {
      throw new Error(
        'Cannot process BeeKEM v2 update: local leaf key does not match snapshot',
      );
    }
    nextNodes.set(this._myLeafIndex, {
      type: 'leaf',
      index: this._myLeafIndex,
      publicKey: snapshotLeaf.publicKey,
      privateKey: currentLeaf.privateKey,
    });

    let authorizedBundleCount = 0;
    let recoveredPath: PrivatePathKey[] | null = null;
    for (let nodeOffset = 0; nodeOffset < update.nodes.length; nodeOffset++) {
      const pathNode = update.nodes[nodeOffset];
      for (const bundle of pathNode.encryptedPathKeyBundles) {
        const recipientNode = this._nodes.get(bundle.recipientNodeIndex);
        const snapshotRecipient = nextNodes.get(bundle.recipientNodeIndex);
        if (
          !recipientNode?.privateKey ||
          !recipientNode.publicKey ||
          !snapshotRecipient?.publicKey ||
          !(await this._publicKeysEqual(
            recipientNode.publicKey,
            snapshotRecipient.publicKey,
          ))
        ) {
          continue;
        }

        const privatePath = await this._decryptPathKeyBundle(
          bundle.ciphertext,
          recipientNode.privateKey,
          update.numLeaves,
          update.generation,
        );
        const expectedNodes = update.nodes.slice(nodeOffset);
        if (
          privatePath.length !== expectedNodes.length ||
          privatePath.some(
            (entry, i) => entry.nodeIndex !== expectedNodes[i].nodeIndex,
          )
        ) {
          throw new Error('BeeKEM v2 bundle path does not match update path');
        }
        authorizedBundleCount++;
        recoveredPath = privatePath;
      }
    }

    if (authorizedBundleCount !== 1 || recoveredPath === null) {
      throw new Error(
        `Cannot process BeeKEM v2 update: expected exactly one authorized bundle, got ${authorizedBundleCount}`,
      );
    }

    for (const entry of recoveredPath) {
      const node = nextNodes.get(entry.nodeIndex);
      if (
        !node?.publicKey ||
        !(await this._pathKeyPairMatches(entry.privateKey, node.publicKey))
      ) {
        throw new Error(
          `BeeKEM v2 private key does not match path node ${entry.nodeIndex}`,
        );
      }
      nextNodes.set(entry.nodeIndex, {
        ...node,
        privateKey: entry.privateKey,
      });
    }

    const rootSecret = await this._getRootSecret(update.numLeaves, nextNodes);
    this._nodes = nextNodes;
    this._numLeaves = update.numLeaves;
    this._generation = update.generation;
    this._lastAppliedV2UpdateDigest = updateDigest;
    return { rootSecret, disposition: 'applied' };
  }

  /**
   * Process a welcome message to join an existing group.
   */
  async processWelcome(
    welcome: BeeKEMWelcomeV2,
    privateKey: CryptoKey,
    publicKey: CryptoKey,
  ): Promise<Uint8Array> {
    let stableWelcome: BeeKEMWelcomeV2;
    return this._runTransition(
      async (staged) => {
        staged._validateWelcomeV2(stableWelcome);
        if (
          staged._generation !== null &&
          stableWelcome.generation <= staged._generation
        ) {
          throw new Error(
            'Cannot process non-increasing BeeKEM Welcome generation',
          );
        }
        if (
          !(await staged._privateKeyMatchesPublicKey(privateKey, publicKey))
        ) {
          throw new Error(
            'Welcome recipient private key does not match public key',
          );
        }
        staged._myLeafIndex = stableWelcome.leafIndex;

        staged._numLeaves = stableWelcome.numLeaves;
        staged._nodes = new Map();

        // Set up our leaf node
        const myLeaf: LeafNode = {
          type: 'leaf',
          index: stableWelcome.leafIndex,
          publicKey,
          privateKey,
        };
        staged._nodes.set(stableWelcome.leafIndex, myLeaf);

        // Decrypt path keys using our private key for the first one,
        // then derive the rest up the tree
        let currentPrivateKey = privateKey;

        for (const pathKey of stableWelcome.pathKeys) {
          const nodePublicKey = await crypto.subtle.importKey(
            'raw',
            toBuffer(pathKey.publicKey),
            ECDH_ALGO,
            true,
            [],
          );

          // Decrypt the private key for this node
          const nodePrivateKey = await staged._decryptNodeKey(
            pathKey.encryptedPrivateKey,
            currentPrivateKey,
          );
          if (
            !(await staged._pathKeyPairMatches(nodePrivateKey, nodePublicKey))
          ) {
            throw new Error(
              `Welcome decrypted private key does not match path node ${pathKey.nodeIndex}`,
            );
          }

          const node: InternalNode = {
            type: 'internal',
            index: pathKey.nodeIndex,
            publicKey: nodePublicKey,
            privateKey: nodePrivateKey,
          };
          staged._nodes.set(pathKey.nodeIndex, node);

          // Use this node's private key to decrypt the next level
          currentPrivateKey = nodePrivateKey;
        }

        // Install all tree node public keys so we have the full tree state
        for (const nodeEntry of stableWelcome.treeNodePublicKeys) {
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
              : {
                  type: 'internal',
                  index: nodeEntry.nodeIndex,
                  publicKey: pubKey,
                };
            staged._nodes.set(nodeEntry.nodeIndex, node);
          } else {
            const isLeaf = TreeMath.isLeaf(nodeEntry.nodeIndex);
            const node: TreeNode = isLeaf
              ? { type: 'leaf', index: nodeEntry.nodeIndex, publicKey: null }
              : {
                  type: 'internal',
                  index: nodeEntry.nodeIndex,
                  publicKey: null,
                };
            staged._nodes.set(nodeEntry.nodeIndex, node);
          }
        }

        const computedHash = await staged._computeTreeHashV2(
          staged._nodes,
          staged._numLeaves,
        );
        if (
          computedHash.byteLength !== stableWelcome.treeHash.byteLength ||
          !computedHash.every((b, i) => b === stableWelcome.treeHash[i])
        ) {
          throw new Error(
            'Welcome tree hash mismatch: reconstructed tree does not match sender state',
          );
        }

        staged._generation = stableWelcome.generation;
        staged._lastAppliedV2UpdateDigest = null;
        return staged.getRootSecret();
      },
      () => {
        stableWelcome = snapshotBeeKEMRuntimeInput(welcome, 'BeeKEM Welcome');
      },
    );
  }

  /**
   * Get the current root secret (shared by all members).
   * Hashes extractable root key material; a single-member tree with the
   * canonical non-extractable KEM key uses a domain-separated ECDH transcript.
   */
  async getRootSecret(): Promise<Uint8Array> {
    return this._getRootSecret(this._numLeaves, this._nodes);
  }

  private async _getRootSecret(
    numLeaves: number,
    nodes: Map<number, TreeNode>,
  ): Promise<Uint8Array> {
    if (numLeaves <= 0) {
      throw new Error('Tree is empty');
    }

    if (numLeaves === 1) {
      // Single member: root secret is derived from the leaf's key
      const leaf = nodes.get(0);
      if (!leaf?.privateKey || !leaf.publicKey) {
        throw new Error('No private key available for root secret derivation');
      }
      // Canonical KEM private keys are deliberately non-extractable. Prove
      // possession through ECDH with the matching leaf public key and hash a
      // domain-separated transcript; no private-key bytes leave WebCrypto.
      const publicKey = await crypto.subtle.exportKey('raw', leaf.publicKey);
      const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: leaf.publicKey },
        leaf.privateKey,
        256,
      );
      const publicKeyBytes = new Uint8Array(publicKey);
      const transcript = new Uint8Array(
        SINGLE_MEMBER_ROOT_V2_DOMAIN.byteLength +
          4 +
          publicKeyBytes.byteLength +
          sharedBits.byteLength,
      );
      let offset = 0;
      transcript.set(SINGLE_MEMBER_ROOT_V2_DOMAIN, offset);
      offset += SINGLE_MEMBER_ROOT_V2_DOMAIN.byteLength;
      new DataView(transcript.buffer).setUint32(
        offset,
        publicKeyBytes.byteLength,
        false,
      );
      offset += 4;
      transcript.set(publicKeyBytes, offset);
      offset += publicKeyBytes.byteLength;
      transcript.set(new Uint8Array(sharedBits), offset);
      try {
        return new Uint8Array(
          await crypto.subtle.digest('SHA-256', transcript),
        );
      } finally {
        new Uint8Array(sharedBits).fill(0);
        transcript.fill(0);
      }
    }

    const rootIndex = TreeMath.root(numLeaves);
    const rootNode = nodes.get(rootIndex);

    if (!rootNode?.privateKey) {
      throw new Error('Root secret not available: no private key at root node');
    }

    const exported = await crypto.subtle.exportKey(
      'pkcs8',
      rootNode.privateKey,
    );
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

  /** Monotonic generation, or null before initialization. */
  get generation(): number | null {
    return this._generation;
  }

  /**
   * Return true only when the tree contains exactly one live leaf and that
   * leaf is the local member. Blanked and missing leaf slots do not count.
   *
   * This is intentionally stricter than checking `memberCount === 1` because
   * removed members leave blanked positions behind. Callers use this as proof
   * that no remote member remains when identity-to-leaf caches are absent.
   */
  hasOnlyLocalLiveLeaf(): boolean {
    if (this._myLeafIndex < 0) return false;

    let foundLocalLeaf = false;
    for (let leafPos = 0; leafPos < this._numLeaves; leafPos++) {
      const nodeIndex = TreeMath.leafToNodeIndex(leafPos);
      const node = this._nodes.get(nodeIndex);
      if (!node || node.type !== 'leaf' || !node.publicKey) continue;
      if (nodeIndex !== this._myLeafIndex) return false;
      foundLocalLeaf = true;
    }
    return foundLocalLeaf;
  }

  /** Return whether any live leaf owns `publicKey`, including duplicates. */
  async hasLiveLeafWithPublicKey(
    publicKey: CryptoKey | Uint8Array,
  ): Promise<boolean> {
    return (await this._matchingLiveLeafIndices(publicKey, 1)).length > 0;
  }

  /**
   * Find the node index of the unique live leaf whose public key matches
   * `publicKey`, or `undefined` if no such leaf exists or the key appears in
   * more than one non-blanked leaf.
   *
   * Used by `PeerborneDocument` as the canonical source of truth for live
   * leaf-index lookup during reader revocation and writer promotion. The
   * writer's in-memory leaf-index cache can be missing, so role transitions
   * must be able to recover an unambiguous assignment from tree state alone.
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
    const matches = await this._matchingLiveLeafIndices(publicKey, 2);
    return matches.length === 1 ? matches[0] : undefined;
  }

  private async _matchingLiveLeafIndices(
    publicKey: CryptoKey | Uint8Array,
    maximumMatches: number,
  ): Promise<number[]> {
    // Snapshot caller-owned bytes before the first await so mutation during a
    // WebCrypto export cannot redirect the lookup to a different leaf.
    const target = copyUnsharedUint8Array(
      isArrayBufferView(publicKey)
        ? publicKey
        : new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)),
      ECIES_P256_PUBLIC_KEY_LENGTH,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      'BeeKEM public key lookup',
    );
    const matchingLeafIndices: number[] = [];
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
      if (match) {
        matchingLeafIndices.push(nodeIndex);
        if (matchingLeafIndices.length >= maximumMatches) break;
      }
    }
    return matchingLeafIndices;
  }

  /**
   * Remove blanked leaf nodes and their parent path nodes from the tree
   * when an entire subtree is blanked. This reclaims memory for nodes
   * that can never contribute to key derivation.
   */
  compact(): void {
    if (this._pendingTransitionCount !== 0) {
      throw new Error(
        'Cannot compact BeeKEM synchronously while a transition is active or queued; use compactAsync()',
      );
    }
    this._compactNow();
  }

  /** Queue compaction behind any active BeeKEM transition. */
  async compactAsync(): Promise<void> {
    return this._runTransition(async (staged) => staged._compactNow());
  }

  private _compactNow(): void {
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

  /** Reserve call order before inspecting input, then publish only a complete tree. */
  private async _runTransition<T>(
    operation: (staged: BeeKEM) => Promise<T>,
    captureInput?: () => void,
  ): Promise<T> {
    this._pendingTransitionCount++;
    const previous = this._transitionTail;
    let release: () => void = () => {};
    this._transitionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    let captureFailed = false;
    let captureError: unknown;
    try {
      captureInput?.();
    } catch (error) {
      captureFailed = true;
      captureError = error;
    }
    await previous;
    try {
      if (captureFailed) throw captureError;
      const staged = this._copyState();
      const result = await operation(staged);
      this._nodes = staged._nodes;
      this._numLeaves = staged._numLeaves;
      this._myLeafIndex = staged._myLeafIndex;
      this._generation = staged._generation;
      this._lastAppliedV2UpdateDigest = staged._lastAppliedV2UpdateDigest;
      return result;
    } finally {
      this._pendingTransitionCount--;
      release();
    }
  }

  private _snapshotState(): {
    nodes: Map<number, TreeNode>;
    numLeaves: number;
    myLeafIndex: number;
    generation: number | null;
    lastAppliedV2UpdateDigest: Uint8Array | null;
  } {
    const nodes = new Map<number, TreeNode>();
    for (const [index, node] of this._nodes) {
      nodes.set(
        index,
        node.type === 'internal'
          ? {
              ...node,
              ...(node.conflictKeys
                ? { conflictKeys: [...node.conflictKeys] }
                : {}),
            }
          : { ...node },
      );
    }
    return {
      nodes,
      numLeaves: this._numLeaves,
      myLeafIndex: this._myLeafIndex,
      generation: this._generation,
      lastAppliedV2UpdateDigest:
        this._lastAppliedV2UpdateDigest === null
          ? null
          : new Uint8Array(this._lastAppliedV2UpdateDigest),
    };
  }

  /**
   * Generate fresh key pairs along our direct path and encrypt each
   * to the corresponding sibling subtree's resolution key.
   */
  private async _updatePath(parentTreeHash: Uint8Array): Promise<{
    pathUpdate: PathUpdateV2;
    rootSecret: Uint8Array;
  }> {
    if (this._generation === null) {
      throw new Error('Cannot create a BeeKEM update before initialization');
    }
    if (this._generation >= 0xffffffff) {
      throw new Error('BeeKEM generation limit reached');
    }
    if (parentTreeHash.byteLength !== 32) {
      throw new Error('BeeKEM parent tree hash must be 32 bytes');
    }
    const nextGeneration = this._generation + 1;

    // Export our leaf public key for inclusion in the PathUpdate
    const myLeaf = this._nodes.get(this._myLeafIndex);
    if (!myLeaf?.publicKey) {
      throw new Error('Cannot update path: no public key at our leaf');
    }
    const senderLeafPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', myLeaf.publicKey),
    );

    const dp = TreeMath.directPath(this._myLeafIndex, this._numLeaves);
    const cp = TreeMath.copath(this._myLeafIndex, this._numLeaves);
    const nextNodes = new Map(this._nodes);
    const generatedPath: Array<{
      nodeIndex: number;
      keyPair: CryptoKeyPair;
      publicKey: Uint8Array;
    }> = [];

    for (const nodeIndex of dp) {
      const nodeKeyPair = await crypto.subtle.generateKey(ECDH_ALGO, true, [
        'deriveBits',
      ]);
      const exportedPublicKey = new Uint8Array(
        await crypto.subtle.exportKey('raw', nodeKeyPair.publicKey),
      );
      const internalNode: InternalNode = {
        type: 'internal',
        index: nodeIndex,
        publicKey: nodeKeyPair.publicKey,
        privateKey: nodeKeyPair.privateKey,
      };
      nextNodes.set(nodeIndex, internalNode);
      generatedPath.push({
        nodeIndex,
        keyPair: nodeKeyPair,
        publicKey: exportedPublicKey,
      });
    }

    const pathNodes: PathNodeUpdateV2[] = [];
    for (let i = 0; i < generatedPath.length; i++) {
      const generated = generatedPath[i];
      const resolution = this._resolvePublicKeys(
        cp[i],
        this._numLeaves,
        nextNodes,
      );
      const privatePath: PrivatePathKey[] = generatedPath
        .slice(i)
        .map((entry) => ({
          nodeIndex: entry.nodeIndex,
          privateKey: entry.keyPair.privateKey,
        }));
      const encryptedPathKeyBundles = await Promise.all(
        resolution.map(async (recipient) => ({
          recipientNodeIndex: recipient.nodeIndex,
          ciphertext: await this._encryptPathKeyBundle(
            privatePath,
            recipient.publicKey,
            this._numLeaves,
            nextGeneration,
          ),
        })),
      );

      pathNodes.push({
        nodeIndex: generated.nodeIndex,
        publicKey: generated.publicKey,
        encryptedPathKeyBundles,
      });
    }

    const rootSecret = await this._getRootSecret(this._numLeaves, nextNodes);
    const treeNodePublicKeys =
      await this._buildTreePublicKeySnapshot(nextNodes);
    const treeHash = await this._computeTreeHashV2(nextNodes, this._numLeaves);
    const pathUpdate: PathUpdateV2 = {
      version: 2,
      generation: nextGeneration,
      parentTreeHash: new Uint8Array(parentTreeHash),
      numLeaves: this._numLeaves,
      senderLeafIndex: this._myLeafIndex,
      senderLeafPublicKey,
      nodes: pathNodes,
      treeNodePublicKeys,
      treeHash,
    };

    this._nodes = nextNodes;
    this._generation = nextGeneration;
    this._lastAppliedV2UpdateDigest = null;
    return { pathUpdate, rootSecret };
  }

  /**
   * Build a welcome message for a new member at the given leaf index.
   * Encrypts path keys so the new member can derive the root secret.
   */
  private async _buildWelcome(
    newLeafIndex: number,
    newMemberPublicKey: CryptoKey,
  ): Promise<BeeKEMWelcomeV2> {
    const dp = TreeMath.directPath(newLeafIndex, this._numLeaves);
    const pathKeys: WelcomePathKey[] = [];

    // Encrypt available direct-path keys as a chain. A left-balanced append
    // can introduce a blank intermediate parent outside the committer's path;
    // the next available ancestor is sealed directly to the last usable key.
    let encryptionKey: CryptoKey = newMemberPublicKey;

    for (const nodeIndex of dp) {
      const node = this._nodes.get(nodeIndex);
      if (!node?.publicKey || !node.privateKey) {
        continue;
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

    const rootIndex = TreeMath.root(this._numLeaves);
    if (pathKeys.at(-1)?.nodeIndex !== rootIndex) {
      throw new Error(`Cannot build welcome: missing key at root ${rootIndex}`);
    }

    // Collect public keys for all tree nodes NOT already covered by pathKeys
    // or the new member's own leaf. This allows the joiner to reconstruct the
    // full tree state for hash verification and future path updates.
    const pathKeyIndices = new Set(
      pathKeys.map((pathKey) => pathKey.nodeIndex),
    );
    const treeNodePublicKeys: WelcomeNodePublicKey[] = [];
    const treeWidth = 2 * this._numLeaves - 1;
    for (let nodeIndex = 0; nodeIndex < treeWidth; nodeIndex++) {
      if (nodeIndex === newLeafIndex) continue; // skip new member's own leaf
      if (pathKeyIndices.has(nodeIndex)) continue; // already in pathKeys
      const node = this._nodes.get(nodeIndex);
      if (node?.publicKey) {
        const exported = new Uint8Array(
          await crypto.subtle.exportKey('raw', node.publicKey),
        );
        treeNodePublicKeys.push({ nodeIndex, publicKey: exported });
      } else {
        treeNodePublicKeys.push({ nodeIndex, publicKey: null });
      }
    }

    // Tree hash for verification
    const treeHash = await this._computeTreeHashV2(
      this._nodes,
      this._numLeaves,
    );

    if (this._generation === null) {
      throw new Error('Cannot build a BeeKEM Welcome before initialization');
    }
    return {
      version: 2,
      numLeaves: this._numLeaves,
      leafIndex: newLeafIndex,
      pathKeys,
      treeNodePublicKeys,
      treeHash,
      generation: this._generation,
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

  private async _encryptPathKeyBundle(
    path: PrivatePathKey[],
    recipientPublicKey: CryptoKey,
    numLeaves: number,
    generation: number,
  ): Promise<Uint8Array> {
    if (path.length === 0 || path.length > MAX_PATH_KEYS) {
      throw new Error('BeeKEM path-key bundle has an invalid key count');
    }
    const exported = await Promise.all(
      path.map(async (entry) => ({
        nodeIndex: entry.nodeIndex,
        privateKey: new Uint8Array(
          await crypto.subtle.exportKey('pkcs8', entry.privateKey),
        ),
      })),
    );
    for (const entry of exported) {
      if (
        entry.privateKey.byteLength === 0 ||
        entry.privateKey.byteLength > MAX_PRIVATE_KEY_BYTES
      ) {
        throw new Error('BeeKEM path-key bundle private key has invalid size');
      }
    }

    const headerLength = 15;
    const byteLength =
      headerLength +
      exported.reduce((sum, entry) => sum + 8 + entry.privateKey.byteLength, 0);
    const plaintext = new Uint8Array(byteLength);
    plaintext.set(PATH_KEY_BUNDLE_MAGIC, 0);
    const view = new DataView(plaintext.buffer);
    view.setUint8(4, PATH_KEY_BUNDLE_VERSION);
    view.setUint32(5, numLeaves, false);
    view.setUint32(9, generation, false);
    view.setUint16(13, exported.length, false);
    let offset = headerLength;
    for (const entry of exported) {
      view.setUint32(offset, entry.nodeIndex, false);
      view.setUint32(offset + 4, entry.privateKey.byteLength, false);
      offset += 8;
      plaintext.set(entry.privateKey, offset);
      offset += entry.privateKey.byteLength;
    }
    return eciesSeal(plaintext, recipientPublicKey);
  }

  private async _decryptPathKeyBundle(
    ciphertext: Uint8Array,
    recipientPrivateKey: CryptoKey,
    expectedNumLeaves: number,
    expectedGeneration: number,
  ): Promise<PrivatePathKey[]> {
    const plaintext = await eciesOpen(ciphertext, recipientPrivateKey);
    if (plaintext.byteLength < 15) {
      throw new Error('Malformed BeeKEM path-key bundle: truncated header');
    }
    if (
      !PATH_KEY_BUNDLE_MAGIC.every((byte, i) => plaintext[i] === byte) ||
      plaintext[4] !== PATH_KEY_BUNDLE_VERSION
    ) {
      throw new Error('Malformed BeeKEM path-key bundle: invalid header');
    }
    const view = new DataView(
      plaintext.buffer,
      plaintext.byteOffset,
      plaintext.byteLength,
    );
    const numLeaves = view.getUint32(5, false);
    const generation = view.getUint32(9, false);
    if (numLeaves !== expectedNumLeaves || generation !== expectedGeneration) {
      throw new Error('Malformed BeeKEM path-key bundle: context mismatch');
    }
    const count = view.getUint16(13, false);
    if (count === 0 || count > MAX_PATH_KEYS) {
      throw new Error('Malformed BeeKEM path-key bundle: invalid key count');
    }

    const result: PrivatePathKey[] = [];
    const seen = new Set<number>();
    let offset = 15;
    for (let i = 0; i < count; i++) {
      if (offset + 8 > plaintext.byteLength) {
        throw new Error('Malformed BeeKEM path-key bundle: truncated entry');
      }
      const nodeIndex = view.getUint32(offset, false);
      const keyLength = view.getUint32(offset + 4, false);
      offset += 8;
      if (
        seen.has(nodeIndex) ||
        keyLength === 0 ||
        keyLength > MAX_PRIVATE_KEY_BYTES ||
        offset + keyLength > plaintext.byteLength
      ) {
        throw new Error('Malformed BeeKEM path-key bundle: invalid entry');
      }
      seen.add(nodeIndex);
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        toBuffer(plaintext.slice(offset, offset + keyLength)),
        ECDH_ALGO,
        true,
        ['deriveBits'],
      );
      result.push({ nodeIndex, privateKey });
      offset += keyLength;
    }
    if (offset !== plaintext.byteLength) {
      throw new Error('Malformed BeeKEM path-key bundle: trailing bytes');
    }
    return result;
  }

  private async _publicKeyEqualsBytes(
    publicKey: CryptoKey,
    raw: Uint8Array,
  ): Promise<boolean> {
    const exported = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    return bytesEqual(exported, raw);
  }

  private async _publicKeysEqual(
    left: CryptoKey,
    right: CryptoKey,
  ): Promise<boolean> {
    const [leftRaw, rightRaw] = await Promise.all([
      crypto.subtle.exportKey('raw', left),
      crypto.subtle.exportKey('raw', right),
    ]);
    return bytesEqual(new Uint8Array(leftRaw), new Uint8Array(rightRaw));
  }

  private async _pathKeyPairMatches(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
  ): Promise<boolean> {
    // ECDH agreement alone cannot distinguish a point from its negation.
    // Decrypted path keys are extractable so their exact public point can be checked.
    const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', privateKey);
    const advertised = await crypto.subtle.exportKey('jwk', publicKey);
    return (
      kty === 'EC' &&
      crv === ECDH_CURVE &&
      advertised.kty === kty &&
      advertised.crv === crv &&
      typeof x === 'string' &&
      typeof y === 'string' &&
      advertised.x === x &&
      advertised.y === y
    );
  }

  private async _privateKeyMatchesPublicKey(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
  ): Promise<boolean> {
    const challenge = (await crypto.subtle.generateKey(ECDH_ALGO, false, [
      'deriveBits',
    ])) as CryptoKeyPair;
    const privateSide = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'ECDH', public: challenge.publicKey },
        privateKey,
        256,
      ),
    );
    let publicSide: Uint8Array | undefined;
    try {
      publicSide = new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: 'ECDH', public: publicKey },
          challenge.privateKey,
          256,
        ),
      );
      return bytesEqual(privateSide, publicSide);
    } finally {
      privateSide.fill(0);
      publicSide?.fill(0);
    }
  }

  private _resolvePublicKeys(
    nodeIndex: number,
    numLeaves: number,
    nodes: Map<number, TreeNode>,
  ): Array<{ nodeIndex: number; publicKey: CryptoKey }> {
    const node = nodes.get(nodeIndex);
    if (node?.publicKey) {
      return [{ nodeIndex, publicKey: node.publicKey }];
    }
    if (!TreeMath.isInternal(nodeIndex)) return [];
    return [
      ...this._resolvePublicKeys(TreeMath.left(nodeIndex), numLeaves, nodes),
      ...this._resolvePublicKeys(
        TreeMath.right(nodeIndex, numLeaves),
        numLeaves,
        nodes,
      ),
    ];
  }

  private _validateWelcomeV2(welcome: BeeKEMWelcomeV2): void {
    if (
      welcome.version !== 2 ||
      !Number.isSafeInteger(welcome.generation) ||
      welcome.generation < 1 ||
      welcome.generation > 0xffffffff
    ) {
      throw new Error('Invalid BeeKEM Welcome v2 version or generation');
    }
    if (
      !Number.isSafeInteger(welcome.numLeaves) ||
      welcome.numLeaves < 2 ||
      welcome.numLeaves > MAX_BEEKEM_TREE_LEAVES
    ) {
      throw new Error('Invalid BeeKEM Welcome v2 numLeaves');
    }
    const treeWidth = 2 * welcome.numLeaves - 1;
    if (welcome.leafIndex !== TreeMath.leafToNodeIndex(welcome.numLeaves - 1)) {
      throw new Error('Invalid BeeKEM Welcome v2 leaf index');
    }
    if (
      welcome.pathKeys.length === 0 ||
      welcome.pathKeys.length > MAX_PATH_KEYS ||
      welcome.treeHash.byteLength !== 32
    ) {
      throw new Error('Invalid BeeKEM Welcome v2 path or tree hash size');
    }

    const directPath = TreeMath.directPath(
      welcome.leafIndex,
      welcome.numLeaves,
    );
    const directPathIndices = new Set(directPath);
    const covered = new Set<number>([welcome.leafIndex]);
    let previousPathOffset = -1;
    for (const pathKey of welcome.pathKeys) {
      const pathOffset = directPath.indexOf(pathKey.nodeIndex);
      if (
        pathOffset <= previousPathOffset ||
        pathKey.nodeIndex < 0 ||
        pathKey.nodeIndex >= treeWidth ||
        covered.has(pathKey.nodeIndex) ||
        pathKey.publicKey.byteLength !== 65 ||
        pathKey.encryptedPrivateKey.byteLength === 0 ||
        pathKey.encryptedPrivateKey.byteLength >
          MAX_PATH_KEYS * (MAX_PRIVATE_KEY_BYTES + 8) + MAX_PRIVATE_KEY_BYTES
      ) {
        throw new Error('Invalid BeeKEM Welcome v2 path key');
      }
      previousPathOffset = pathOffset;
      covered.add(pathKey.nodeIndex);
    }
    if (
      welcome.pathKeys.at(-1)?.nodeIndex !== TreeMath.root(welcome.numLeaves)
    ) {
      throw new Error('Invalid BeeKEM Welcome v2 root path key');
    }

    for (const node of welcome.treeNodePublicKeys) {
      if (
        !Number.isSafeInteger(node.nodeIndex) ||
        node.nodeIndex < 0 ||
        node.nodeIndex >= treeWidth ||
        covered.has(node.nodeIndex) ||
        (node.publicKey !== null && node.publicKey.byteLength !== 65)
      ) {
        throw new Error('Invalid BeeKEM Welcome v2 tree snapshot entry');
      }
      if (directPathIndices.has(node.nodeIndex) && node.publicKey !== null) {
        throw new Error(
          'Invalid BeeKEM Welcome v2: omitted direct-path nodes must be blank',
        );
      }
      covered.add(node.nodeIndex);
    }
    if (
      covered.size !== treeWidth ||
      Array.from({ length: treeWidth }, (_, index) => index).some(
        (index) => !covered.has(index),
      )
    ) {
      throw new Error('Incomplete BeeKEM Welcome v2 tree snapshot');
    }
  }

  private _validatePathUpdateV2(update: PathUpdateV2): void {
    if (update.version !== 2) {
      throw new Error('Invalid BeeKEM v2 update version');
    }
    if (
      !Number.isSafeInteger(update.generation) ||
      update.generation < 1 ||
      update.generation > 0xffffffff
    ) {
      throw new Error(
        'BeeKEM v2 generation must be an integer from 1 to 2^32-1',
      );
    }
    if (
      !Number.isSafeInteger(update.numLeaves) ||
      update.numLeaves < 1 ||
      update.numLeaves > MAX_BEEKEM_TREE_LEAVES
    ) {
      throw new Error(
        `BeeKEM v2 numLeaves must be an integer from 1 to ${MAX_BEEKEM_TREE_LEAVES}`,
      );
    }
    const treeWidth = 2 * update.numLeaves - 1;
    if (
      !Number.isSafeInteger(update.senderLeafIndex) ||
      update.senderLeafIndex < 0 ||
      update.senderLeafIndex >= treeWidth ||
      !TreeMath.isLeaf(update.senderLeafIndex)
    ) {
      throw new Error('BeeKEM v2 senderLeafIndex is invalid');
    }
    if (update.senderLeafPublicKey.byteLength !== 65) {
      throw new Error('BeeKEM v2 sender leaf public key must be 65 bytes');
    }
    if (update.nodes.length > MAX_PATH_KEYS) {
      throw new Error('BeeKEM v2 update has too many path nodes');
    }
    const nodeIndices = new Set<number>();
    for (const node of update.nodes) {
      if (
        !Number.isSafeInteger(node.nodeIndex) ||
        node.nodeIndex < 0 ||
        node.nodeIndex >= treeWidth ||
        !TreeMath.isInternal(node.nodeIndex) ||
        nodeIndices.has(node.nodeIndex)
      ) {
        throw new Error('BeeKEM v2 update has an invalid path node');
      }
      nodeIndices.add(node.nodeIndex);
      if (node.publicKey.byteLength !== 65) {
        throw new Error('BeeKEM v2 path public key must be 65 bytes');
      }
      if (node.encryptedPathKeyBundles.length > update.numLeaves) {
        throw new Error('BeeKEM v2 path node exceeds size bounds');
      }
      const recipients = new Set<number>();
      for (const bundle of node.encryptedPathKeyBundles) {
        if (
          !Number.isSafeInteger(bundle.recipientNodeIndex) ||
          bundle.recipientNodeIndex < 0 ||
          bundle.recipientNodeIndex >= treeWidth ||
          recipients.has(bundle.recipientNodeIndex) ||
          bundle.ciphertext.byteLength === 0 ||
          bundle.ciphertext.byteLength >
            MAX_PATH_KEYS * (MAX_PRIVATE_KEY_BYTES + 8) + MAX_PRIVATE_KEY_BYTES
        ) {
          throw new Error(
            'BeeKEM v2 update has an invalid or duplicate bundle',
          );
        }
        recipients.add(bundle.recipientNodeIndex);
      }
    }
    if (
      update.treeNodePublicKeys.length !== treeWidth ||
      update.treeHash.byteLength !== 32 ||
      update.parentTreeHash.byteLength !== 32
    ) {
      throw new Error('BeeKEM v2 update has an invalid tree snapshot size');
    }
    const snapshotIndices = new Set<number>();
    for (const entry of update.treeNodePublicKeys) {
      if (
        !Number.isSafeInteger(entry.nodeIndex) ||
        entry.nodeIndex < 0 ||
        entry.nodeIndex >= treeWidth ||
        snapshotIndices.has(entry.nodeIndex) ||
        (entry.publicKey !== null && entry.publicKey.byteLength !== 65)
      ) {
        throw new Error('BeeKEM v2 update has an invalid tree snapshot entry');
      }
      snapshotIndices.add(entry.nodeIndex);
    }
  }

  /** Enforce the append-only leaf transition emitted by local producers. */
  private async _validatePathUpdateLeafTransition(
    update: PathUpdateV2,
  ): Promise<void> {
    if (update.senderLeafIndex >= 2 * this._numLeaves) {
      throw new Error('BeeKEM v2 update sender must be a current live leaf');
    }
    const nextPublicKeys = new Map(
      update.treeNodePublicKeys.map((entry) => [
        entry.nodeIndex,
        entry.publicKey,
      ]),
    );
    const nextLiveLeafKeys = new Set<string>();
    for (
      let leafPosition = 0;
      leafPosition < update.numLeaves;
      leafPosition++
    ) {
      const publicKey = nextPublicKeys.get(
        TreeMath.leafToNodeIndex(leafPosition),
      );
      if (publicKey === null || publicKey === undefined) continue;
      const fingerprint = bytesFingerprint(publicKey);
      if (nextLiveLeafKeys.has(fingerprint)) {
        throw new Error(
          'BeeKEM v2 tree contains duplicate live leaf public keys',
        );
      }
      nextLiveLeafKeys.add(fingerprint);
    }
    let removedLeaves = 0;
    for (let leafPosition = 0; leafPosition < this._numLeaves; leafPosition++) {
      const nodeIndex = TreeMath.leafToNodeIndex(leafPosition);
      const currentPublicKey = this._nodes.get(nodeIndex)?.publicKey ?? null;
      const nextPublicKey = nextPublicKeys.get(nodeIndex) ?? null;
      if (currentPublicKey === null) {
        if (nextPublicKey !== null) {
          throw new Error(
            'BeeKEM v2 update cannot reactivate an append-only blank leaf',
          );
        }
        continue;
      }
      if (nodeIndex === update.senderLeafIndex) {
        if (nextPublicKey === null) {
          throw new Error('BeeKEM v2 update sender must remain live');
        }
        continue;
      }
      if (nextPublicKey === null) {
        removedLeaves++;
        continue;
      }
      if (
        !(await this._publicKeyEqualsBytes(currentPublicKey, nextPublicKey))
      ) {
        throw new Error(
          'BeeKEM v2 update cannot rewrite another live leaf public key',
        );
      }
    }

    if (update.numLeaves === this._numLeaves + 1) {
      const appendedLeafIndex = TreeMath.leafToNodeIndex(this._numLeaves);
      if (nextPublicKeys.get(appendedLeafIndex) === null) {
        throw new Error('BeeKEM v2 append must add one live rightmost leaf');
      }
      if (removedLeaves !== 0) {
        throw new Error('BeeKEM v2 append cannot remove an existing live leaf');
      }
    } else if (removedLeaves > 1) {
      throw new Error(
        'BeeKEM v2 same-size update cannot remove more than one live leaf',
      );
    }
  }

  private async _buildTreePublicKeySnapshot(
    nodes: Map<number, TreeNode>,
  ): Promise<WelcomeNodePublicKey[]> {
    const snapshot: WelcomeNodePublicKey[] = [];
    const treeWidth = 2 * this._numLeaves - 1;
    for (let nodeIndex = 0; nodeIndex < treeWidth; nodeIndex++) {
      const node = nodes.get(nodeIndex);
      snapshot.push({
        nodeIndex,
        publicKey: node?.publicKey
          ? new Uint8Array(await crypto.subtle.exportKey('raw', node.publicKey))
          : null,
      });
    }
    return snapshot;
  }

  private async _importTreeSnapshot(
    snapshot: WelcomeNodePublicKey[],
    numLeaves: number,
  ): Promise<Map<number, TreeNode>> {
    const treeWidth = 2 * numLeaves - 1;
    if (snapshot.length !== treeWidth) {
      throw new Error('BeeKEM v2 tree snapshot has the wrong width');
    }
    const nodes = new Map<number, TreeNode>();
    for (const entry of snapshot) {
      const publicKey =
        entry.publicKey === null
          ? null
          : await crypto.subtle.importKey(
              'raw',
              toBuffer(entry.publicKey),
              ECDH_ALGO,
              true,
              [],
            );
      nodes.set(
        entry.nodeIndex,
        TreeMath.isLeaf(entry.nodeIndex)
          ? { type: 'leaf', index: entry.nodeIndex, publicKey }
          : { type: 'internal', index: entry.nodeIndex, publicKey },
      );
    }
    return nodes;
  }

  private async _computePathUpdateDigest(
    update: PathUpdateV2,
  ): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    const addUint32 = (value: number) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value, false);
      parts.push(bytes);
    };
    const addBytes = (bytes: Uint8Array) => {
      addUint32(bytes.byteLength);
      parts.push(bytes);
    };

    addUint32(update.version);
    addUint32(update.generation);
    addBytes(update.parentTreeHash);
    addUint32(update.numLeaves);
    addUint32(update.senderLeafIndex);
    addBytes(update.senderLeafPublicKey);
    addUint32(update.nodes.length);
    for (const node of update.nodes) {
      addUint32(node.nodeIndex);
      addBytes(node.publicKey);
      addUint32(node.encryptedPathKeyBundles.length);
      for (const bundle of node.encryptedPathKeyBundles) {
        addUint32(bundle.recipientNodeIndex);
        addBytes(bundle.ciphertext);
      }
    }
    addUint32(update.treeNodePublicKeys.length);
    for (const entry of update.treeNodePublicKeys) {
      addUint32(entry.nodeIndex);
      if (entry.publicKey === null) {
        addUint32(0xffffffff);
      } else {
        addBytes(entry.publicKey);
      }
    }
    addBytes(update.treeHash);

    const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
    const input = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      input.set(part, offset);
      offset += part.byteLength;
    }
    return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  }

  /**
   * Commit to the exact v2 tree shape and every indexed public-key slot.
   *
   * Format:
   *   domain || numLeaves:u32 || treeWidth:u32 ||
   *   repeated(index:u32 || type:u8 || present:u8 || keyLength:u32 || key)
   */
  private async _computeTreeHashV2(
    nodes: Map<number, TreeNode>,
    numLeaves: number,
  ): Promise<Uint8Array> {
    const treeWidth = 2 * numLeaves - 1;
    const parts: Uint8Array[] = [TREE_HASH_V2_DOMAIN];
    const liveLeafPublicKeys = new Set<string>();
    const addUint32 = (value: number) => {
      const encoded = new Uint8Array(4);
      new DataView(encoded.buffer).setUint32(0, value, false);
      parts.push(encoded);
    };

    addUint32(numLeaves);
    addUint32(treeWidth);
    for (let nodeIndex = 0; nodeIndex < treeWidth; nodeIndex++) {
      const node = nodes.get(nodeIndex);
      addUint32(nodeIndex);
      parts.push(new Uint8Array([TreeMath.isLeaf(nodeIndex) ? 0 : 1]));

      if (!node?.publicKey) {
        parts.push(new Uint8Array([0]));
        addUint32(0);
        continue;
      }

      const publicKey = new Uint8Array(
        await crypto.subtle.exportKey('raw', node.publicKey),
      );
      if (TreeMath.isLeaf(nodeIndex)) {
        const fingerprint = bytesFingerprint(publicKey);
        if (liveLeafPublicKeys.has(fingerprint)) {
          throw new Error(
            'BeeKEM v2 tree contains duplicate live leaf public keys',
          );
        }
        liveLeafPublicKeys.add(fingerprint);
      }
      parts.push(new Uint8Array([1]));
      addUint32(publicKey.byteLength);
      parts.push(publicKey);
    }

    const totalLength = parts.reduce((sum, part) => sum + part.byteLength, 0);
    const input = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
      input.set(part, offset);
      offset += part.byteLength;
    }
    return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  }
}
