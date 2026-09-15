import {
  TreeNode,
  LeafNode,
  InternalNode,
  PathUpdate,
  PathNodeUpdate,
  BeeKEMWelcome,
  WelcomeNodePublicKey,
  MAX_BEEKEM_TREE_LEAVES,
} from './types.js';
import * as TreeMath from './tree-math.js';
import { eciesSeal, eciesOpen } from '../ecies.js';
import { snapshotBeeKEMWelcomeForProcessing } from '../beekem-welcome-wire.js';
import { snapshotDeepEnumerableData } from '../utils.js';
import {
  MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
  MAX_V1_PATH_NODES,
  MAX_V1_PATH_UPDATE_BYTES,
  MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
} from './path-update-limits.js';

/** ECDH curve used for tree key pairs. */
const ECDH_CURVE = 'P-256';
const ECDH_ALGO = { name: 'ECDH', namedCurve: ECDH_CURVE };
const V1_PATH_UPDATE_FORBIDDEN_FIELDS = [
  'version',
  'generation',
  'parentTreeHash',
  'numLeaves',
  'treeNodePublicKeys',
  'treeHash',
  'encryptedPathKeyBundles',
] as const;

/** Cast Uint8Array to ArrayBuffer for WebCrypto API compatibility. */
function toBuffer(data: Uint8Array): ArrayBuffer {
  return (data.buffer as ArrayBuffer).slice(
    data.byteOffset,
    data.byteOffset + data.byteLength,
  );
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let difference = a.byteLength ^ b.byteLength;
  const length = Math.max(a.byteLength, b.byteLength);
  for (let index = 0; index < length; index++) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

async function assertEcdhKeyPairCompatible(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  probe: CryptoKeyPair,
  label: string,
  context = 'Cannot process Welcome',
): Promise<void> {
  let privateSide: Uint8Array | undefined;
  let publicSide: Uint8Array | undefined;
  let coherent = false;
  try {
    privateSide = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'ECDH', public: probe.publicKey }, privateKey, 256,
    ));
    publicSide = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey }, probe.privateKey, 256,
    ));
    coherent = constantTimeEqual(privateSide, publicSide);
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : '';
    throw new Error(
      `${context}: ${label} ECDH compatibility check failed${detail}`,
      { cause: error },
    );
  } finally {
    privateSide?.fill(0);
    publicSide?.fill(0);
  }

  if (!coherent) {
    throw new Error(
      `${context}: ${label} public and private keys are not ECDH-compatible`,
    );
  }
}

async function assertExactWelcomePathKeyPair(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  nodeIndex: number,
): Promise<void> {
  // WebCrypto has no public-only projection for an imported private EC key.
  // Exact x/y comparison also rejects the negated point that ECDH alone accepts.
  // JWK export creates a GC-managed private-scalar string that cannot be wiped;
  // this primitive assumes a trusted process and never retains or logs the JWK.
  let publicJwk: JsonWebKey;
  let privateJwk: JsonWebKey;
  try {
    [publicJwk, privateJwk] = await Promise.all([
      crypto.subtle.exportKey('jwk', publicKey),
      crypto.subtle.exportKey('jwk', privateKey),
    ]);
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : '';
    throw new Error(
      `Cannot process Welcome: could not validate the key pair at path node ${nodeIndex}${detail}`,
      { cause: error },
    );
  }
  if (
    publicJwk.kty !== 'EC' ||
    privateJwk.kty !== 'EC' ||
    publicJwk.crv !== ECDH_CURVE ||
    privateJwk.crv !== ECDH_CURVE ||
    typeof publicJwk.x !== 'string' ||
    typeof publicJwk.y !== 'string' ||
    publicJwk.x !== privateJwk.x ||
    publicJwk.y !== privateJwk.y
  ) {
    throw new Error(
      `Cannot process Welcome: path node ${nodeIndex} public and private keys do not match`,
    );
  }
}

const WELCOME_SUPERSEDED_MESSAGE =
  'Cannot process Welcome: the attempt was superseded or receiver state changed';

async function assertMatchingPathKeyPair(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  nodeIndex: number,
): Promise<void> {
  let publicJwk: JsonWebKey;
  let privateJwk: JsonWebKey;
  try {
    [publicJwk, privateJwk] = await Promise.all([
      crypto.subtle.exportKey('jwk', publicKey),
      crypto.subtle.exportKey('jwk', privateKey),
    ]);
  } catch (error) {
    throw new Error(
      `Invalid PathUpdate: could not validate the key pair at node ${nodeIndex}`,
      { cause: error },
    );
  }
  if (
    publicJwk.kty !== 'EC' ||
    privateJwk.kty !== 'EC' ||
    publicJwk.crv !== ECDH_CURVE ||
    privateJwk.crv !== ECDH_CURVE ||
    typeof publicJwk.x !== 'string' ||
    typeof publicJwk.y !== 'string' ||
    publicJwk.x !== privateJwk.x ||
    publicJwk.y !== privateJwk.y
  ) {
    throw new Error(
      `Invalid PathUpdate: decrypted private key does not match the public key at node ${nodeIndex}`,
    );
  }
}

interface StagedWelcomeCandidate {
  receiverGeneration: bigint;
  nodes: Map<number, TreeNode>;
  numLeaves: number;
  leafIndex: number;
  rootSecret: Uint8Array;
  resolve: (rootSecret: Uint8Array) => void;
  reject: (error: Error) => void;
}

function requireExactDataFields(
  value: unknown,
  expectedFields: readonly string[],
  context: string,
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${context} must be a plain data object`);
  }
  const expected = new Set(expectedFields);
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string' || !expected.has(key)) {
      throw new Error(
        `${context} contains an unexpected ${
          typeof key === 'string' ? `field '${key}'` : 'symbol field'
        }`,
      );
    }
  }
  for (const field of expectedFields) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) {
      throw new Error(`${context} is missing field '${field}'`);
    }
  }
  return value as Record<string, unknown>;
}

function requireDetachedBytes(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  field: string,
): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < minimumLength ||
    value.byteLength > maximumLength
  ) {
    throw new Error(
      `Invalid PathUpdate: '${field}' must be a Uint8Array from ${minimumLength} to ${maximumLength} bytes`,
    );
  }
  return value;
}

function snapshotPathUpdate(update: PathUpdate): PathUpdate {
  let detached: unknown;
  try {
    detached = snapshotDeepEnumerableData(
      update,
      'PathUpdate',
      {
        maxDepth: 3,
        maxObjects: 64,
        maxProperties: 64,
        maxArrayLength: MAX_V1_PATH_NODES,
        maxValueBytes: MAX_V1_PATH_UPDATE_BYTES,
      },
      { forbiddenFields: V1_PATH_UPDATE_FORBIDDEN_FIELDS },
    );
  } catch (error) {
    throw new Error('Invalid PathUpdate: could not safely detach input', {
      cause: error,
    });
  }

  const raw = requireExactDataFields(
    detached,
    ['senderLeafIndex', 'senderLeafPublicKey', 'nodes'],
    'Invalid PathUpdate',
  );
  const maximumTreeWidth = 2 * MAX_BEEKEM_TREE_LEAVES - 1;
  if (
    typeof raw.senderLeafIndex !== 'number' ||
    !Number.isSafeInteger(raw.senderLeafIndex) ||
    raw.senderLeafIndex < 0 ||
    raw.senderLeafIndex >= maximumTreeWidth ||
    !TreeMath.isLeaf(raw.senderLeafIndex)
  ) {
    throw new Error(
      "Invalid PathUpdate: 'senderLeafIndex' must identify a bounded tree leaf",
    );
  }
  const senderLeafIndex = raw.senderLeafIndex;
  const senderLeafPublicKey = requireDetachedBytes(
    raw.senderLeafPublicKey,
    65,
    65,
    'senderLeafPublicKey',
  );
  if (!Array.isArray(raw.nodes)) {
    throw new Error("Invalid PathUpdate: 'nodes' must be an array");
  }

  const nodes: PathNodeUpdate[] = raw.nodes.map((value, index) => {
    const node = requireExactDataFields(
      value,
      ['nodeIndex', 'publicKey', 'encryptedPrivateKey'],
      `Invalid PathUpdate: node[${index}]`,
    );
    if (
      typeof node.nodeIndex !== 'number' ||
      !Number.isSafeInteger(node.nodeIndex) ||
      node.nodeIndex < 0 ||
      node.nodeIndex >= maximumTreeWidth ||
      TreeMath.isLeaf(node.nodeIndex)
    ) {
      throw new Error(
        `Invalid PathUpdate: 'node[${index}].nodeIndex' must identify a bounded internal tree node`,
      );
    }
    const encryptedPrivateKey = requireDetachedBytes(
      node.encryptedPrivateKey,
      0,
      MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES,
      `node[${index}].encryptedPrivateKey`,
    );
    if (
      encryptedPrivateKey.byteLength !== 0 &&
      encryptedPrivateKey.byteLength < MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES
    ) {
      throw new Error(
        `Invalid PathUpdate: 'node[${index}].encryptedPrivateKey' must be empty or ${MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES}..${MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES} bytes`,
      );
    }
    return {
      nodeIndex: node.nodeIndex,
      publicKey: requireDetachedBytes(
        node.publicKey,
        65,
        65,
        `node[${index}].publicKey`,
      ),
      encryptedPrivateKey,
    };
  });

  return { senderLeafIndex, senderLeafPublicKey, nodes };
}

function snapshotPathUpdateForTree(
  update: PathUpdate,
  numLeaves: number,
): PathUpdate {
  const detached = snapshotPathUpdate(update);
  const treeWidth = 2 * numLeaves - 1;
  if (detached.senderLeafIndex >= treeWidth) {
    throw new Error(
      "Invalid PathUpdate: 'senderLeafIndex' must identify a leaf in the current tree",
    );
  }

  const expectedPath = TreeMath.directPath(
    detached.senderLeafIndex,
    numLeaves,
  );
  if (
    detached.nodes.length !== expectedPath.length ||
    detached.nodes.some(
      (node, index) => node.nodeIndex !== expectedPath[index],
    )
  ) {
    throw new Error(
      'Invalid PathUpdate: nodes must exactly match the sender direct path',
    );
  }
  return detached;
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
  private _receiverGeneration = 0n;
  private _welcomeAttemptRevision = 0n;
  private _pendingWelcomeAttempts = new Set<bigint>();
  private _stagedWelcomeCandidates = new Map<bigint, StagedWelcomeCandidate>();
  private _welcomeSettlement: Promise<void> = Promise.resolve();
  private _resolveWelcomeSettlement: (() => void) | undefined;
  private _mutationTail: Promise<void> = Promise.resolve();
  private _pendingMutations = 0;
  private _pendingInitializations = 0;

  private _reserveMutation(): <T>(
    operation: () => Promise<T>,
  ) => Promise<T> {
    const previous = this._mutationTail;
    let release!: () => void;
    const turn = new Promise<void>((resolve) => {
      release = resolve;
    });
    this._mutationTail = turn;
    this._pendingMutations++;
    let consumed = false;
    return async <T>(operation: () => Promise<T>): Promise<T> => {
      if (consumed) {
        throw new Error('BeeKEM mutation reservation was already consumed');
      }
      consumed = true;
      await previous;
      try {
        return await operation();
      } finally {
        this._pendingMutations--;
        release();
      }
    };
  }

  private _runMutation<T>(operation: () => Promise<T>): Promise<T> {
    return this._reserveMutation()(operation);
  }

  private _cloneState(): BeeKEM {
    const copy = new BeeKEM();
    copy._nodes = new Map(this._nodes);
    copy._numLeaves = this._numLeaves;
    copy._myLeafIndex = this._myLeafIndex;
    return copy;
  }

  /** @internal Create a detached copy for validating before commit. */
  clone(): BeeKEM {
    if (this._pendingMutations !== 0) {
      throw new Error('Cannot clone BeeKEM during an active mutation');
    }
    return this._cloneState();
  }

  /**
   * Initialize as the first member of a new group.
   * Creates a single-leaf tree with the creator's key pair.
   */
  async initialize(privateKey: CryptoKey, publicKey: CryptoKey): Promise<void> {
    if (
      this._resolveWelcomeSettlement !== undefined &&
      this._pendingMutations !== 0
    ) {
      throw new Error(
        'Cannot initialize BeeKEM while a mutation is waiting for Welcome settlement',
      );
    }
    this._pendingInitializations++;
    try {
      await this._runMutation(() => this._initialize(privateKey, publicKey));
    } finally {
      this._pendingInitializations--;
      this._settleWelcomeCandidates();
    }
  }

  private async _initialize(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
  ): Promise<void> {
    let compatibilityProbe: CryptoKeyPair;
    try {
      compatibilityProbe = (await crypto.subtle.generateKey(
        ECDH_ALGO,
        false,
        ['deriveBits'],
      )) as CryptoKeyPair;
    } catch (error) {
      const detail = error instanceof Error ? `: ${error.message}` : '';
      throw new Error(
        `Cannot initialize BeeKEM: ECDH compatibility probe generation failed${detail}`,
        { cause: error },
      );
    }
    await assertEcdhKeyPairCompatible(
      publicKey,
      privateKey,
      compatibilityProbe,
      'founder leaf 0',
      'Cannot initialize BeeKEM',
    );
    this._receiverGeneration++;
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
    this._settleWelcomeCandidates();
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
    this._assertInitializedForMutation('add a member');
    return this._runMutation(() => this._addMember(memberPublicKey));
  }

  private async _addMember(memberPublicKey: CryptoKey): Promise<{
    pathUpdate: PathUpdate;
    welcome: BeeKEMWelcome;
    rootSecret: Uint8Array;
  }> {
    this._assertLocalMutationState('add member');
    if (this._numLeaves >= MAX_BEEKEM_TREE_LEAVES) {
      throw new Error(
        `Cannot add member: BeeKEM tree is limited to ${MAX_BEEKEM_TREE_LEAVES} leaves`,
      );
    }
    const staged = this._cloneState();
    const newLeafPos = staged._numLeaves;
    const newLeafIndex = TreeMath.leafToNodeIndex(newLeafPos);
    staged._numLeaves++;

    const newLeaf: LeafNode = {
      type: 'leaf',
      index: newLeafIndex,
      publicKey: memberPublicKey,
    };
    staged._nodes.set(newLeafIndex, newLeaf);

    const { pathUpdate, rootSecret } = await staged._updatePath();
    const welcome = await staged._buildWelcome(
      newLeafIndex,
      memberPublicKey,
    );

    this._nodes = staged._nodes;
    this._numLeaves = staged._numLeaves;
    this._myLeafIndex = staged._myLeafIndex;
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
    this._assertInitializedForMutation('remove a member');
    const treeWidth = 2 * this._numLeaves - 1;
    if (
      !Number.isSafeInteger(memberLeafIndex) ||
      memberLeafIndex < 0 ||
      Object.is(memberLeafIndex, -0) ||
      memberLeafIndex >= treeWidth ||
      !TreeMath.isLeaf(memberLeafIndex)
    ) {
      throw new Error('Cannot remove member: invalid leaf index');
    }
    return this._runMutation(() => this._removeMember(memberLeafIndex));
  }

  private async _removeMember(memberLeafIndex: number): Promise<{
    pathUpdate: PathUpdate;
    rootSecret: Uint8Array;
  }> {
    this._assertLocalMutationState('remove member');
    const treeWidth = 2 * this._numLeaves - 1;
    if (
      !Number.isSafeInteger(memberLeafIndex) ||
      memberLeafIndex < 0 ||
      memberLeafIndex >= treeWidth ||
      !TreeMath.isLeaf(memberLeafIndex)
    ) {
      throw new Error(
        'Cannot remove member: target must identify a leaf in the current tree',
      );
    }
    if (memberLeafIndex === this._myLeafIndex) {
      throw new Error('Cannot remove member: cannot remove the local member');
    }
    const memberLeaf = this._nodes.get(memberLeafIndex);
    if (
      memberLeaf?.type !== 'leaf' ||
      memberLeaf.index !== memberLeafIndex ||
      !memberLeaf.publicKey
    ) {
      throw new Error('Cannot remove member: target is not an active tree leaf');
    }

    const staged = this._cloneState();
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
    const result = await staged._updatePath();
    this._nodes = staged._nodes;
    return result;
  }

  /**
   * Perform a self-update for post-compromise security.
   * Generates fresh key material along our path.
   */
  async update(): Promise<{
    pathUpdate: PathUpdate;
    rootSecret: Uint8Array;
  }> {
    this._assertInitializedForMutation('update');
    return this._runMutation(() => this._update());
  }

  private async _update(): Promise<{
    pathUpdate: PathUpdate;
    rootSecret: Uint8Array;
  }> {
    this._assertLocalMutationState('update');
    const staged = this._cloneState();
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
    const result = await staged._updatePath();
    this._nodes = staged._nodes;
    return result;
  }

  /**
   * Process a path update from another member.
   * Requires an initialized tree at admission, detaches the update, validates
   * it against the tree when its reserved turn begins, and commits a staged
   * tree only on success.
   *
   * This is the legacy v1 shape. It has no generation or parent-tree binding,
   * so structural validation and FIFO application do not make captured valid
   * updates replay-safe. Callers must treat replay/out-of-order resistance as a
   * v2 requirement.
   */
  async processPathUpdate(update: PathUpdate): Promise<Uint8Array> {
    this._assertInitializedForMutation('process a PathUpdate');
    const welcomeSettlement = this._resolveWelcomeSettlement
      ? this._welcomeSettlement
      : undefined;
    const validateAgainstCurrentTree =
      this._pendingMutations === 0 && welcomeSettlement === undefined;
    const runReservedMutation = this._reserveMutation();
    try {
      let detachedUpdate: PathUpdate;
      if (validateAgainstCurrentTree) {
        this._assertPathUpdateState();
        detachedUpdate = snapshotPathUpdateForTree(
          update,
          this._numLeaves,
        );
      } else {
        detachedUpdate = snapshotPathUpdate(update);
      }
      return runReservedMutation(async () => {
        await welcomeSettlement;
        return this._processPathUpdate(detachedUpdate);
      });
    } catch (error) {
      return runReservedMutation(async () => {
        throw error;
      });
    }
  }

  private async _processPathUpdate(update: PathUpdate): Promise<Uint8Array> {
    this._assertPathUpdateState();
    const detachedUpdate = snapshotPathUpdateForTree(
      update,
      this._numLeaves,
    );
    const currentSenderLeaf = this._nodes.get(detachedUpdate.senderLeafIndex);
    if (
      currentSenderLeaf?.type !== 'leaf' ||
      currentSenderLeaf.publicKey === null
    ) {
      throw new Error(
        'Cannot process path update: sender is not an active tree leaf',
      );
    }
    const myDirectPath = TreeMath.directPath(
      this._myLeafIndex,
      this._numLeaves,
    );
    const firstIntersection = detachedUpdate.nodes.findIndex((node) =>
      myDirectPath.includes(node.nodeIndex),
    );
    if (
      firstIntersection >= 0 &&
      firstIntersection < detachedUpdate.nodes.length - 1
    ) {
      throw new Error(
        'Cannot process path update: legacy PathUpdate v1 cannot safely ' +
          'distribute ancestor keys above a non-root intersection',
      );
    }

    const staged = this._cloneState();
    // Update the sender's leaf with their new public key
    const senderLeafPublicKey = await crypto.subtle.importKey(
      'raw',
      toBuffer(detachedUpdate.senderLeafPublicKey),
      ECDH_ALGO,
      true,
      [],
    );
    const senderLeaf: LeafNode = {
      type: 'leaf',
      index: detachedUpdate.senderLeafIndex,
      publicKey: senderLeafPublicKey,
    };
    staged._nodes.set(detachedUpdate.senderLeafIndex, senderLeaf);

    if (firstIntersection === -1) {
      throw new Error(
        'Cannot process path update: no intersection found with our path',
      );
    }

    const intersectionNode = detachedUpdate.nodes[firstIntersection];
    const intersectionPublicKey = await crypto.subtle.importKey(
      'raw',
      toBuffer(intersectionNode.publicKey),
      ECDH_ALGO,
      true,
      [],
    );
    const childOnOurSide = staged._findChildOnOurSide(
      intersectionNode.nodeIndex,
    );
    const candidateKeys =
      childOnOurSide === undefined
        ? []
        : staged._privateKeyCandidates(childOnOurSide);
    let decryptedPrivateKey: CryptoKey | null = null;
    let lastDecryptionError: unknown;
    for (const candidateKey of candidateKeys) {
      let candidatePrivateKey: CryptoKey;
      try {
        candidatePrivateKey = await staged._decryptNodeKey(
          intersectionNode.encryptedPrivateKey,
          candidateKey,
        );
      } catch (error) {
        lastDecryptionError = error;
        continue;
      }
      await assertMatchingPathKeyPair(
        intersectionPublicKey,
        candidatePrivateKey,
        intersectionNode.nodeIndex,
      );
      decryptedPrivateKey = candidatePrivateKey;
      break;
    }
    if (!decryptedPrivateKey) {
      throw new Error(
        'Cannot process path update: no local resolution key could decrypt ' +
          'the intersection',
        { cause: lastDecryptionError },
      );
    }

    // Set the intersection node
    const intNode: InternalNode = {
      type: 'internal',
      index: intersectionNode.nodeIndex,
      publicKey: intersectionPublicKey,
      privateKey: decryptedPrivateKey,
    };
    staged._nodes.set(intersectionNode.nodeIndex, intNode);

    // Also update nodes below the intersection from the sender's side
    for (let i = 0; i < firstIntersection; i++) {
      const pathNode = detachedUpdate.nodes[i];
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
      staged._nodes.set(pathNode.nodeIndex, node);
    }

    const rootSecret = await staged.getRootSecret();
    this._nodes = staged._nodes;
    return rootSecret;
  }

  private _assertPathUpdateState(): void {
    if (
      !Number.isSafeInteger(this._numLeaves) ||
      this._numLeaves < 1 ||
      this._numLeaves > MAX_BEEKEM_TREE_LEAVES
    ) {
      throw new Error('Cannot process path update: BeeKEM tree state is invalid');
    }
    const treeWidth = 2 * this._numLeaves - 1;
    if (
      !Number.isSafeInteger(this._myLeafIndex) ||
      this._myLeafIndex < 0 ||
      this._myLeafIndex >= treeWidth ||
      !TreeMath.isLeaf(this._myLeafIndex)
    ) {
      throw new Error('Cannot process path update: local leaf is invalid');
    }
  }

  private _assertLocalMutationState(action: string): void {
    if (
      !Number.isSafeInteger(this._numLeaves) ||
      this._numLeaves < 1 ||
      this._numLeaves > MAX_BEEKEM_TREE_LEAVES
    ) {
      throw new Error(`Cannot ${action}: BeeKEM tree state is invalid`);
    }
    const treeWidth = 2 * this._numLeaves - 1;
    if (
      !Number.isSafeInteger(this._myLeafIndex) ||
      this._myLeafIndex < 0 ||
      this._myLeafIndex >= treeWidth ||
      !TreeMath.isLeaf(this._myLeafIndex)
    ) {
      throw new Error(`Cannot ${action}: local leaf is invalid`);
    }
    const localLeaf = this._nodes.get(this._myLeafIndex);
    if (
      localLeaf?.type !== 'leaf' ||
      localLeaf.index !== this._myLeafIndex ||
      !localLeaf.publicKey ||
      !localLeaf.privateKey
    ) {
      throw new Error(`Cannot ${action}: local leaf is not active`);
    }
  }

  /**
   * Process a welcome message to join an existing group.
   * Requires a fresh BeeKEM instance; replacement and re-invitation must use a
   * new instance so a replayed legacy Welcome cannot roll back live tree state.
   */
  async processWelcome(
    welcome: BeeKEMWelcome,
    privateKey: CryptoKey,
    publicKey: CryptoKey,
  ): Promise<Uint8Array> {
    if (!this._isFreshWelcomeTarget()) {
      throw new Error('Cannot process Welcome on a non-fresh BeeKEM tree');
    }
    // Reserve this attempt before inspecting caller-controlled input. A Proxy
    // descriptor trap can invoke processWelcome reentrantly; in that case the
    // nested, later invocation must retain the higher revision and win.
    this._beginWelcomeSettlement();
    const attemptRevision = ++this._welcomeAttemptRevision;
    const receiverGeneration = this._receiverGeneration;
    this._pendingWelcomeAttempts.add(attemptRevision);

    try {
      return await this._processWelcomeAttempt(
        attemptRevision,
        welcome,
        privateKey,
        publicKey,
        receiverGeneration,
      );
    } catch (error) {
      if (this._pendingWelcomeAttempts.delete(attemptRevision)) {
        this._settleWelcomeCandidates();
      }
      throw error;
    }
  }

  private async _processWelcomeAttempt(
    attemptRevision: bigint,
    welcome: BeeKEMWelcome,
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    receiverGeneration: bigint,
  ): Promise<Uint8Array> {
    // This public method can be called without passing through the strict wire
    // decoder. Snapshot and bound the complete legacy tree synchronously
    // before the first WebCrypto await so caller mutation cannot change what
    // is authenticated or installed while processing is in flight.
    const validated = snapshotBeeKEMWelcomeForProcessing(welcome);
    const staged = new BeeKEM();
    staged._myLeafIndex = validated.welcome.leafIndex;
    staged._numLeaves = validated.numLeaves;

    // Cross-derive through one ephemeral key pair to prove that the caller's
    // private key is compatible with its advertised ECDH public key. The
    // private key can remain non-extractable because validation only uses its
    // deriveBits capability. Decrypted path keys are extractable and are
    // compared exactly below.
    let coherenceProbe: CryptoKeyPair;
    try {
      coherenceProbe = (await crypto.subtle.generateKey(
        ECDH_ALGO,
        false,
        ['deriveBits'],
      )) as CryptoKeyPair;
    } catch (error) {
      const detail = error instanceof Error ? `: ${error.message}` : '';
      throw new Error(
        `Cannot process Welcome: key-pair coherence probe generation failed${detail}`,
        { cause: error },
      );
    }
    await assertEcdhKeyPairCompatible(
      publicKey,
      privateKey,
      coherenceProbe,
      `recipient leaf ${validated.welcome.leafIndex}`,
    );

    // Set up our leaf node
    const myLeaf: LeafNode = {
      type: 'leaf',
      index: validated.welcome.leafIndex,
      publicKey,
      privateKey,
    };
    staged._nodes.set(validated.welcome.leafIndex, myLeaf);

    // Decrypt path keys using our private key for the first one,
    // then derive the rest up the tree
    let currentPrivateKey = privateKey;

    for (const pathKey of validated.welcome.pathKeys) {
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
      await assertExactWelcomePathKeyPair(
        nodePublicKey,
        nodePrivateKey,
        pathKey.nodeIndex,
      );

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
    for (const nodeEntry of validated.welcome.treeNodePublicKeys) {
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
        staged._nodes.set(nodeEntry.nodeIndex, node);
      } else {
        const isLeaf = TreeMath.isLeaf(nodeEntry.nodeIndex);
        const node: TreeNode = isLeaf
          ? { type: 'leaf', index: nodeEntry.nodeIndex, publicKey: null }
          : { type: 'internal', index: nodeEntry.nodeIndex, publicKey: null };
        staged._nodes.set(nodeEntry.nodeIndex, node);
      }
    }

    // Verify tree hash matches the sender's snapshot
    const computedHash = await staged._computeTreeHash();
    if (
      computedHash.byteLength !== validated.welcome.treeHash.byteLength ||
      !constantTimeEqual(computedHash, validated.welcome.treeHash)
    ) {
      throw new Error(
        'Welcome tree hash mismatch: reconstructed tree does not match sender state',
      );
    }

    // Root-key export and hashing are part of validation. Commit only after
    // they succeed so every malformed-input or WebCrypto failure leaves the
    // receiver's prior tree intact and a retry starts from that exact state.
    const rootSecret = await staged.getRootSecret();
    if (
      receiverGeneration !== this._receiverGeneration ||
      !this._isFreshWelcomeTarget()
    ) {
      throw new Error(
        WELCOME_SUPERSEDED_MESSAGE,
      );
    }
    return await this._registerWelcomeCandidate(
      attemptRevision,
      staged,
      rootSecret,
      receiverGeneration,
    );
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
    if (this._pendingMutations !== 0) {
      throw new Error('Cannot compact BeeKEM during an active mutation');
    }
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

  private _isFreshWelcomeTarget(): boolean {
    return (
      this._nodes.size === 0 &&
      this._numLeaves === 0 &&
      this._myLeafIndex === -1
    );
  }

  private _assertInitializedForMutation(operation: string): void {
    if (
      !Number.isSafeInteger(this._numLeaves) ||
      this._numLeaves < 1 ||
      this._numLeaves > MAX_BEEKEM_TREE_LEAVES ||
      !Number.isSafeInteger(this._myLeafIndex) ||
      this._myLeafIndex < 0 ||
      this._myLeafIndex >= 2 * this._numLeaves - 1 ||
      !TreeMath.isLeaf(this._myLeafIndex) ||
      !this._nodes.has(this._myLeafIndex)
    ) {
      throw new Error(`Cannot ${operation}: BeeKEM tree is not initialized`);
    }
  }

  private _registerWelcomeCandidate(
    revision: bigint,
    staged: BeeKEM,
    rootSecret: Uint8Array,
    receiverGeneration: bigint,
  ): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
      this._pendingWelcomeAttempts.delete(revision);
      if (
        receiverGeneration !== this._receiverGeneration ||
        !this._isFreshWelcomeTarget()
      ) {
        rootSecret.fill(0);
        reject(
          new Error(
            WELCOME_SUPERSEDED_MESSAGE,
          ),
        );
        this._settleWelcomeCandidates();
        return;
      }
      for (const [previousRevision, candidate] of this._stagedWelcomeCandidates) {
        if (previousRevision > revision) {
          rootSecret.fill(0);
          reject(new Error(WELCOME_SUPERSEDED_MESSAGE));
          return;
        }
        this._stagedWelcomeCandidates.delete(previousRevision);
        candidate.rootSecret.fill(0);
        candidate.reject(new Error(WELCOME_SUPERSEDED_MESSAGE));
      }
      this._stagedWelcomeCandidates.set(revision, {
        receiverGeneration,
        nodes: staged._nodes,
        numLeaves: staged._numLeaves,
        leafIndex: staged._myLeafIndex,
        rootSecret,
        resolve,
        reject,
      });
      this._settleWelcomeCandidates();
    });
  }

  private _beginWelcomeSettlement(): void {
    if (this._resolveWelcomeSettlement !== undefined) return;
    this._welcomeSettlement = new Promise<void>((resolve) => {
      this._resolveWelcomeSettlement = resolve;
    });
  }

  private _finishWelcomeSettlementIfPossible(): void {
    if (
      this._resolveWelcomeSettlement === undefined ||
      (this._isFreshWelcomeTarget() &&
        (this._pendingWelcomeAttempts.size !== 0 ||
          this._stagedWelcomeCandidates.size !== 0))
    ) {
      return;
    }
    const resolve = this._resolveWelcomeSettlement;
    this._resolveWelcomeSettlement = undefined;
    resolve();
  }

  private _settleWelcomeCandidates(): void {
    if (this._stagedWelcomeCandidates.size === 0) {
      this._finishWelcomeSettlementIfPossible();
      return;
    }

    for (const [revision, candidate] of this._stagedWelcomeCandidates) {
      if (candidate.receiverGeneration !== this._receiverGeneration) {
        this._stagedWelcomeCandidates.delete(revision);
        candidate.rootSecret.fill(0);
        candidate.reject(
          new Error(
            WELCOME_SUPERSEDED_MESSAGE,
          ),
        );
      }
    }
    if (this._stagedWelcomeCandidates.size === 0) {
      this._finishWelcomeSettlementIfPossible();
      return;
    }

    if (!this._isFreshWelcomeTarget()) {
      const candidates = [...this._stagedWelcomeCandidates.values()];
      this._stagedWelcomeCandidates.clear();
      for (const candidate of candidates) {
        candidate.rootSecret.fill(0);
        candidate.reject(
          new Error(
            WELCOME_SUPERSEDED_MESSAGE,
          ),
        );
      }
      this._finishWelcomeSettlementIfPossible();
      return;
    }

    if (this._pendingInitializations !== 0) return;

    let winnerRevision = -1n;
    let winner: StagedWelcomeCandidate | undefined;
    for (const [revision, candidate] of this._stagedWelcomeCandidates) {
      if (revision > winnerRevision) {
        winnerRevision = revision;
        winner = candidate;
      }
    }
    if (
      winner === undefined ||
      [...this._pendingWelcomeAttempts].some(
        (revision) => revision > winnerRevision,
      )
    ) {
      return;
    }

    const candidates = [...this._stagedWelcomeCandidates.entries()];
    this._stagedWelcomeCandidates.clear();
    this._receiverGeneration++;
    this._nodes = winner.nodes;
    this._numLeaves = winner.numLeaves;
    this._myLeafIndex = winner.leafIndex;
    winner.resolve(winner.rootSecret);
    for (const [revision, candidate] of candidates) {
      if (revision !== winnerRevision) {
        candidate.rootSecret.fill(0);
        candidate.reject(
          new Error(WELCOME_SUPERSEDED_MESSAGE),
        );
      }
    }
    this._finishWelcomeSettlementIfPossible();
  }

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
   * Resolve the single public key that legacy PathUpdate v1 can address for a
   * subtree. A blank node can expand to several resolution nodes, but v1 has
   * only one ciphertext per path level and must reject that case.
   */
  private async _resolvePublicKey(
    nodeIndex: number,
  ): Promise<CryptoKey | null> {
    const resolution = this._collectResolutionPublicKeys(nodeIndex, 2);
    if (resolution.length > 1) {
      throw new Error(
        'Cannot update path: legacy PathUpdate v1 cannot safely encode ' +
          'multiple sibling resolution nodes',
      );
    }
    return resolution[0] ?? null;
  }

  private _collectResolutionPublicKeys(
    nodeIndex: number,
    limit: number,
  ): CryptoKey[] {
    const node = this._nodes.get(nodeIndex);
    if (node?.publicKey) return [node.publicKey];

    if (TreeMath.isInternal(nodeIndex)) {
      const leftChild = TreeMath.left(nodeIndex);
      const rightChild = TreeMath.right(nodeIndex, this._numLeaves);
      const leftKeys = this._collectResolutionPublicKeys(
        leftChild,
        limit,
      );
      if (leftKeys.length >= limit) return leftKeys;
      const rightKeys = this._collectResolutionPublicKeys(
        rightChild,
        limit - leftKeys.length,
      );
      return [...leftKeys, ...rightKeys];
    }

    return [];
  }

  /** Private resolution keys from the subtree root down to our own leaf. */
  private _privateKeyCandidates(nodeIndex: number): CryptoKey[] {
    const localPath = [
      this._myLeafIndex,
      ...TreeMath.directPath(this._myLeafIndex, this._numLeaves),
    ];
    const subtreeOffset = localPath.indexOf(nodeIndex);
    if (subtreeOffset === -1) return [];

    const candidates: CryptoKey[] = [];
    for (let offset = subtreeOffset; offset >= 0; offset--) {
      const privateKey = this._nodes.get(localPath[offset])?.privateKey;
      if (privateKey) candidates.push(privateKey);
    }
    return candidates;
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
