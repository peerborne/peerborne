/**
 * Output from a group key agreement operation.
 * Contains the derived shared secret and an update message to broadcast
 * to other group members so they can derive the same secret.
 */
export interface GroupKeyAgreementOutput {
  /** The shared group secret from which epoch keys are derived. */
  groupSecret: Uint8Array;
  /** Update message to send to other group members. */
  updateMessage: Uint8Array;
}

/**
 * Welcome message for onboarding a new member into an existing group.
 * Contains everything the new member needs to derive the current epoch key.
 */
export interface WelcomeMessage {
  /** The new member's position/leaf index in the group. */
  memberIndex: number;
  /** Encrypted epoch key material for the new member. */
  encryptedKeyMaterial: Uint8Array;
  /** Current group state needed for the new member to participate. */
  groupState: Uint8Array;
}

/**
 * Proposal for a membership change.
 * Must be signed by the proposer to prevent unauthorized modifications.
 */
export interface MembershipProposal {
  /** Whether this is an add or remove operation. */
  type: 'add' | 'remove';
  /** Public key of the affected member. */
  memberPublicKey: Uint8Array;
  /** Public key of the proposer. */
  proposerPublicKey: Uint8Array;
  /** Signature of the proposal by the proposer. */
  signature: Uint8Array;
}

/**
 * GroupKeyProvider abstracts the group key agreement protocol (BeeKEM or DCGKA).
 *
 * It manages a ratchet tree of member keys and produces shared secrets
 * from which epoch encryption keys are derived. Implementations of this
 * interface handle the tree structure, path secret derivation, and
 * key encapsulation internally.
 */
export interface GroupKeyProvider {
  /**
   * Initialize the group with the creator's key pair.
   * This sets up the ratchet tree with a single leaf for the creator.
   *
   * @param privateKey - The creator's private key.
   * @param publicKey - The creator's public key.
   */
  initialize(privateKey: CryptoKey, publicKey: CryptoKey): Promise<void>;

  /**
   * Add a new member to the group.
   * Inserts the member's public key into the ratchet tree and derives
   * new path secrets. Returns the updated group secret and a Welcome
   * message containing everything the new member needs to participate.
   *
   * @param memberPublicKey - The new member's public key.
   * @returns The group key agreement output and a Welcome message for the new member.
   */
  addMember(memberPublicKey: CryptoKey): Promise<{
    agreement: GroupKeyAgreementOutput;
    welcome: WelcomeMessage;
  }>;

  /**
   * Remove a member from the group.
   * Blanks the member's leaf in the ratchet tree and derives new key
   * material along the path to the root, ensuring the removed member
   * cannot derive the new group secret.
   *
   * @param memberPublicKey - The public key of the member to remove.
   * @returns The group key agreement output with the new group secret.
   */
  removeMember(memberPublicKey: CryptoKey): Promise<GroupKeyAgreementOutput>;

  /**
   * Perform a key update (periodic rotation for post-compromise security).
   * Generates fresh DH key pairs along the path from the caller's leaf
   * to the root of the ratchet tree.
   *
   * @returns The group key agreement output with the new group secret.
   */
  update(): Promise<GroupKeyAgreementOutput>;

  /**
   * Process an update message received from another group member.
   * Applies the sender's path updates to the local ratchet tree and
   * derives the new group secret.
   *
   * @param updateMessage - The serialized update message from a peer.
   * @returns The derived group secret.
   */
  processUpdate(updateMessage: Uint8Array): Promise<Uint8Array>;

  /**
   * Process a Welcome message when joining an existing group.
   * Decrypts the key material, initializes the local ratchet tree state,
   * and derives the current group secret.
   *
   * @param welcome - The Welcome message received from the group.
   * @param privateKey - The joining member's private key for decryption.
   * @returns The derived group secret.
   */
  processWelcome(welcome: WelcomeMessage, privateKey: CryptoKey): Promise<Uint8Array>;

  /**
   * Get the current number of members in the group.
   *
   * @returns The number of active (non-blank) leaves in the ratchet tree.
   */
  memberCount(): number;

  /**
   * Get the public keys of all current members.
   *
   * @returns An array of public CryptoKeys for all active members.
   */
  members(): CryptoKey[];
}
