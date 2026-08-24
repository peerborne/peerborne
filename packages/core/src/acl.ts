/**
 * An ACL keeps track of a list of user's public keys and produces changes that
 * can be sent to other swarm peers.
 *
 * @typeParam ChangesType A block of CRDT change(s).
 * @typeParam PublicKey Type of a user's public key.
 */
export interface ACL<ChangesType, PublicKey> {
  /**
   * Add a new user to the ACL.
   *
   * @param publicKey User's public key.
   * @return A block of change(s) for the addition to the ACL.
   */
  add(publicKey: PublicKey): Promise<ChangesType>;

  /**
   * Remove a user from the ACL.
   *
   * @param publicKey User's public key.
   * @return A block of change(s) for the removal from the ACL.
   */
  remove(publicKey: PublicKey): Promise<ChangesType>;

  /**
   * Gets a block of change(s) describing the current state of the ACL.
   *
   * @return A block of change(s) describing the whole ACL.
   */
  current(): ChangesType;

  /**
   * Applies a block of change(s) to the ACL.
   *
   * @param changes A block of change(s) to apply.
   */
  merge(changes: ChangesType): void;

  /**
   * Checks to see if the specified user has a specific capability.
   * If capability is undefined, checks if the user is in the ACL at all (backward compatible).
   *
   * @param publicKey User's public key.
   * @param capability Optional capability string to check for.
   * @return true if the user has the specified capability (or is in the ACL if no capability specified).
   */
  check(publicKey: PublicKey, capability?: string): Promise<boolean>;

  /**
   * Returns the list of users with a specific capability.
   * If capability is undefined, returns all users (backward compatible).
   *
   * @param capability Optional capability to filter users by.
   */
  users(capability?: string): Promise<PublicKey[]>;
}
