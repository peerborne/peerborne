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
   * Stage a user addition without mutating the live ACL.
   *
   * Callers can finish fallible publication work before invoking the
   * synchronous commit. Implementations MUST detach `changes` from both the
   * caller and the private staged state, reject a repeated or stale commit
   * before mutation, and either apply the staged state completely or throw
   * before changing live membership.
   *
   * Optional for backwards compatibility. Workflows that require
   * publication-before-commit semantics must feature-detect this method and
   * fail closed when it is absent.
   */
  prepareAdd?(publicKey: PublicKey): Promise<PreparedACLChange<ChangesType>>;

  /**
   * Remove a user from the ACL.
   *
   * @param publicKey User's public key.
   * @return A block of change(s) for the removal from the ACL.
   */
  remove(publicKey: PublicKey): Promise<ChangesType>;

  /**
   * Stage a user removal without mutating the live ACL.
   *
   * Callers can finish fallible publication work before invoking the
   * synchronous commit. Implementations MUST detach `changes` from both the
   * caller and the private staged state, reject a repeated or stale commit
   * before mutation, and either apply the staged state completely or throw
   * before changing live membership.
   *
   * Optional for backwards compatibility. Workflows that require
   * publication-before-commit semantics must feature-detect this method and
   * fail closed when it is absent.
   */
  prepareRemove?(
    publicKey: PublicKey,
  ): Promise<PreparedACLChange<ChangesType>>;

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

/** A detached ACL mutation that has not yet changed live membership. */
export interface PreparedACLChange<ChangesType> {
  /** Changes suitable for publication to an ACL with the same base state. */
  readonly changes: ChangesType;
  /** Synchronous, single-use, stale-base-checked live-state commit. */
  commit(): void;
}

/** Backwards-compatible name for a prepared ACL removal. */
export type PreparedACLRemoval<ChangesType> = PreparedACLChange<ChangesType>;
