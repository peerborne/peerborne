/** A retryable conflict with an unresolved ACL operation. */
export class ACLOperationInProgressError extends Error {
  private readonly _settled: Promise<void>;

  constructor(
    operation: string,
    settled: Promise<void>,
  ) {
    super(
      `${operation} is unavailable while another ACL operation is in progress`,
    );
    this.name = 'ACLOperationInProgressError';
    this._settled = settled.then(
      () => undefined,
      () => undefined,
    );
  }

  /** Wait until the conflicting operation has settled before retrying. */
  waitForSettlement(): Promise<void> {
    return this._settled;
  }
}

/**
 * Retry an external ACL operation across explicitly reported conflicts.
 * ACL implementations must emit this conflict only from a pre-invocation
 * admission boundary, certifying that the rejected operation made no state
 * change. Backing ACL implementations and identity codecs must propagate a
 * conflict rather than waiting because they may own the operation that must
 * settle. Security wrappers may convert a conflict received after invoking an
 * opaque mutating provider into a terminal failure because they cannot prove
 * that provider remained unchanged before propagating it.
 */
export async function retryACLConflict<T>(
  operation: () => T | PromiseLike<T>,
): Promise<T> {
  for (;;) {
    try {
      return await operation();
    } catch (error) {
      if (!(error instanceof ACLOperationInProgressError)) {
        throw error;
      }
      await error.waitForSettlement();
    }
  }
}

/**
 * An ACL keeps track of a list of user's public keys and produces changes that
 * can be sent to other swarm peers.
 *
 * Implementations must compare public keys by their provider-defined canonical
 * key material, not JavaScript object reference. Security wrappers may pass a
 * fresh detached object that represents the same canonical identity to each
 * operation.
 *
 * Implementations that serialize access may reject overlapping calls with
 * {@link ACLOperationInProgressError}. External orchestration can use
 * {@link retryACLConflict}; backing implementations must propagate the
 * conflict without waiting on it.
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
