import type { PreparedCommitClaim } from './prepared-commit.js';

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
 * A remote ACL merge that was rejected before any membership state changed.
 * Only ACL implementations that stage merges and swap them in atomically may
 * emit it; it certifies that the live ACL is exactly as it was before the call.
 */
export class ACLMergeRejectedError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : 'ACL merge was rejected', {
      cause,
    });
    this.name = 'ACLMergeRejectedError';
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
   * Stage a user addition without mutating the live ACL.
   *
   * Callers can finish fallible publication work before invoking the
   * synchronous commit. Implementations MUST detach `changes` from both the
   * caller and the private staged state and reject a repeated or stale commit
   * before mutation. A successful commit MUST apply the staged state
   * completely. Generic callers MUST treat any other commit exception as an
   * indeterminate backing state and fail closed; they cannot assume a custom
   * implementation rolled back a partially applied commit. The shipped CRDT
   * adapters complete fallible work during preparation and atomically swap
   * their private staged state only after all commit checks pass.
   */
  prepareAdd(publicKey: PublicKey): Promise<PreparedACLChange<ChangesType>>;

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
   * caller and the private staged state and reject a repeated or stale commit
   * before mutation. A successful commit MUST apply the staged state
   * completely. Generic callers MUST treat any other commit exception as an
   * indeterminate backing state and fail closed; they cannot assume a custom
   * implementation rolled back a partially applied commit. The shipped CRDT
   * adapters complete fallible work during preparation and atomically swap
   * their private staged state only after all commit checks pass.
   */
  prepareRemove(
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
   * A thrown {@link ACLOperationInProgressError} certifies that the merge was
   * rejected at its pre-mutation admission boundary and can be retried after
   * settlement. A thrown {@link ACLMergeRejectedError} certifies that the
   * merge was rejected without changing the ACL and must not be retried with
   * the same changes. Generic callers cannot assume any other exception left a
   * custom implementation unchanged, so authorization-sensitive orchestration
   * must fail closed.
   *
   * @param changes A block of change(s) to apply.
   */
  merge(changes: ChangesType): void;

  /**
   * Checks to see if the specified user has a specific capability.
   * If capability is undefined, checks if the user is in the ACL at all.
   *
   * @param publicKey User's public key.
   * @param capability Optional capability string to check for.
   * @return true if the user has the specified capability (or is in the ACL if no capability specified).
   */
  check(publicKey: PublicKey, capability?: string): Promise<boolean>;

  /**
   * Returns the list of users with a specific capability.
   * If capability is undefined, returns all users.
   *
   * @param capability Optional capability to filter users by.
   */
  users(capability?: string): Promise<PublicKey[]>;
}

/** A detached ACL mutation that has not yet changed live membership. */
export interface PreparedACLChange<ChangesType> {
  /** Changes suitable for publication to an ACL with the same base state. */
  readonly changes: ChangesType;
  /**
   * Claim the staged revision without changing live authorization.
   *
   * All fallible single-use and stale-base checks, allocation, and provider
   * work MUST finish before this method returns. The returned finalizer obeys
   * {@link PreparedCommitClaim}: callers may compose several successful
   * claims and then install them synchronously without a fail-partial state.
   * If a later claim fails, discarding this claim MUST leave live state
   * unchanged; a fresh staging operation must remain possible.
   *
   * Composed transitions must claim every provider before finalizing any
   * live-state mutation.
   */
  claimCommit(): PreparedCommitClaim;
  /**
   * Synchronous, single-use, stale-base-checked live-state commit. A normal
   * return proves complete application. Repeated and stale calls throw before
   * mutation; any other exception leaves state indeterminate to generic
   * callers and requires fail-closed handling.
   */
  commit(): void;
}
