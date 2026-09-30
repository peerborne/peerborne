import { ACL } from './acl.js';

/**
 * Factory for ACL objects.
 *
 * Every call to {@link initialize} must return an ACL with logically isolated
 * mutable state. A provider must not return the same ACL object twice or return
 * distinct objects that share an underlying mutable ACL document. Mutation
 * ordering is scoped to each initialized backing instance.
 *
 * @typeParam ChangesType A block of CRDT change(s).
 * @typeParam PublicKey Type of a user's public key.
 */
export interface ACLProvider<ChangesType, PublicKey> {
  /**
   * Construct a new, logically isolated ACL object.
   *
   * @return A new ACL object.
   */
  initialize(): ACL<ChangesType, PublicKey>;
}
