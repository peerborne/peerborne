import { ACL } from './acl.js';

/**
 * Factory for ACL objects.
 *
 * @typeParam ChangesType A block of CRDT change(s).
 * @typeParam PublicKey Type of a user's public key.
 */
export interface ACLProvider<ChangesType, PublicKey> {
  /**
   * Construct a new ACL object.
   *
   * @return A new ACL object.
   */
  initialize(): ACL<ChangesType, PublicKey>;
}
