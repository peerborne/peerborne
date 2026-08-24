import { CRDTLoadRequest } from './crdt-load-request.js';

/**
 * LoadMessageSerializer provides serialization/deserialization methods for `CRDTLoadRequest`s.
 *
 * @typeParam PublicKey Type of a user's identity.
 */
export interface LoadMessageSerializer {
  serializeLoadRequest(message: CRDTLoadRequest): Uint8Array;
  deserializeLoadRequest(message: Uint8Array): CRDTLoadRequest;
}
