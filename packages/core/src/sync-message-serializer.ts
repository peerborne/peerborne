import { CRDTSyncMessage } from './crdt-sync-message.js';

/**
 * SyncMessageSerializer provides serialization/deserialization methods for
 * `CRDTSyncMessage`s.
 *
 * This is a signed compatibility boundary. Implementations and callers that
 * accept untrusted serialized messages must ensure deserialization yields a
 * deep-snapshot-compatible graph: primitives, genuine unshared `Uint8Array`s,
 * dense arrays, plain records containing only enumerable own data properties,
 * and an optional genuine `CryptoKey`. They must reject accessors, cycles,
 * symbols, functions, exotic objects, sparse/extended arrays, SAB-backed
 * views, and graphs outside their depth/object/property/byte bounds before
 * authentication or state mutation.
 *
 * Recognized field insertion order must also survive deserialize/serialize
 * round trips. Existing sync-message signatures cover the serializer's exact
 * bytes, so rebuilding a decoded object in a different field order makes an
 * otherwise valid signed envelope unverifiable. Implementations may drop
 * unknown wire fields, but must preserve the incoming order of recognized
 * fields.
 *
 * @typeParam ChangesType Type describing changes made to a CRDT document. CRDT implementation dependent.
 */
export interface SyncMessageSerializer<ChangesType, PublicKey = unknown> {
  serializeSyncMessage(message: CRDTSyncMessage<ChangesType, PublicKey>): Uint8Array;
  deserializeSyncMessage(message: Uint8Array): CRDTSyncMessage<ChangesType, PublicKey>;
}
