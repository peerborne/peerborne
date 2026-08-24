import { CRDTSyncMessage } from './crdt-sync-message.js';

/**
 * SyncMessageSerializer provides serialization/deserialization methods for `CRDTSyncMessage`s.
 *
 * @typeParam ChangesType Type describing changes made to a CRDT document. CRDT implementation dependent.
 */
export interface SyncMessageSerializer<ChangesType, PublicKey = unknown> {
  serializeSyncMessage(message: CRDTSyncMessage<ChangesType, PublicKey>): Uint8Array;
  deserializeSyncMessage(message: Uint8Array): CRDTSyncMessage<ChangesType, PublicKey>;
}
