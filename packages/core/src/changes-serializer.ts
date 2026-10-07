/**
 * ChangesSerializer provides serialization/deserialization methods for CRDT changes.
 *
 * @typeParam ChangesType Type describing changes to a CRDT document. CRDT implementation dependent.
 */
export interface ChangesSerializer<ChangesType> {
  serializeChanges(changes: ChangesType): Uint8Array;
  deserializeChanges(changes: Uint8Array): ChangesType;
}
