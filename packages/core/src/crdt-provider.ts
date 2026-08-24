/**
 * The crdt provider provides an implementation of a set of methods for interacting with crdts generally
 */

/**
 * CRDTProvider is an interface with a set of methods for manipulating CRDT documents.
 *
 * @typeParam DocType The CRDT document type
 * @typeParam ChangesType A block of CRDT change(s)
 * @typeParam ChangeFnType A function for applying changes to a document
 * @typeParam MessageType The sync message that gets sent when changes are made to a document
 */
export interface CRDTProvider<DocType, ChangesType, ChangeFnType> {
  /**
   * Create a new empty (contains the equivalent of `{}`) CRDT document.
   */
  newDocument(): DocType;

  /**
   * Apply locally made changes to provided CRDT document as defined by `changeFn`.
   *
   * @param document CRDT document to change.
   * @param message A description of the change made.
   * @param changeFn A function that modifies a CRDT document (provided as a parameter).
   *     This function will be run as a part of `.localChange(...)`
   */
  localChange(
    document: DocType,
    message: string,
    changeFn: ChangeFnType,
  ): [DocType, ChangesType];

  /**
   * Apply CRDT document changes made by a remote peer.
   *
   * @param document CRDT document to update.
   * @param changes An object describing changes made by a peer. CRDT-specific.
   */
  remoteChange(document: DocType, changes: ChangesType): DocType;

  /**
   * Gets all changes for the document.
   *
   * @param document CRDT document to inspect.
   */
  getHistory(document: DocType): ChangesType;

  /**
   * Get a compacted state snapshot of the document.
   * Used for onboarding new members without replaying individual changes.
   *
   * For Yjs: `Y.encodeStateAsUpdateV2(doc)` (directly applicable via `remoteChange()`)
   * For Automerge: `Automerge.save(doc)` (requires `applySnapshot()` since save format
   *   differs from the incremental change format used by `remoteChange()`)
   *
   * @param document CRDT document to snapshot.
   * @returns A snapshot representation. If the snapshot format differs from the
   *   incremental change format, implement `applySnapshot()` as well.
   */
  getSnapshot?(document: DocType): ChangesType;

  /**
   * Apply a full-state snapshot produced by `getSnapshot()`.
   *
   * Implement this when the snapshot format differs from incremental changes
   * (e.g. Automerge's `save()` output cannot be applied via `applyChanges()`).
   * When not implemented, the caller falls back to `remoteChange()`.
   *
   * @param document Current CRDT document.
   * @param snapshot Snapshot state from `getSnapshot()`.
   * @returns The updated document with the snapshot state merged in.
   */
  applySnapshot?(document: DocType, snapshot: ChangesType): DocType;
}
