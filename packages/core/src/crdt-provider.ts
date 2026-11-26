import type { CRDTActorBinding } from './crdt-actor-binding.js';
import type { CRDTDocumentSession } from './document-crdt-session.js';

/**
 * A change function threw after editing a document that cannot be rolled back.
 * `changes` encodes that partial edit. Publish it before surfacing `cause`, or
 * later changes from this replica depend on an edit no peer received.
 */
export class PartialLocalChangeError<DocType, ChangesType> extends Error {
  constructor(
    cause: unknown,
    readonly document: DocType,
    readonly changes: ChangesType,
  ) {
    super('Change function failed after editing the document', { cause });
    this.name = 'PartialLocalChangeError';
  }
}

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
   * Binds this provider's actor identifiers to change signers. When present,
   * ordinary documents sign every change, write under derived actors and
   * reject a change that adds operations under an actor its signer does not
   * own. Coordinator-backed documents do not use it.
   */
  readonly actorBinding?: CRDTActorBinding<DocType, ChangesType>;

  /** Required by coordinator-backed documents; never falls back to live preparation. */
  createDocumentSession?(
    document: DocType,
  ): CRDTDocumentSession<DocType, ChangesType, ChangeFnType>;

  /**
   * Create a new empty (contains the equivalent of `{}`) CRDT document.
   */
  newDocument(): DocType;

  /**
   * Return a writable copy of `document` as it was when it was produced, even
   * after a later `localChange()` or `remoteChange()` consumed it, or
   * `undefined` when no faithful copy exists.
   *
   * Implement this when those methods leave their input unusable, as
   * Automerge marks it outdated. A local change that fails before it is stored
   * and recorded in the change tree rolls back to this copy. The copy must
   * make its next local change under a new replica identity, so the discarded
   * change's position is never reused.
   * Return `undefined` when the copy would lose state, such as remote changes
   * still waiting for their dependencies: the document instance is then
   * retired instead. When not implemented, a failed change rolls back to
   * `document` itself if `localChange()` returned a new document. A provider
   * whose `localChange()` returns the document it was given edits in place
   * and cannot roll back, so the instance is retired.
   *
   * @param document A document this provider returned before the failed change.
   */
  cloneDocument?(document: DocType): DocType | undefined;

  /**
   * Apply locally made changes to provided CRDT document as defined by `changeFn`.
   *
   * If `changeFn` throws, leave `document` without its edits and rethrow the
   * error. A provider that edits in place and cannot roll back throws
   * {@link PartialLocalChangeError} instead when the callback edited anything.
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
   * Report whether `document` has integrated every change in `changes`.
   *
   * Implement this when `remoteChange()` can buffer changes until their
   * causal dependencies arrive and buffered changes are missing from
   * `getHistory()`. Peerborne records a remote change as applied only after
   * this returns true, so a buffered change stays eligible for redelivery.
   * It runs for every delivered change and, after a change integrates, for
   * each change still waiting, of which Peerborne keeps at most 4,096 per
   * document. Those checks pass the same
   * `changes` object, so cache per-change decoding by it. When not
   * implemented, every applied change counts as integrated.
   *
   * @param document CRDT document returned by `remoteChange()`.
   * @param changes Changes previously passed to `remoteChange()`.
   */
  hasIntegrated?(document: DocType, changes: ChangesType): boolean;

  /**
   * Report whether `document` no longer holds `changes`, which
   * `remoteChange()` buffered while a dependency was missing, and will never
   * integrate them. A provider that validates buffered changes once their
   * dependencies arrive, or evicts them, implements this. Peerborne then stops
   * waiting for the change, as when it evicts a waiting change itself, so a
   * later delivery passes it to `remoteChange()` again. It runs for a waiting
   * change when it is delivered again and, after a change integrates, for each
   * change still waiting. When not implemented, a buffered change waits until
   * it integrates or Peerborne evicts it.
   *
   * @param document CRDT document returned by `remoteChange()`.
   * @param changes Changes previously passed to `remoteChange()`.
   */
  hasDiscarded?(document: DocType, changes: ChangesType): boolean;

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

  /**
   * Report whether `document` holds remote changes that wait for missing
   * causal dependencies, such as Automerge's queued changes or Yjs pending
   * structs and deletions. Automatic catch-up asks peers for missed updates
   * while this is true. When not implemented, only failed block fetches and
   * advertised heads reveal a gap.
   *
   * @param document CRDT document to inspect.
   */
  hasPendingChanges?(document: DocType): boolean;
}
