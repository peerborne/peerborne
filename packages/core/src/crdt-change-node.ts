export type CRDTChangeNodeDeferred = false;
export const crdtChangeNodeDeferred: CRDTChangeNodeDeferred = false;

export type CRDTDocumentChangeNode = 'document';
export const crdtDocumentChangeNode: CRDTDocumentChangeNode = 'document';
export type CRDTWriterChangeNode = 'writer';
export const crdtWriterChangeNode: CRDTWriterChangeNode = 'writer';
export type CRDTReaderChangeNode = 'reader';
export const crdtReaderChangeNode: CRDTReaderChangeNode = 'reader';
export type CRDTChangeNodeKind =
  | CRDTDocumentChangeNode
  | CRDTWriterChangeNode
  | CRDTReaderChangeNode;

/**
 * A CRDT Change node represents a shadow copy of a Merkle DAG that is sent over sync messages.
 *
 * @typeParam ChangesType A block of CRDT change(s).
 */
export type CRDTChangeNode<ChangesType> = {
  /**
   * Identifier for the document encryption key used to encrypt this node's change.
   * Preserved through serialize/deserialize round-trips in sync messages.
   */
  keyID?: string;

  kind: CRDTChangeNodeKind;

  /**
   * Changes made to the document itself (if any).
   *
   * `undefined` means the change payload was deferred -- it was not included
   * in the sync message and should be fetched from the Helia blockstore
   * using the node's CID.
   */
  change?: ChangesType;

  /**
   * Child nodes of the current node keyed on its CID.
   *
   * `undefined` means that this node is a leaf node (equivalent to `[]`).
   */
  children?:
    | { [hash: string]: CRDTChangeNode<ChangesType> }
    | CRDTChangeNodeDeferred;
};
