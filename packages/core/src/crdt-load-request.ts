/**
 * CRDTLoadMessage is the message sent to peers to get the document's current state.
 *
 * @typeParam PublicKey Type of a user's identity.
 */
export type CRDTLoadRequest = {
  /**
   * ID of a peerborne document.
   */
  documentId: string;

  /**
   * Signature made by requesting user.
   */
  signature: string;
};
