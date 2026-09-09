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

  /** Fresh 32-byte nonce required and signed on security-aware V4 loads. */
  loadChallenge?: Uint8Array;
};
