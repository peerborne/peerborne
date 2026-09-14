import { CRDTLoadRequest } from './crdt-load-request.js';

/**
 * Incremental boundary detector for an unframed serialized load request.
 *
 * The callback receives each newly read chunk in order. It returns `true`
 * only when that chunk completes the request and throws when the bytes can no
 * longer form a valid frame. Implementations must do bounded incremental work
 * rather than rescanning previously supplied chunks.
 */
export type LoadRequestCompletionDetector = (chunk: Uint8Array) => boolean;

/**
 * LoadMessageSerializer provides serialization/deserialization methods for `CRDTLoadRequest`s.
 *
 * @typeParam PublicKey Type of a user's identity.
 */
export interface LoadMessageSerializer {
  serializeLoadRequest(message: CRDTLoadRequest): Uint8Array;
  deserializeLoadRequest(message: Uint8Array): CRDTLoadRequest;

  /**
   * Create per-stream framing state for fragmented requests whose writer may
   * remain open while waiting for a response.
   *
   * When omitted, a one-chunk request can still complete immediately, but a
   * fragmented request is decoded only after EOF. This fail-closed fallback
   * prevents repeated whole-buffer deserialization under byte-dribble input.
   */
  createLoadRequestCompletionDetector?(): LoadRequestCompletionDetector;
}
