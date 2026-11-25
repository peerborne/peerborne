import {
  cloneInitialLoadChallenge,
  initialLoadRequestSignaturePayload,
} from './initial-load-challenge.js';
import { snapshotEnumerableOwnDataObject } from './utils.js';

/**
 * A signed document request addressed to one responder's libp2p PeerId, with
 * a fresh challenge bound into every response.
 */
export type CRDTLoadRequest = {
  documentId: string;
  signature: string;
  loadChallenge: Uint8Array;
  responder: string;
};

export function snapshotLoadRequest(value: unknown): CRDTLoadRequest {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    value,
    'load request',
    { maxProperties: 4, maxKeyBytes: 256 },
  );
  if (
    Reflect.ownKeys(record).length !== 4 ||
    typeof record.documentId !== 'string' ||
    typeof record.responder !== 'string' ||
    typeof record.signature !== 'string' ||
    record.signature.length === 0 ||
    record.signature.length > 4 * Math.ceil(8192 / 3)
  ) {
    throw new TypeError(
      'Load request requires documentId, signature, loadChallenge, and responder',
    );
  }
  const loadChallenge = cloneInitialLoadChallenge(
    record.loadChallenge as Uint8Array,
  );
  initialLoadRequestSignaturePayload(
    record.documentId,
    loadChallenge,
    record.responder,
  );
  return { ...record, loadChallenge } as CRDTLoadRequest;
}
