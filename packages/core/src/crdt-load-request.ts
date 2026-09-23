import {
  cloneInitialLoadChallenge,
  initialLoadRequestSignaturePayload,
} from './initial-load-challenge.js';
import { snapshotEnumerableOwnDataObject } from './utils.js';

/** A signed document request with a fresh challenge bound into every response. */
export type CRDTLoadRequest = {
  documentId: string;
  signature: string;
  loadChallenge: Uint8Array;
};

export function snapshotLoadRequest(value: unknown): CRDTLoadRequest {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    value,
    'load request',
    { maxProperties: 3, maxKeyBytes: 256 },
  );
  if (
    Reflect.ownKeys(record).length !== 3 ||
    typeof record.documentId !== 'string' ||
    typeof record.signature !== 'string' ||
    record.signature.length === 0 ||
    record.signature.length > 4 * Math.ceil(8192 / 3)
  ) {
    throw new TypeError(
      'Load request requires documentId, signature, and loadChallenge',
    );
  }
  const loadChallenge = cloneInitialLoadChallenge(
    record.loadChallenge as Uint8Array,
  );
  initialLoadRequestSignaturePayload(record.documentId, loadChallenge);
  return { ...record, loadChallenge } as CRDTLoadRequest;
}
