import type {
  CRDTSyncMessage,
  SyncMessageSignatureContext,
} from './crdt-sync-message.js';
import {
  MAX_CHANGE_TREE_DEPTH,
  MAX_CHANGE_TREE_EDGES,
  MAX_CHANGE_TREE_NODES,
} from './change-tree-walk.js';
import {
  MAX_SHARED_PROTOCOL_REQUEST_BYTES,
  snapshotDeepEnumerableData,
  snapshotEnumerableOwnDataObject,
} from './utils.js';

const reflectOwnKeys = Reflect.ownKeys;

const syncMessageSnapshotLimits = {
  // A change-node level adds a node and a children-map object.
  maxDepth: 2 * MAX_CHANGE_TREE_DEPTH + 16,
  // Accommodate every change-tree node, its children map, an adapter change
  // collection, and one binary change value, plus fixed message metadata.
  maxObjects: 4 * MAX_CHANGE_TREE_NODES + 1_024,
  // Cover maximum tree edges, node fields, and adapter collection entries.
  maxProperties: MAX_CHANGE_TREE_EDGES + 6 * MAX_CHANGE_TREE_NODES + 1_024,
  maxArrayLength: MAX_CHANGE_TREE_EDGES,
  // A bounded UTF-8 request may expand to two-byte JS strings while binary
  // adapter values shrink when decoded from base64.
  maxValueBytes: 2 * MAX_SHARED_PROTOCOL_REQUEST_BYTES,
} as const;

export type SyncMessageContext = SyncMessageSignatureContext;

const allowedFields: Readonly<
  Record<SyncMessageContext, ReadonlySet<string>>
> = {
  'ordinary-sync-v1': new Set([
    'documentId',
    'signatureContext',
    'changeId',
    'changes',
    'snapshot',
    'signature',
  ]),
  'document-publish-v1': new Set([
    'documentId',
    'signatureContext',
    'changeId',
    'changes',
    'signature',
  ]),
  'load-response-v3': new Set([
    'documentId',
    'signatureContext',
    'changeId',
    'changes',
    'snapshot',
    'keychainChanges',
    'tips',
    'signature',
  ]),
  'load-response-v4': new Set([
    'documentId',
    'signatureContext',
    'changeId',
    'changes',
    'snapshot',
    'keychainChanges',
    'tipsHash',
    'tips',
    'loadSecurityState',
    'loadChallenge',
    'signature',
  ]),
  'tip-advertisement-v1': new Set([
    'documentId',
    'signatureContext',
    'tipsHash',
    'signature',
  ]),
  'security-advertisement-v1': new Set([
    'documentId',
    'signatureContext',
    'tipsHash',
    'loadSecurityState',
    'loadChallenge',
    'signature',
  ]),
  'invitation-bootstrap-v1': new Set([
    'documentId',
    'signatureContext',
    'changeId',
    'changes',
    'snapshot',
    'keychainChanges',
    'tips',
    'signature',
  ]),
  'beekem-welcome-v1': new Set([
    'documentId',
    'signatureContext',
    'welcomeEpochId',
    'welcomeRecipient',
    'welcomeRecipientKemPublicKey',
    'eciesSealed',
    'signature',
  ]),
  'beekem-path-update-v1': new Set([
    'documentId',
    'signatureContext',
    'pathUpdate',
    'pathUpdateEpochId',
    'signature',
  ]),
  'key-update-v2': new Set([
    'documentId',
    'signatureContext',
    'keychainChanges',
    'signature',
  ]),
};

/**
 * Deeply detach a deserialized sync message and reject fields owned by another
 * wire context. A writer signature authenticates bytes, not protocol intent,
 * so a captured specialized body must not be accepted by ordinary sync or
 * another specialized handler after a reader re-encrypts it.
 */
export function snapshotSyncMessageForContext<ChangesType, PublicKey>(
  value: unknown,
  context: SyncMessageContext,
): CRDTSyncMessage<ChangesType, PublicKey> {
  const message = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    value,
    `${context} message`,
  );
  const fields = reflectOwnKeys(message);
  const allowed = allowedFields[context];
  for (const field of fields) {
    if (typeof field !== 'string') {
      throw new TypeError(`${context} message contains a symbol field`);
    }
    if (!allowed.has(field)) {
      throw new TypeError(
        `${context} message contains unexpected field '${field}'`,
      );
    }
  }
  if (message.signatureContext !== context) {
    throw new TypeError(
      `${context} message must declare signatureContext '${context}'`,
    );
  }

  return snapshotDeepEnumerableData(
    message,
    `${context} message`,
    syncMessageSnapshotLimits,
  ) as CRDTSyncMessage<ChangesType, PublicKey>;
}

/** @internal Compare an untrusted serializer input with the detached state to apply. */
export function syncMessageMatchesSnapshot<ChangesType, PublicKey>(
  expected: CRDTSyncMessage<ChangesType, PublicKey>,
  candidate: unknown,
  context: SyncMessageContext,
): boolean {
  let actual: CRDTSyncMessage<ChangesType, PublicKey>;
  try {
    actual = snapshotSyncMessageForContext(candidate, context);
  } catch {
    return false;
  }
  const pending: [unknown, unknown][] = [[expected, actual]];
  while (pending.length > 0) {
    const [left, right] = pending.pop()!;
    if (Object.is(left, right)) continue;
    if (
      left === null ||
      right === null ||
      typeof left !== 'object' ||
      typeof right !== 'object'
    )
      return false;
    if (left instanceof Uint8Array || right instanceof Uint8Array) {
      if (
        !(left instanceof Uint8Array) ||
        !(right instanceof Uint8Array) ||
        left.length !== right.length
      )
        return false;
      for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
      }
      continue;
    }
    if (Array.isArray(left) !== Array.isArray(right)) return false;
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    if (leftKeys.length !== rightKeys.length) return false;
    for (let index = 0; index < leftKeys.length; index++) {
      const key = leftKeys[index];
      if (key !== rightKeys[index]) return false;
      pending.push([
        (left as Record<string, unknown>)[key],
        (right as Record<string, unknown>)[key],
      ]);
    }
  }
  return true;
}
