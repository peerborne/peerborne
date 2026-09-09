import { BeeKEM } from './beekem/beekem.js';
import { PathUpdate } from './beekem/types.js';
import type { BeeKEMWireVersion } from './wire-protocols.js';

export type BeeKEMPathUpdateApplyResult =
  | { kind: 'applied' }
  | { kind: 'duplicate' }
  | {
      kind: 'rejected';
      reason:
        | 'legacy-downgrade'
        | 'path-update'
        | 'epoch-mismatch'
        | 'key-install';
      error?: unknown;
    };

export interface BeeKEMPathUpdateApplyDependencies<DocumentKey> {
  deriveEpochId(rootSecret: Uint8Array): Promise<Uint8Array>;
  deriveDocumentKey(rootSecret: Uint8Array): Promise<DocumentKey>;
  /**
   * MUST either commit completely or reject before any externally visible
   * mutation. BeeKEM can roll back its own tree, but cannot undo caller-owned
   * state changed before this promise rejects.
   */
  installEpochKey(epochId: Uint8Array, key: DocumentKey): Promise<void>;
}

/** Exact document binding used before authenticating or applying a message. */
export function isBeeKEMMessageForDocument(
  messageDocumentId: unknown,
  documentPath: string,
): boolean {
  return messageDocumentId === documentPath;
}

/**
 * Couple ratchet advancement, epoch binding, and a caller-staged key install.
 * A callback rejection restores BeeKEM generation and tree state only. The
 * caller owns atomicity of any external keychain mutation.
 */
export async function applyBeeKEMPathUpdateWithEpoch<DocumentKey>(
  beekem: BeeKEM,
  pathUpdate: PathUpdate,
  protocolVersion: BeeKEMWireVersion,
  expectedEpochId: Uint8Array,
  dependencies: BeeKEMPathUpdateApplyDependencies<DocumentKey>,
): Promise<BeeKEMPathUpdateApplyResult> {
  if (protocolVersion === 1 && beekem.generation !== null) {
    return { kind: 'rejected', reason: 'legacy-downgrade' };
  }

  let failureStage: 'path-update' | 'epoch-mismatch' | 'key-install' =
    'path-update';
  let duplicate = false;
  try {
    await beekem.processPathUpdateTransactionally(
      pathUpdate,
      async (rootSecret, disposition) => {
        failureStage = 'epoch-mismatch';
        const localEpochId = await dependencies.deriveEpochId(rootSecret);
        if (!constantTimeEqual(localEpochId, expectedEpochId)) {
          throw new Error('BeeKEM PathUpdate epoch-ID mismatch');
        }
        if (disposition === 'duplicate') {
          duplicate = true;
          return;
        }

        failureStage = 'key-install';
        const documentKey = await dependencies.deriveDocumentKey(rootSecret);
        await dependencies.installEpochKey(localEpochId, documentKey);
      },
    );
    return duplicate ? { kind: 'duplicate' } : { kind: 'applied' };
  } catch (error) {
    return { kind: 'rejected', reason: failureStage, error };
  }
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference === 0;
}
