import { LoroDoc } from 'loro-crdt';
import type { CRDTProvider } from '@peerborne/core';

export type LoroChange = (document: LoroDoc) => void;

/**
 * Experimental document provider. Snapshots retain history so offline replicas
 * can merge without introducing a shallow-history compatibility boundary.
 * ACL, keychain and wire serializers are supplied independently by the caller.
 */
export class LoroProvider
  implements CRDTProvider<LoroDoc, Uint8Array, LoroChange>
{
  newDocument(): LoroDoc {
    return new LoroDoc();
  }

  localChange(
    document: LoroDoc,
    message: string,
    change: LoroChange,
  ): [LoroDoc, Uint8Array] {
    const from = document.oplogVersion();
    change(document);
    document.commit({ message });
    return [document, document.export({ mode: 'update', from })];
  }

  remoteChange(document: LoroDoc, changes: Uint8Array): LoroDoc {
    document.import(changes);
    return document;
  }

  getHistory(document: LoroDoc): Uint8Array {
    return document.export({ mode: 'snapshot' });
  }

  getSnapshot(document: LoroDoc): Uint8Array {
    return document.export({ mode: 'snapshot' });
  }

  applySnapshot(document: LoroDoc, snapshot: Uint8Array): LoroDoc {
    return this.remoteChange(document, snapshot);
  }
}
