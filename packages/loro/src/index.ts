import { LoroDoc, decodeImportBlobMeta } from 'loro-crdt';
import { PartialLocalChangeError, type CRDTProvider } from '@peerborne/core';

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
    try {
      change(document);
    } catch (error) {
      document.commit({ message });
      if (from.compare(document.oplogVersion()) === 0) throw error;
      throw new PartialLocalChangeError(
        error,
        document,
        document.export({ mode: 'update', from }),
      );
    }
    document.commit({ message });
    return [document, document.export({ mode: 'update', from })];
  }

  remoteChange(document: LoroDoc, changes: Uint8Array): LoroDoc {
    document.import(changes);
    return document;
  }

  /**
   * Loro holds an imported change whose dependencies are missing outside the
   * oplog, and snapshot exports omit it. A change is integrated once the oplog
   * covers the end of every peer range it carries.
   */
  hasIntegrated(document: LoroDoc, changes: Uint8Array): boolean {
    const integrated = document.oplogVersion();
    for (const [peer, end] of decodeImportBlobMeta(
      changes,
      false,
    ).partialEndVersionVector.toJSON())
      if ((integrated.get(peer) ?? 0) < end) return false;
    return true;
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
