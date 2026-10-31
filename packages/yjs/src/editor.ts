import {
  Doc,
  applyUpdateV2,
  encodeStateAsUpdateV2,
  encodeStateVector,
} from 'yjs';

export interface YjsEditorSource<PublicKey = unknown> {
  readonly document: Doc;
  change(change: (document: Doc) => void, message?: string): Promise<unknown>;
  subscribe(
    id: string,
    handler: (
      document: Doc,
      readers: PublicKey[],
      writers: PublicKey[],
      hashes: string[],
    ) => void,
    originFilter?: 'all' | 'local' | 'remote',
  ): void;
  unsubscribe(id: string): void;
}

export interface YjsEditorBridge {
  /** Bind the editor to this private mirror, never directly to source.document. */
  readonly document: Doc;
  /** Wait for queued writes; rejects on the first failed Peerborne mutation. */
  flush(): Promise<void>;
  /** Detach listeners, finish queued writes, then destroy the editor mirror. */
  destroy(): Promise<void>;
}

let nextBridge = 0;

/**
 * Bind an editor to an already-open Peerborne document. Local mirror updates
 * enter source.change() before mutating the authoritative document, preserving
 * delta capture, authorization, encryption and publication. Remote updates do
 * not echo. After a write failure, recreate the bridge from authoritative state.
 * Presence/awareness transport is not provided.
 */
export function createYjsEditorBridge<PublicKey>(
  source: YjsEditorSource<PublicKey>,
  options: { onError?: (error: unknown) => void; message?: string } = {},
): YjsEditorBridge {
  const document = new Doc();
  const origin = {};
  const id = `peerborne-editor-${nextBridge++}`;
  let pending = Promise.resolve();
  let failed = false;
  let failure: unknown;
  let destroying: Promise<void> | undefined;

  const receive = () => {
    applyUpdateV2(
      document,
      encodeStateAsUpdateV2(source.document, encodeStateVector(document)),
      origin,
    );
  };
  source.subscribe(id, receive);
  receive();

  const send = (update: Uint8Array, updateOrigin: unknown) => {
    if (updateOrigin === origin) return;
    const bytes = new Uint8Array(update);
    pending = pending
      .then(async () => {
        if (failed) throw failure;
        await source.change((current) => {
          applyUpdateV2(current, bytes, origin);
        }, options.message ?? 'Editor change');
      })
      .catch((error: unknown) => {
        if (!failed) {
          failed = true;
          failure = error;
          options.onError?.(error);
        }
        throw error;
      });
    void pending.catch(() => {});
  };
  document.on('updateV2', send);

  return {
    document,
    flush: () => pending,
    destroy() {
      if (!destroying) {
        source.unsubscribe(id);
        document.off('updateV2', send);
        destroying = pending.finally(() => {
          document.destroy();
        });
      }
      return destroying;
    },
  };
}
