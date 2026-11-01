import {
  advanceDocumentOperation,
  type DocumentOperationPhase,
} from './policy/document-admission.js';

export interface PreparedDocumentChange<Changes> {
  readonly changes: Changes;
  isCurrent(): boolean;
  commit(): void;
  discard(): void;
  snapshot?(): Changes;
}

/** One document owner; preparation must not mutate its visible document. */
export interface CRDTDocumentSession<Document, Changes, Change> {
  readonly document: Document;
  prepareLocal(
    message: string,
    change: Change,
  ): PreparedDocumentChange<Changes>;
  prepareRemote(changes: Changes): PreparedDocumentChange<Changes>;
  prepareSnapshot?(snapshot: Changes): PreparedDocumentChange<Changes>;
  close(): void;
}

export function preparedDocumentChange<Changes>(
  changes: Changes,
  current: () => boolean,
  commit: () => void,
  discard: () => void,
  snapshot?: () => Changes,
): PreparedDocumentChange<Changes> {
  let phase: DocumentOperationPhase = 'prepared';
  return {
    changes,
    ...(snapshot
      ? {
          snapshot: () => {
            if (phase !== 'prepared' || !current())
              throw new Error('Stale document checkpoint');
            return snapshot();
          },
        }
      : {}),
    isCurrent: () => phase === 'prepared' && current(),
    commit: () => {
      if (phase === 'committed') return;
      if (phase !== 'prepared' || !current())
        throw new Error('Prepared document change is stale');
      phase = advanceDocumentOperation(phase, 'commit', true, true);
      commit();
    },
    discard: () => {
      if (phase !== 'prepared') return;
      phase = advanceDocumentOperation(phase, 'cancel', false, false);
      discard();
    },
  };
}
