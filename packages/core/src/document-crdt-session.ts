import {
  advancePreparedDocumentChange,
  type PreparedDocumentPhase,
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
  let phase: PreparedDocumentPhase = 'prepared';
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
      phase = advancePreparedDocumentChange(phase, 'begin');
      try {
        commit();
        phase = advancePreparedDocumentChange(phase, 'succeed');
      } catch (error) {
        phase = advancePreparedDocumentChange(phase, 'fail');
        try {
          discard();
        } catch {
          throw new Error('Document application and cleanup failed');
        }
        throw error;
      }
    },
    discard: () => {
      if (phase !== 'prepared') return;
      phase = advancePreparedDocumentChange(phase, 'cancel');
      discard();
    },
  };
}
