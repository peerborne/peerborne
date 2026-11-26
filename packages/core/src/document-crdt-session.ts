import {
  advancePreparedDocumentChange,
  type PreparedDocumentPhase,
} from './policy/document-admission.js';
import type { DocumentWritePaths } from './document-field-authorization.js';

export interface DocumentPreparationOptions {
  /**
   * `true` fails preparation when inspection fails or exceeds its bounds.
   * `'record'` inspects the same way but reports the whole document, `[[]]`,
   * instead of failing.
   */
  readonly inspectOperations?: boolean | 'record';
}

/**
 * A remote change names native causal dependencies the session does not hold
 * yet. `ready` reports, without staging, whether the session now holds every
 * dependency the change named, so a held change is retried only then.
 */
export class DocumentCausalDependencyError extends Error {
  constructor(readonly ready?: () => boolean) {
    super('Document change has missing causal dependencies');
    this.name = 'DocumentCausalDependencyError';
  }
}

export interface PreparedDocumentChange<Changes> {
  readonly changes: Changes;
  isCurrent(): boolean;
  commit(): void;
  discard(): void;
  snapshot?(): Changes;
  operationPaths?(): DocumentWritePaths;
}

/** One document owner; preparation must not mutate its visible document. */
export interface CRDTDocumentSession<Document, Changes, Change> {
  readonly document: Document;
  prepareLocal(
    message: string,
    change: Change,
    options?: DocumentPreparationOptions,
  ): PreparedDocumentChange<Changes>;
  prepareRemote(
    changes: Changes,
    options?: DocumentPreparationOptions,
  ): PreparedDocumentChange<Changes>;
  prepareSnapshot?(snapshot: Changes): PreparedDocumentChange<Changes>;
  /** Stage a native CRDT merge that retains already accepted local operations. */
  prepareMergeSnapshot?(snapshot: Changes): PreparedDocumentChange<Changes>;
  close(): void;
}

export function preparedDocumentChange<Changes>(
  changes: Changes,
  current: () => boolean,
  commit: () => void,
  discard: () => void,
  snapshot?: () => Changes,
  operationPaths?: () => DocumentWritePaths,
): PreparedDocumentChange<Changes> {
  let phase: PreparedDocumentPhase = 'prepared';
  let checking = false;
  const isCurrent = () => {
    if (phase !== 'prepared' || checking) return false;
    checking = true;
    try {
      return current() === true && phase === 'prepared';
    } finally {
      checking = false;
    }
  };
  return {
    changes,
    ...(operationPaths
      ? {
          operationPaths: () => {
            if (!isCurrent())
              throw new Error('Stale document operation inspection');
            const paths = operationPaths();
            if (!isCurrent())
              throw new Error('Stale document operation inspection');
            return paths;
          },
        }
      : {}),
    ...(snapshot
      ? {
          snapshot: () => {
            if (!isCurrent()) throw new Error('Stale document checkpoint');
            const value = snapshot();
            if (!isCurrent()) throw new Error('Stale document checkpoint');
            return value;
          },
        }
      : {}),
    isCurrent,
    commit: () => {
      if (phase === 'committed') return;
      if (!isCurrent()) throw new Error('Prepared document change is stale');
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
