const MAX_REVISION = 9007199254740991;

export type DocumentRecoveryDisposition = 'ready' | 'already-active' | 'stale';

/** Decide against an observed locator after validation and authorization. */
export function classifyDocumentRecovery(
  baseRevision: number,
  observedRevision: number,
  baseMatches: boolean,
  successorMatches: boolean,
): DocumentRecoveryDisposition {
  //@ verify
  //@ requires 0 <= baseRevision && baseRevision < MAX_REVISION
  //@ requires 0 <= observedRevision && observedRevision <= MAX_REVISION
  //@ ensures \result === "ready" <==> observedRevision === baseRevision && baseMatches
  //@ ensures \result === "already-active" <==> observedRevision === baseRevision + 1 && successorMatches
  //@ ensures \result === "stale" <==> !(observedRevision === baseRevision && baseMatches) && !(observedRevision === baseRevision + 1 && successorMatches)
  if (observedRevision === baseRevision && baseMatches) return 'ready';
  if (observedRevision === baseRevision + 1 && successorMatches)
    return 'already-active';
  return 'stale';
}

/** Present a successor for atomic publication only after durable private staging. */
export function canPublishDocumentRecovery(
  disposition: DocumentRecoveryDisposition,
  staged: boolean,
): boolean {
  //@ verify
  //@ ensures \result <==> disposition === "ready" && staged
  return disposition === 'ready' && staged;
}
