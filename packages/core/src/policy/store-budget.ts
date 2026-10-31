/** Reserve or release framed bytes without escaping the committed-state bound. */
export function adjustStoreBytes(
  used: number,
  delta: number,
  minimum: number,
  maximum: number,
): number {
  //@ verify
  //@ requires 0 <= minimum && minimum <= used && used <= maximum && maximum <= 134217728
  //@ requires -134217728 <= delta && delta <= 134217728
  //@ ensures \result === -1 <==> used + delta < minimum || used + delta > maximum
  //@ ensures \result !== -1 ==> \result === used + delta && minimum <= \result && \result <= maximum
  const next = used + delta;
  return next < minimum || next > maximum ? -1 : next;
}

export function nextStoreRevision(revision: number): number {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991
  //@ ensures \result === -1 <==> revision === 9007199254740991
  //@ ensures \result !== -1 ==> \result === revision + 1 && revision < \result && \result <= 9007199254740991
  return revision === 9007199254740991 ? -1 : revision + 1;
}

export function classifyStoreCommitBaseline(
  baseRevision: number,
  observedRevision: number,
  hadEpoch: boolean,
  hasEpoch: boolean,
  baseEpoch: bigint,
  nextEpoch: bigint,
): 'revision' | 'rollback' | 'ready' {
  //@ verify
  //@ ensures \result === "revision" <==> baseRevision !== observedRevision
  //@ ensures \result === "rollback" <==> baseRevision === observedRevision && hadEpoch && (!hasEpoch || nextEpoch < baseEpoch)
  //@ ensures \result === "ready" <==> baseRevision === observedRevision && (!hadEpoch || (hasEpoch && nextEpoch >= baseEpoch))
  if (baseRevision !== observedRevision) return 'revision';
  return hadEpoch && (!hasEpoch || nextEpoch < baseEpoch)
    ? 'rollback'
    : 'ready';
}
