export type DocumentJournalRecovery = 'current' | 'finish-anchor' | 'reject';

export function isAcceptedDocumentPublication(
  revision: number,
  currentRevision: number,
  bindingRevision: number,
): boolean {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991
  //@ requires 0 <= currentRevision && currentRevision <= 9007199254740991
  //@ requires 0 <= bindingRevision && bindingRevision <= 9007199254740991
  //@ ensures \result <==> 1 <= revision && revision <= currentRevision && bindingRevision === revision
  return (
    1 <= revision && revision <= currentRevision && bindingRevision === revision
  );
}

export function classifyDocumentJournalRecovery(
  stored: number,
  anchored: number,
  commitmentMatches: boolean,
  parentMatches: boolean,
  markerAuthenticated: boolean,
): DocumentJournalRecovery {
  //@ verify
  //@ requires 0 <= stored && stored <= 9007199254740991
  //@ requires 0 <= anchored && anchored <= 9007199254740991
  //@ ensures \result === "current" <==> markerAuthenticated && stored === anchored && commitmentMatches
  //@ ensures \result === "finish-anchor" <==> markerAuthenticated && stored > anchored && stored - anchored === 1 && parentMatches
  //@ ensures \result === "reject" <==> !markerAuthenticated || !(stored === anchored && commitmentMatches) && !(stored > anchored && stored - anchored === 1 && parentMatches)
  if (!markerAuthenticated) return 'reject';
  if (stored === anchored && commitmentMatches) return 'current';
  if (stored > anchored && stored - anchored === 1 && parentMatches)
    return 'finish-anchor';
  return 'reject';
}

export function canAdvanceDocumentAuthority(
  previous: bigint,
  next: bigint,
  sameGroup: boolean,
  headChanged: boolean,
): boolean {
  //@ verify
  //@ requires 0n <= previous && previous <= 18446744073709551615n
  //@ requires 0n <= next && next <= 18446744073709551615n
  //@ ensures \result <==> next > previous && sameGroup && headChanged
  return next > previous && sameGroup && headChanged;
}
